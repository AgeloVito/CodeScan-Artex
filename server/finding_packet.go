package server

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// =====================================================================
// 漏洞复测报文（LLM 推演）HTTP 接口
//
// 平台不抓包：漏洞详情页的「原始数据包」在没有真实流量证据时由上报 Agent 依据
// 源码推演。写入入口是 agent 的 report_finding.retest_packets；这里只暴露读取、
// 人工修订、清除——让人能纠正模型的偏差，而不是只能删掉重报。
//
// 报文**按接口一份**：报文里写死了 Host 与路径，一份报文只可能覆盖一个接口。
// 所以这里以 (finding_id, asset_id) 为粒度读写，并同时返回该漏洞锚定的接口清单，
// 让页面能把「哪个接口还没有报文」直接摆出来——这正是改造前最伤复测的地方。
//
// 权限沿用流量证据那套：context_task 校验 + 继承漏洞只读（写操作 403）。
// 报文**不是证据**：这里不提供任何把它变成证据的入口。
// =====================================================================

// maxRetestPacketBodyBytes 允许一次提交「请求 + 响应」两份报文（各 256 KB）加上
// 依据/假设列表的余量。
const maxRetestPacketBodyBytes = 1 << 20

// packetInterfaceDTO 是详情页「原始数据包」卡片里的一个接口槽位：该漏洞锚定的一个
// 接口，以及它是否已经有报文。没有报文的槽位也要返回（has_packet=false），
// 页面据此显示「未生成」，而不是让一份报文看起来覆盖了全部涉及资产。
type packetInterfaceDTO struct {
	AssetID   int64  `json:"asset_id,string"`
	Label     string `json:"label"`
	HasPacket bool   `json:"has_packet"`
}

func (s *Server) registerFindingPacket(mux *http.ServeMux) {
	base := "/api/exploration/findings/{id}/packets"
	mux.HandleFunc("GET "+base, s.listFindingPackets)
	mux.HandleFunc("PATCH "+base+"/{assetID}", s.saveFindingPacket)
	mux.HandleFunc("DELETE "+base+"/{assetID}", s.deleteFindingPacket)

	// 改造前的单报文路由：等价于「未指定接口」那一份（asset_id=0），保留以兼容
	// 已有调用方与老前端；新前端一律走上面的按接口路由。
	legacy := "/api/exploration/findings/{id}/packet"
	mux.HandleFunc("GET "+legacy, s.getFindingPacket)
	mux.HandleFunc("PATCH "+legacy, s.saveFindingPacket)
	mux.HandleFunc("DELETE "+legacy, s.deleteFindingPacket)
}

// packetAssetID 取路径里的接口 id。老路由没有这一段，按「未指定接口」(0) 处理。
func packetAssetID(r *http.Request) (int64, bool) {
	raw := r.PathValue("assetID")
	if raw == "" {
		return 0, true
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id < 0 {
		return 0, false
	}
	return id, true
}

// findingPacketInterfaces 把漏洞锚定的接口资产整理成槽位列表（保持 asset_ids 顺序）。
// 只收 type='endpoint' 且有 url 的资产：其余类型（域名/IP/服务）没有请求形状，
// 承载不了报文，它们只能作为接口报文的 Host 上下文出现。
func (s *Server) findingPacketInterfaces(f *db.DBFinding) ([]packetInterfaceDTO, error) {
	out := []packetInterfaceDTO{}
	if f == nil || len(f.AssetIDs) == 0 {
		return out, nil
	}
	assets, err := s.m.pg.Assets().GetByIDs(f.AssetIDs)
	if err != nil {
		return out, err
	}
	byID := make(map[int64]*db.Asset, len(assets))
	for _, a := range assets {
		if a != nil {
			byID[a.ID] = a
		}
	}
	for _, id := range f.AssetIDs {
		a := byID[id]
		if a == nil || a.Type != "endpoint" || strings.TrimSpace(a.URL) == "" {
			continue
		}
		out = append(out, packetInterfaceDTO{AssetID: a.ID, Label: assetLabel(a)})
	}
	return out, nil
}

// packetCoverage 组装列表响应：全部报文 + 接口槽位（标出哪些已有报文）。
func (s *Server) packetCoverage(f *db.DBFinding) (map[string]any, error) {
	packets, err := s.m.pg.ListFindingPackets(f.ID)
	if err != nil {
		return nil, err
	}
	interfaces, err := s.findingPacketInterfaces(f)
	if err != nil {
		return nil, err
	}
	have := make(map[int64]bool, len(packets))
	for _, p := range packets {
		if p.AssetID > 0 {
			have[p.AssetID] = true
		}
	}
	for i := range interfaces {
		interfaces[i].HasPacket = have[interfaces[i].AssetID]
	}
	return map[string]any{"packets": packets, "interfaces": interfaces}, nil
}

// packetCoverageSummary 是 packetCoverage 的轻量版：只回「哪个接口有没有报文」，
// 不带报文正文。agent 工具（复核修订）保存完一份后用它回报剩余缺口——把全部报文
// 正文再灌回模型上下文既浪费 token，也容易让它把旧报文当成新依据。
func (s *Server) packetCoverageSummary(f *db.DBFinding) ([]map[string]any, error) {
	packets, err := s.m.pg.ListFindingPackets(f.ID)
	if err != nil {
		return nil, err
	}
	interfaces, err := s.findingPacketInterfaces(f)
	if err != nil {
		return nil, err
	}
	have := make(map[int64]bool, len(packets))
	for _, p := range packets {
		if p.AssetID > 0 {
			have[p.AssetID] = true
		}
	}
	out := make([]map[string]any, 0, len(interfaces))
	for _, it := range interfaces {
		out = append(out, map[string]any{
			"asset_id": it.AssetID, "label": it.Label, "has_packet": have[it.AssetID],
		})
	}
	return out, nil
}

func (s *Server) listFindingPackets(w http.ResponseWriter, r *http.Request) {
	id, ok := s.findingTrafficAccess(w, r, false)
	if !ok {
		return
	}
	f, err := s.m.pg.GetFinding(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if f == nil {
		writeErr(w, http.StatusNotFound, "finding not found")
		return
	}
	out, err := s.packetCoverage(f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// getFindingPacket 读取一份报文（老路由：未指定接口那份）。
func (s *Server) getFindingPacket(w http.ResponseWriter, r *http.Request) {
	id, ok := s.findingTrafficAccess(w, r, false)
	if !ok {
		return
	}
	assetID, ok := packetAssetID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid asset id")
		return
	}
	p, err := s.m.pg.GetFindingPacket(id, assetID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"packet": p})
}

// saveFindingPacket 人工修订某一份报文：未提供的字段沿用该接口已存报文，整体重新校验。
// 返回与列表接口同形的结果，这样即使 asset_id 对不上被降级为「未指定接口」，
// 调用方也能从返回里看到报文实际落在了哪个槽位、以及原因。
func (s *Server) saveFindingPacket(w http.ResponseWriter, r *http.Request) {
	id, ok := s.findingTrafficAccess(w, r, true)
	if !ok {
		return
	}
	assetID, ok := packetAssetID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid asset id")
		return
	}
	var body struct {
		RawRequest   *string   `json:"raw_request"`
		RawResponse  *string   `json:"raw_response"`
		GroundedRefs *[]string `json:"grounded_refs"`
		Assumptions  *[]string `json:"assumptions"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRetestPacketBodyBytes)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "请求体不合法："+err.Error())
		return
	}
	f, err := s.m.pg.GetFinding(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if f == nil {
		writeErr(w, http.StatusNotFound, "finding not found")
		return
	}
	in := db.RetestPacketInput{AssetID: assetID, Source: db.RetestPacketSourceManual, Generator: "manual"}
	if prev, err := s.m.pg.GetFindingPacket(id, assetID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	} else if prev != nil {
		in.RawRequest, in.RawResponse = prev.RawRequest, prev.RawResponse
		in.GroundedRefs, in.Assumptions = prev.GroundedRefs, prev.Assumptions
	}
	if body.RawRequest != nil {
		in.RawRequest = *body.RawRequest
	}
	if body.RawResponse != nil {
		in.RawResponse = *body.RawResponse
	}
	if body.GroundedRefs != nil {
		in.GroundedRefs = *body.GroundedRefs
	}
	if body.Assumptions != nil {
		in.Assumptions = *body.Assumptions
	}
	if strings.TrimSpace(in.RawRequest) == "" {
		writeErr(w, http.StatusBadRequest, "raw_request 不能为空")
		return
	}
	if _, err = s.m.pg.SaveRetestPacket(r.Context(), id, assetID, f.AssetIDs, in); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// 老路由（路径里没有 {assetID} 段）保持改造前的响应形状 {packet: ...}，
	// 新路由返回按接口的列表形状，让调用方一次拿到全部槽位与覆盖情况。
	if r.PathValue("assetID") == "" {
		p, err := s.m.pg.GetFindingPacket(id, assetID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"packet": p})
		return
	}
	out, err := s.packetCoverage(f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deleteFindingPacket(w http.ResponseWriter, r *http.Request) {
	id, ok := s.findingTrafficAccess(w, r, true)
	if !ok {
		return
	}
	assetID, ok := packetAssetID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid asset id")
		return
	}
	deleted, err := s.m.pg.DeleteFindingPacket(r.Context(), id, assetID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": deleted})
}

// seedFindingPacketTool 把 report_finding 的单份报文参数 retest_packet 升级为
// 按接口的 retest_packets 数组（一次性）。
//
// 运行时模型看到的 schema/描述来自 tools 表（ToolResolve 用 row.Schema 装饰工具），
// 而 SeedTool 是 ON CONFLICT DO NOTHING：只改代码里的 schema，老库永远拿不到新参数。
// 所以这里用 CAS 写回（schema 未变才更新），保留用户改过的描述、其余属性、绑定与
// 启用状态——与 seedFindingTrafficTools / seedFindingWorkflowTools 同款。
// 单份参数会被删掉：留着它，模型就会继续只写一份报文。
func (s *Server) seedFindingPacketTool() {
	const flag = "finding_retest_packets_tools_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	row, err := s.m.pg.GetTool("report_finding")
	if err != nil {
		log.Printf("[finding-packet] 读取 report_finding: %v", err)
		return
	}
	if row == nil || !row.System {
		return
	}
	var schema map[string]any
	if err = json.Unmarshal(row.Schema, &schema); err != nil || schema == nil {
		log.Printf("[finding-packet] report_finding schema 非法: %v", err)
		return
	}
	props := objectProperty(schema, "properties")
	if props == nil {
		return
	}
	_, hasNew := props["retest_packets"]
	_, hasOld := props["retest_packet"]
	if hasNew && !hasOld {
		_ = s.m.pg.SetSetting(flag, "true")
		return
	}
	props["retest_packets"] = agent.RetestPacketSchema()
	delete(props, "retest_packet")
	raw, err := json.Marshal(schema)
	if err != nil {
		log.Printf("[finding-packet] 序列化 report_finding schema: %v", err)
		return
	}
	result, err := s.m.pg.Exec(`UPDATE tools SET schema=$2::jsonb,updated_at=now() WHERE key=$1 AND system AND schema=$3::jsonb`,
		"report_finding", string(raw), string(row.Schema))
	if err != nil {
		log.Printf("[finding-packet] 升级 report_finding: %v", err)
		return
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return // 并发改过：不覆盖用户编辑，下次启动重试
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// backfillFindingPacketAssets 给历史报文补上接口归属（一次性，幂等）。
//
// 老库的报文是「一漏洞一份」且没有接口信息。这里用报文自己的方法/路径去撞该漏洞锚定的
// 接口，**恰好命中一个**才绑上，命中 0 个或多个就保持「未指定」——猜一个会让复测打错
// 目标，比不绑更糟。绑定结果会立刻反映到详情页的槽位上。
func (s *Server) backfillFindingPacketAssets() {
	const flag = "finding_packet_assets_backfill_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	n, err := s.m.pg.BackfillFindingPacketAssets()
	if err != nil {
		log.Printf("[finding-packet] 回填报文接口归属: %v", err)
		return
	}
	if n > 0 {
		log.Printf("[finding-packet] 已为 %d 份历史报文绑定接口", n)
	}
	_ = s.m.pg.SetSetting(flag, "true")
}
