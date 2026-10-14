package server

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// packetResponse 解出 {packet: {...}} 结构（packet 为 null 时返回 nil）。
func packetResponse(t *testing.T, body string) map[string]any {
	t.Helper()
	var out struct {
		Packet map[string]any `json:"packet"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("解析响应失败: %v; raw=%s", err, body)
	}
	return out.Packet
}

// TestFindingPacketAPI 覆盖「推演复测报文」的读/改/删与继承只读语义。
// 报文不是证据：这里只做人工修订，不存在把它变成证据的入口。
func TestFindingPacketAPI(t *testing.T) {
	s, f, req := trafficEvidenceServer(t)
	base := fmt.Sprintf("/api/exploration/findings/%d/packet", f.FindingID)

	// 未生成时读取：packet 为 null，而不是 404（详情页据此回退到模板）。
	if w := req("GET", base, ""); w.Code != 200 || packetResponse(t, w.Body.String()) != nil {
		t.Fatalf("空报文应返回 null: %d %s", w.Code, w.Body)
	}

	// 人工修订写入合法报文。
	raw := "POST /api/login HTTP/1.1\r\nHost: app.example.com\r\nContent-Type: application/json\r\nCookie: <会话 Cookie>\r\n\r\n{\"username\":\"admin\"}"
	payload, _ := json.Marshal(map[string]any{
		"raw_request":   raw,
		"grounded_refs": []string{"src/main/java/com/x/LoginController.java:40"},
		"assumptions":   []string{"会话 Cookie 需登录后获取"},
	})
	w := req("PATCH", base, string(payload))
	if w.Code != 200 {
		t.Fatalf("PATCH 失败: %d %s", w.Code, w.Body)
	}
	packet := packetResponse(t, w.Body.String())
	if packet == nil || packet["source"] != db.RetestPacketSourceManual || packet["valid"] != true || packet["raw_request"] != raw {
		t.Fatalf("保存结果不符: %v", packet)
	}
	if got := packetResponse(t, req("GET", base, "").Body.String()); got == nil || got["raw_request"] != raw {
		t.Fatalf("再读结果不符: %v", got)
	}

	// 编造真实凭证：保存但标记不可信，并给出可读原因。
	bad, _ := json.Marshal(map[string]any{
		"raw_request": "POST /api/login HTTP/1.1\r\nHost: app.example.com\r\nCookie: session=abc123\r\n\r\n{}",
	})
	w = req("PATCH", base, string(bad))
	if w.Code != 200 {
		t.Fatalf("非法报文也应保存: %d %s", w.Code, w.Body)
	}
	packet = packetResponse(t, w.Body.String())
	if packet == nil || packet["valid"] != false {
		t.Fatalf("非法报文不应标记为有效: %v", packet)
	}
	validation, _ := packet["validation"].(map[string]any)
	if errors, _ := validation["errors"].([]any); len(errors) == 0 {
		t.Fatalf("应记录校验错误: %v", packet)
	}
	if packet["revision"] != float64(2) {
		t.Fatalf("重写应递增 revision: %v", packet["revision"])
	}

	// 清空 raw_request 视为无效请求。
	if w = req("PATCH", base, `{"raw_request":"   "}`); w.Code != 400 {
		t.Fatalf("空报文应被拒绝: %d %s", w.Code, w.Body)
	}

	// 不存在的漏洞 → 404。
	if w = req("GET", "/api/exploration/findings/99999999/packet", ""); w.Code != 404 {
		t.Fatalf("不存在应 404: %d %s", w.Code, w.Body)
	}

	// 继承任务：可读不可写（与流量证据同一套权限）。
	finding, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	child, err := s.m.CreateTaskWithOptions("inherited packet API", "fixture", db.TaskCreateOptions{SourceTaskIDs: []int64{*finding.TaskID}})
	if err != nil {
		t.Fatal(err)
	}
	cid, _ := strconv.ParseInt(child.ID, 10, 64)
	defer s.m.pg.DeleteTask(cid)
	suffix := "?context_task=" + child.ID
	if w = req("GET", base+suffix, ""); w.Code != 200 {
		t.Fatalf("继承任务应可读: %d %s", w.Code, w.Body)
	}
	if w = req("PATCH", base+suffix, string(payload)); w.Code != 403 {
		t.Fatalf("继承任务不可写: %d %s", w.Code, w.Body)
	}
	if w = req("DELETE", base+suffix, ""); w.Code != 403 {
		t.Fatalf("继承任务不可删: %d %s", w.Code, w.Body)
	}

	// 删除后回到空状态。
	if w = req("DELETE", base, ""); w.Code != 200 {
		t.Fatalf("DELETE 失败: %d %s", w.Code, w.Body)
	}
	if packet = packetResponse(t, req("GET", base, "").Body.String()); packet != nil {
		t.Fatalf("删除后应为空: %v", packet)
	}
}

// packetListResponse 解出 {packets: [...], interfaces: [...]} 结构。
func packetListResponse(t *testing.T, body string) ([]map[string]any, []map[string]any) {
	t.Helper()
	var out struct {
		Packets    []map[string]any `json:"packets"`
		Interfaces []map[string]any `json:"interfaces"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("解析响应失败: %v; raw=%s", err, body)
	}
	return out.Packets, out.Interfaces
}

func packetByAsset(packets []map[string]any, assetID float64) map[string]any {
	for _, p := range packets {
		if p["asset_id"] == fmt.Sprintf("%.0f", assetID) {
			return p
		}
	}
	return nil
}

// TestFindingPacketsPerInterfaceAPI 覆盖这次改造的核心：一个漏洞锚定多个接口时，
// 列表接口把每个接口都列成槽位（没报文的也要出现），每份报文按接口独立读写。
func TestFindingPacketsPerInterfaceAPI(t *testing.T) {
	s, f, req := trafficEvidenceServer(t)

	ep1, err := s.m.pg.Assets().UpsertEndpoint(db.UpsertEndpointReq{URL: "https://pk.example.com/api/user", Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	ep2, err := s.m.pg.Assets().UpsertEndpoint(db.UpsertEndpointReq{URL: "https://pk.example.com/api/order", Method: "POST"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = s.m.pg.Exec(`DELETE FROM assets WHERE id IN ($1,$2)`, ep1, ep2) }()
	if _, err := s.m.pg.Exec(`UPDATE findings SET asset_ids=$2::jsonb WHERE id=$1`,
		f.FindingID, fmt.Sprintf("[%d,%d]", ep1, ep2)); err != nil {
		t.Fatal(err)
	}

	list := fmt.Sprintf("/api/exploration/findings/%d/packets", f.FindingID)

	// 空态：两份报文都没有，但两个接口槽位必须都在，且 has_packet=false。
	packets, interfaces := packetListResponse(t, req("GET", list, "").Body.String())
	if len(packets) != 0 {
		t.Fatalf("初始不该有报文: %v", packets)
	}
	if len(interfaces) != 2 {
		t.Fatalf("应列出 2 个接口槽位，实际 %d: %v", len(interfaces), interfaces)
	}
	for _, it := range interfaces {
		if it["has_packet"] != false {
			t.Fatalf("空态槽位不该标为已有报文: %v", it)
		}
		if label, _ := it["label"].(string); !strings.Contains(label, "/api/") {
			t.Fatalf("槽位应带接口标签: %v", it)
		}
	}

	// 按接口各写一份。
	raw1 := "GET /api/user HTTP/1.1\r\nHost: pk.example.com\r\nCookie: <会话 Cookie>\r\n\r\n"
	raw2 := "POST /api/order HTTP/1.1\r\nHost: pk.example.com\r\nCookie: <会话 Cookie>\r\n\r\n{}"
	for _, tc := range []struct {
		asset int64
		raw   string
	}{{ep1, raw1}, {ep2, raw2}} {
		payload, _ := json.Marshal(map[string]any{"raw_request": tc.raw, "grounded_refs": []string{"a.java:1"}})
		w := req("PATCH", fmt.Sprintf("%s/%d", list, tc.asset), string(payload))
		if w.Code != 200 {
			t.Fatalf("PATCH 接口 %d 失败: %d %s", tc.asset, w.Code, w.Body)
		}
	}

	packets, interfaces = packetListResponse(t, req("GET", list, "").Body.String())
	if len(packets) != 2 {
		t.Fatalf("两个接口应各有一份报文，实际 %d: %v", len(packets), packets)
	}
	if p := packetByAsset(packets, float64(ep1)); p == nil || p["raw_request"] != raw1 {
		t.Fatalf("接口1的报文不符: %v", p)
	}
	if p := packetByAsset(packets, float64(ep2)); p == nil || p["raw_request"] != raw2 {
		t.Fatalf("接口2的报文不符: %v", p)
	}
	for _, it := range interfaces {
		if it["has_packet"] != true {
			t.Fatalf("写入后槽位应标为已有报文: %v", it)
		}
	}

	// 删掉一份，另一份不受影响。
	if w := req("DELETE", fmt.Sprintf("%s/%d", list, ep1), ""); w.Code != 200 {
		t.Fatalf("DELETE 失败: %d %s", w.Code, w.Body)
	}
	packets, interfaces = packetListResponse(t, req("GET", list, "").Body.String())
	if len(packets) != 1 || packetByAsset(packets, float64(ep1)) != nil {
		t.Fatalf("删除接口1后应只剩接口2的报文: %v", packets)
	}
	for _, it := range interfaces {
		want := it["asset_id"] == fmt.Sprintf("%d", ep2)
		if it["has_packet"] != want {
			t.Fatalf("槽位覆盖状态不符: %v", it)
		}
	}
}

// TestSeedFindingPacketToolUpgradesOldRow 模拟旧库：report_finding 的 schema 里只有单份的
// retest_packet。运行时模型看到的是 tools 表的 schema，所以迁移必须换成按接口的
// retest_packets 数组（否则模型永远只能写一份报文），同时保留用户改过的描述、绑定与启用状态。
func TestSeedFindingPacketToolUpgradesOldRow(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	const flag = "finding_retest_packets_tools_v1"

	old, err := pg.GetTool("report_finding")
	if err != nil || old == nil {
		t.Fatal("missing report_finding tool", err)
	}
	t.Cleanup(func() {
		bindings, _ := json.Marshal(old.Agents)
		_ = pg.UpdateTool(old.Key, old.Description, old.Schema, bindings, old.Enabled)
		_ = pg.SetSetting(flag, "true")
	})

	// 旧库形态：只有单份的 retest_packet，且描述/绑定被用户改过、工具被停用。
	var schema map[string]any
	if err := json.Unmarshal(old.Schema, &schema); err != nil {
		t.Fatal(err)
	}
	props, _ := schema["properties"].(map[string]any)
	delete(props, "retest_packets")
	props["retest_packet"] = map[string]any{"type": "object"}
	legacy, _ := json.Marshal(schema)
	if err := pg.UpdateTool("report_finding", "USER DESCRIPTION", legacy, json.RawMessage(`["worker"]`), false); err != nil {
		t.Fatal(err)
	}
	if err := pg.SetSetting(flag, "false"); err != nil {
		t.Fatal(err)
	}

	s.seedFindingPacketTool()

	upgraded, err := pg.GetTool("report_finding")
	if err != nil || upgraded == nil {
		t.Fatal("report_finding disappeared", err)
	}
	if upgraded.Description != "USER DESCRIPTION" || upgraded.Enabled || len(upgraded.Agents) != 1 || upgraded.Agents[0] != "worker" {
		t.Fatalf("迁移改动了用户配置: %+v", upgraded)
	}
	var patched map[string]any
	if err := json.Unmarshal(upgraded.Schema, &patched); err != nil {
		t.Fatal(err)
	}
	patchedProps, _ := patched["properties"].(map[string]any)
	packets, _ := patchedProps["retest_packets"].(map[string]any)
	if packets == nil {
		t.Fatalf("迁移未补上 retest_packets: %v", patchedProps)
	}
	if packets["type"] != "array" {
		t.Fatalf("retest_packets 必须是数组: %v", packets["type"])
	}
	item, _ := packets["items"].(map[string]any)
	nested, _ := item["properties"].(map[string]any)
	if nested["raw_request"] == nil || nested["asset_id"] == nil {
		t.Fatalf("retest_packets 元素缺少 asset_id/raw_request: %v", item)
	}
	if patchedProps["retest_packet"] != nil {
		t.Fatal("单份的 retest_packet 必须被删掉，否则模型会继续只写一份")
	}
	// 一次性 flag：再跑一次不应报错，也不应重复改动。
	s.seedFindingPacketTool()
	again, err := pg.GetTool("report_finding")
	if err != nil || again == nil || again.Description != "USER DESCRIPTION" {
		t.Fatalf("二次迁移不应改动行: %+v %v", again, err)
	}
}
