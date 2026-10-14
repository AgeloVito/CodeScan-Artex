package db

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"
)

// =====================================================================
// 漏洞复测报文（LLM 推演）
//
// 代码审计平台不抓包：漏洞详情里的「原始数据包」在**没有真实流量证据**时，
// 由上报 Agent 依据源码与已登记接口资产推演一份可直接粘贴复测的报文。
//
// 它是**复测用例，不是证据**。因此本文件只做三件事——解析、校验、按漏洞存一行，
// 并且刻意不碰 traffic_evidence_snapshots / finding_traffic_bindings / 导出
// evidence/ 目录：任何把推演报文当抓包证据的路径都不应该存在。
//
// 校验的目的不是「拒绝」，而是**把不可信的地方显式暴露出来**：报文始终会被保存
// （漏洞已经落库，辅助产物不该反过来阻断它），但 valid=false 与逐条原因会一路
// 传到模型返回值和详情页，由人判断能不能用。
//
// 解析刻意不走 http.ReadRequest：模型给出的报文常常省略 Content-Length 或结尾空行，
// 而 ReadRequest 会按头部声明去读正文，于是把「格式不够标准」误判成「解析失败」。
// 这里按「第一个空行」切头/正文，头部用 textproto 解析，宽容但不放水。
// =====================================================================

const (
	// MaxRetestPacketBytes 限制单份报文的文本大小。真实抓包正文上限是 1 MiB，
	// 那是抓到的字节；这里是模型生成物，超过这个量只说明它在灌水。
	MaxRetestPacketBytes = 256 << 10
	// MaxRetestPacketRefs / MaxRetestPacketAssumptions 限制依据与假设条数，
	// 避免详情页被模型输出刷屏。
	MaxRetestPacketRefs        = 64
	MaxRetestPacketAssumptions = 64
	// RetestPacketPromptVersion 标记生成规约版本；规约演进后旧报文可被识别。
	RetestPacketPromptVersion = "retest-packet/v1"
)

// 报文来源。
const (
	RetestPacketSourceLLM    = "llm"
	RetestPacketSourceManual = "manual"
)

// FindingPacket 是 finding_packets 的一行（一个漏洞 × 一个接口）。
type FindingPacket struct {
	FindingID int64 `json:"finding_id,string"`
	// AssetID 是这份报文对应的接口资产（assets.id，type='endpoint'）；0 = 未指定接口。
	AssetID       int64            `json:"asset_id,string"`
	Source        string           `json:"source"`
	RawRequest    string           `json:"raw_request"`
	RawResponse   string           `json:"raw_response,omitempty"`
	GroundedRefs  []string         `json:"grounded_refs"`
	Assumptions   []string         `json:"assumptions"`
	Validation    PacketValidation `json:"validation"`
	Valid         bool             `json:"valid"`
	Generator     string           `json:"generator,omitempty"`
	PromptVersion string           `json:"prompt_version,omitempty"`
	Revision      int              `json:"revision"`
	CreatedAt     time.Time        `json:"created_at"`
	UpdatedAt     time.Time        `json:"updated_at"`
}

// PacketValidation 是服务端校验结果，原样展示给使用者：Errors 表示不可信之处，
// Warnings 表示需要人确认之处。
type PacketValidation struct {
	Valid     bool      `json:"valid"`
	Errors    []string  `json:"errors,omitempty"`
	Warnings  []string  `json:"warnings,omitempty"`
	Method    string    `json:"method,omitempty"`
	Path      string    `json:"path,omitempty"`
	Host      string    `json:"host,omitempty"`
	Bytes     int       `json:"bytes,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// RetestPacketInput 是上报 Agent（或人工修订）提交的报文内容。
type RetestPacketInput struct {
	// AssetID 声明这份报文是给哪个接口的（assets.id）。0 = 未指定接口。
	AssetID      int64
	RawRequest   string
	RawResponse  string
	GroundedRefs []string
	Assumptions  []string
	Generator    string
	Source       string
}

// packetSensitiveHeaders 必须使用占位符的请求头：模型一旦编出「像真的」凭证，
// 使用者粘到真实环境就是事故。
var packetSensitiveHeaders = []string{"cookie", "authorization", "proxy-authorization", "x-api-key"}

// packetCredentialBodyKeys 是正文里出现时值得提醒的凭证字段名。
var packetCredentialBodyKeys = []string{"password", "passwd", "pwd", "token", "secret", "accesskey", "apikey", "sessionid"}

// parsedRetestPacket 是一份报文解析后的可校验视图。
type parsedRetestPacket struct {
	Method  string
	Target  string
	Proto   string
	Header  textproto.MIMEHeader
	URL     *url.URL
	Body    string
	Chunked bool
}

// ValidateRetestPacket 解析并校验一份推演报文。anchors 是漏洞锚定的资产（核对
// 方法与路径、参数名），scope 是锚定资产所属企业的范围规则（核对 Host 归属）。
// 返回值永远可用：即使报文完全无法解析，原因也会写进 Errors。
func ValidateRetestPacket(raw string, anchors []*Asset, scope []ScopeRule) PacketValidation {
	v := PacketValidation{CheckedAt: time.Now().UTC()}
	if strings.TrimSpace(raw) == "" {
		v.Errors = append(v.Errors, "报文为空")
		return v
	}
	v.Bytes = len(raw)
	if len(raw) > MaxRetestPacketBytes {
		v.Errors = append(v.Errors, fmt.Sprintf("报文超过 %d KB 上限", MaxRetestPacketBytes>>10))
		return v
	}

	pkt, err := parseRetestPacket(raw)
	if err != nil {
		v.Errors = append(v.Errors, err.Error())
		return v
	}
	v.Method = pkt.Method
	v.Path = pkt.URL.RequestURI()
	v.Host = pkt.Host()
	if v.Host == "" && strings.HasPrefix(pkt.Proto, "HTTP/1.1") {
		v.Errors = append(v.Errors, "缺少 Host 头：HTTP/1.1 报文必须给出 Host")
	}
	if !strings.HasPrefix(pkt.Target, "/") && pkt.URL.Host == "" {
		v.Errors = append(v.Errors, "起始行必须是 origin-form（如 GET /api/user HTTP/1.1）")
	}

	body := []byte(pkt.Body)
	if len(body) > MaxRetestPacketBytes {
		v.Errors = append(v.Errors, fmt.Sprintf("正文超过 %d KB 上限", MaxRetestPacketBytes>>10))
		body = nil
	}
	contentType := strings.ToLower(strings.TrimSpace(pkt.Header.Get("Content-Type")))

	// 1) 与锚定接口资产核对方法/路径/参数名。
	endpoints := packetEndpointAnchors(anchors)
	switch matched := packetMatchEndpoint(endpoints, v.Method, pkt.URL.Path); {
	case len(endpoints) == 0:
		v.Warnings = append(v.Warnings, "漏洞未锚定接口资产，方法/路径/参数名无法与代码核对")
	case matched == nil:
		v.Errors = append(v.Errors, "方法与路径不在锚定接口里（期望："+packetEndpointLabels(endpoints)+"）")
	case pkt.Chunked:
		v.Warnings = append(v.Warnings, "正文使用 chunked 编码，跳过正文格式与参数字段核对")
	default:
		v.Warnings = append(v.Warnings, packetCheckParams(pkt.URL.Query(), body, contentType, matched)...)
	}

	// 2) 正文格式：声明 JSON 就必须是合法 JSON 对象。
	if !pkt.Chunked && len(body) > 0 && strings.Contains(contentType, "json") {
		var obj map[string]any
		if err = json.Unmarshal(body, &obj); err != nil {
			v.Errors = append(v.Errors, "Content-Type 声明 JSON，但正文不是合法 JSON 对象："+err.Error())
		} else {
			v.Warnings = append(v.Warnings, packetCredentialWarnings(obj)...)
		}
	}

	// 3) 敏感头必须占位。
	for _, name := range packetSensitiveHeaders {
		value := strings.TrimSpace(pkt.Header.Get(name))
		if value == "" {
			continue
		}
		if !packetHasPlaceholder(value) {
			v.Errors = append(v.Errors, "请求头 "+textproto.CanonicalMIMEHeaderKey(name)+" 必须用 <占位符>，不得编造真实凭证")
		}
	}

	// 4) Host 归属：只在企业范围确有规则时判定，避免无范围数据时误报。
	if v.Host != "" && len(scope) > 0 && !packetHostInScope(v.Host, scope) {
		v.Warnings = append(v.Warnings, "Host "+v.Host+" 不在锚定资产所属企业的范围规则内，请确认目标是否填错")
	}

	v.Valid = len(v.Errors) == 0
	return v
}

// ValidateRetestResponse 校验可选的响应报文（推断产物，只做结构检查）。
func ValidateRetestResponse(rawResponse, method string) []string {
	resp := strings.TrimSpace(rawResponse)
	if resp == "" {
		return nil
	}
	if len(resp) > MaxRetestPacketBytes {
		return []string{fmt.Sprintf("响应报文超过 %d KB 上限", MaxRetestPacketBytes>>10)}
	}
	if method == "" {
		method = http.MethodGet
	}
	res, err := http.ReadResponse(bufio.NewReader(strings.NewReader(resp+"\r\n")), &http.Request{Method: method})
	if err != nil {
		return []string{"无法解析为 HTTP 响应报文（需要状态行 + 头部 + 空行 + 正文）：" + err.Error()}
	}
	_ = res.Body.Close()
	return nil
}

// parseRetestPacket 按「第一个空行」切分头/正文，再解析起始行与头部。
func parseRetestPacket(raw string) (*parsedRetestPacket, error) {
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	head, body := normalized, ""
	if idx := strings.Index(normalized, "\n\n"); idx >= 0 {
		head, body = normalized[:idx], normalized[idx+2:]
	}
	lines := strings.Split(head, "\n")
	for len(lines) > 0 && strings.TrimSpace(lines[0]) == "" {
		lines = lines[1:]
	}
	if len(lines) == 0 {
		return nil, errors.New("报文为空")
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 2 {
		return nil, errors.New("起始行不合法（应为 METHOD 路径 HTTP/1.1）：" + strings.TrimSpace(lines[0]))
	}
	method, target := strings.ToUpper(fields[0]), fields[1]
	proto := "HTTP/1.1"
	if len(fields) >= 3 {
		proto = fields[2]
	}
	if !strings.HasPrefix(strings.ToUpper(proto), "HTTP/") {
		return nil, errors.New("起始行缺少 HTTP 版本（应为 METHOD 路径 HTTP/1.1）")
	}
	if !validPacketMethod(method) {
		return nil, errors.New("起始行的 HTTP 方法不合法：" + method)
	}
	parsedURL, err := url.ParseRequestURI(target)
	if err != nil {
		return nil, errors.New("起始行的请求目标不合法：" + target)
	}
	tp := textproto.NewReader(bufio.NewReader(strings.NewReader(strings.Join(lines[1:], "\n") + "\n\n")))
	header, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, errors.New("请求头无法解析：" + err.Error())
	}
	return &parsedRetestPacket{
		Method:  method,
		Target:  target,
		Proto:   strings.ToUpper(proto),
		Header:  header,
		URL:     parsedURL,
		Body:    body,
		Chunked: strings.Contains(strings.ToLower(header.Get("Transfer-Encoding")), "chunked"),
	}, nil
}

// Host 返回报文声明的 Host（优先 Host 头，其次绝对形式请求目标里的主机）。
func (p *parsedRetestPacket) Host() string {
	if host := strings.TrimSpace(p.Header.Get("Host")); host != "" {
		return host
	}
	return strings.TrimSpace(p.URL.Host)
}

// validPacketMethod 只认 HTTP 方法 token 形态，避免把一段散文当起始行。
func validPacketMethod(method string) bool {
	if method == "" || len(method) > 20 {
		return false
	}
	for _, r := range method {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

// SaveRetestPacket 校验并落库（一个漏洞 × 一个接口一行，重写递增 revision）。校验失败同样保存：
// 漏洞已经落库，报文是辅助产物，不该反过来阻断它；调用方负责把状态回传。
//
// assetID 声明这份报文对应哪个接口：>0 时只拿那一个接口当锚点校验（方法/路径必须与它一致），
// 这才是「每个涉及接口各有一份报文」的正确语义；=0 时退回漏洞的全部接口锚点（命中任一即可），
// 但当锚点不止一个时补一条警告——否则一份报文会被误读成覆盖了全部涉及资产。
// findingAssetIDs 是该漏洞的 findings.asset_ids，用于确认 assetID 确实是它锚定的接口。
func (d *DB) SaveRetestPacket(ctx context.Context, findingID, assetID int64, findingAssetIDs []int64, in RetestPacketInput) (PacketValidation, error) {
	if findingID <= 0 {
		return PacketValidation{}, errors.New("finding id 无效")
	}
	source := strings.TrimSpace(in.Source)
	if source != RetestPacketSourceManual {
		source = RetestPacketSourceLLM
	}
	anchors, scope, endpointCount := d.retestPacketAnchors(assetID, findingAssetIDs)
	v := ValidateRetestPacket(in.RawRequest, anchors, scope)

	// asset_id 必须正好命中本漏洞锚定的那一个接口。模型给了对不上的 id 时不能把报文挂到
	// 别的接口上（复测会打错目标），降级为「未指定」并把原因写进校验错误，人能在页面上看到。
	storedAssetID := assetID
	if storedAssetID > 0 && (len(anchors) != 1 || anchors[0].ID != storedAssetID) {
		v.Errors = append(v.Errors, fmt.Sprintf("asset_id=%d 不是本漏洞锚定的接口，报文已按「未指定接口」保存", storedAssetID))
		storedAssetID = 0
	}
	if storedAssetID == 0 && endpointCount > 1 {
		v.Warnings = append(v.Warnings, fmt.Sprintf(
			"报文未指定对应接口（asset_id）：本漏洞锚定了 %d 个接口，无法确认这份报文覆盖哪一个", endpointCount))
	}
	if len(cleanPacketStrings(in.GroundedRefs, MaxRetestPacketRefs)) == 0 {
		v.Warnings = append(v.Warnings, "未给出源码依据（grounded_refs），报文取值无法逐条核对")
	}
	v.Errors = append(v.Errors, ValidateRetestResponse(in.RawResponse, v.Method)...)
	v.Valid = len(v.Errors) == 0

	refs, err := json.Marshal(cleanPacketStrings(in.GroundedRefs, MaxRetestPacketRefs))
	if err != nil {
		return v, err
	}
	assumptions, err := json.Marshal(cleanPacketStrings(in.Assumptions, MaxRetestPacketAssumptions))
	if err != nil {
		return v, err
	}
	validation, err := json.Marshal(v)
	if err != nil {
		return v, err
	}
	generator := strings.TrimSpace(in.Generator)
	if len(generator) > 200 {
		generator = generator[:200]
	}
	_, err = d.ExecContext(ctx, `
INSERT INTO finding_packets(finding_id,asset_id,source,raw_request,raw_response,grounded_refs,assumptions,validation,valid,generator,prompt_version)
VALUES($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8::jsonb,$9,$10,$11)
ON CONFLICT (finding_id, asset_id) DO UPDATE SET
    source=EXCLUDED.source,
    raw_request=EXCLUDED.raw_request,
    raw_response=EXCLUDED.raw_response,
    grounded_refs=EXCLUDED.grounded_refs,
    assumptions=EXCLUDED.assumptions,
    validation=EXCLUDED.validation,
    valid=EXCLUDED.valid,
    generator=EXCLUDED.generator,
    prompt_version=EXCLUDED.prompt_version,
    revision=finding_packets.revision+1,
    updated_at=now()`,
		findingID, storedAssetID, source, capRetestPacketText(in.RawRequest), capRetestPacketText(in.RawResponse),
		string(refs), string(assumptions), string(validation), v.Valid, generator, RetestPacketPromptVersion)
	return v, err
}

// capRetestPacketText 限制落库文本大小。校验已经会报「超过上限」，但超长文本多半是
// 模型灌水；截断保存比把几十 MB 塞进库、再推给详情页更可控，且页面能看到截断说明。
func capRetestPacketText(text string) string {
	if len(text) <= MaxRetestPacketBytes {
		return text
	}
	return text[:MaxRetestPacketBytes] + fmt.Sprintf("\n\n（已截断：原始报文超过 %d KB 上限）", MaxRetestPacketBytes>>10)
}

// SaveRetestPacket 让 agent 侧的工具经探索存储写入，不必自己持有 *DB。
func (s *ExplorationStore) SaveRetestPacket(ctx context.Context, findingID, assetID int64, findingAssetIDs []int64, in RetestPacketInput) (PacketValidation, error) {
	return s.db.SaveRetestPacket(ctx, findingID, assetID, findingAssetIDs, in)
}

// GetFindingPacket 读取漏洞某一份推演报文；assetID=0 表示「未指定接口」的那一份。
// 没有时返回 (nil, nil)。
func (d *DB) GetFindingPacket(findingID, assetID int64) (*FindingPacket, error) {
	if findingID <= 0 {
		return nil, nil
	}
	return scanFindingPacket(d.QueryRow(`
SELECT finding_id,asset_id,source,raw_request,raw_response,grounded_refs,assumptions,validation,valid,generator,prompt_version,revision,created_at,updated_at
FROM finding_packets WHERE finding_id=$1 AND asset_id=$2`, findingID, assetID))
}

// ListFindingPackets 读取漏洞的全部推演报文（每个接口一份，外加可能的「未指定接口」一份）。
// 「未指定接口」的 asset_id=0 排在最前，其余按接口 id 升序——详情页据此稳定渲染。
func (d *DB) ListFindingPackets(findingID int64) ([]*FindingPacket, error) {
	out := []*FindingPacket{}
	if findingID <= 0 {
		return out, nil
	}
	rows, err := d.Query(`
SELECT finding_id,asset_id,source,raw_request,raw_response,grounded_refs,assumptions,validation,valid,generator,prompt_version,revision,created_at,updated_at
FROM finding_packets WHERE finding_id=$1 ORDER BY (asset_id > 0), asset_id`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		p, err := scanFindingPacket(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func scanFindingPacket(row interface{ Scan(...any) error }) (*FindingPacket, error) {
	var (
		p          FindingPacket
		refs       []byte
		assum      []byte
		validation []byte
	)
	err := row.Scan(&p.FindingID, &p.AssetID, &p.Source, &p.RawRequest, &p.RawResponse,
		&refs, &assum, &validation, &p.Valid, &p.Generator, &p.PromptVersion,
		&p.Revision, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.GroundedRefs = decodePacketStrings(refs)
	p.Assumptions = decodePacketStrings(assum)
	if len(validation) > 0 {
		_ = json.Unmarshal(validation, &p.Validation)
	}
	return &p, nil
}

// DeleteFindingPacket 删除漏洞某一份报文；assetID=0 删「未指定接口」那一份。
// 返回是否确有删除。
func (d *DB) DeleteFindingPacket(ctx context.Context, findingID, assetID int64) (bool, error) {
	if findingID <= 0 {
		return false, nil
	}
	res, err := d.ExecContext(ctx, `DELETE FROM finding_packets WHERE finding_id=$1 AND asset_id=$2`, findingID, assetID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// retestPacketAnchors 载入报文校验所需的锚定接口与其企业范围规则。任何读取失败都退化为
// 「没有可核对的信息」——校验降级为警告，而不是把上报卡死。
//
// assetID > 0 时只返回那一个接口：报文的目标就是它，方法/路径必须与它一致。
// assetID = 0 时返回漏洞的全部接口锚点（老行为：命中任一即可），调用方负责补一条
// 「未指定接口」的警告。endpointCount 是该漏洞锚定的接口总数，用于判断「未指定」是否含糊。
func (d *DB) retestPacketAnchors(assetID int64, findingAssetIDs []int64) (anchors []*Asset, scope []ScopeRule, endpointCount int) {
	if len(findingAssetIDs) == 0 {
		return nil, nil, 0
	}
	assets, err := d.Assets().GetByIDs(findingAssetIDs)
	if err != nil {
		return nil, nil, 0
	}
	var (
		endpoints []*Asset
		companyID int64
	)
	for _, a := range assets {
		if a == nil {
			continue
		}
		if a.Type == "endpoint" && strings.TrimSpace(a.URL) != "" {
			endpoints = append(endpoints, a)
		}
		if companyID == 0 && a.CompanyID != nil {
			companyID = *a.CompanyID
		}
	}
	endpointCount = len(endpoints)
	if assetID > 0 {
		for _, a := range endpoints {
			if a.ID == assetID {
				anchors = []*Asset{a}
				break
			}
		}
	} else {
		anchors = endpoints
	}
	if companyID == 0 {
		return anchors, nil, endpointCount
	}
	rules, err := d.Companies().GetScope(companyID)
	if err != nil {
		return anchors, nil, endpointCount
	}
	return anchors, rules, endpointCount
}

// BackfillFindingPacketAssets 给历史报文补上它对应的接口（只处理 asset_id 仍为 0 的行）。
//
// 老库的报文是「一漏洞一份」且没有接口信息。这里用报文自己的方法/路径去撞该漏洞锚定的接口：
// **恰好命中一个**才绑上，命中 0 个或多个就保持「未指定」——把原本隐式的歧义变成显式状态，
// 而不是猜一个（猜错会让复测打错目标，比不绑更糟）。幂等：只动 asset_id=0 的行。
// 返回本次绑定的行数。
func (d *DB) BackfillFindingPacketAssets() (int, error) {
	rows, err := d.Query(`SELECT finding_id, raw_request FROM finding_packets WHERE asset_id=0 ORDER BY finding_id`)
	if err != nil {
		return 0, err
	}
	type pending struct {
		findingID int64
		raw       string
	}
	var items []pending
	for rows.Next() {
		var it pending
		if err := rows.Scan(&it.findingID, &it.raw); err != nil {
			rows.Close()
			return 0, err
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()

	bound := 0
	for _, it := range items {
		var aidsJSON string
		if err := d.QueryRow(`SELECT COALESCE(asset_ids::text,'[]') FROM findings WHERE id=$1`, it.findingID).Scan(&aidsJSON); err != nil {
			continue // 漏洞已删除：留着不动，等级联清理
		}
		var assetIDs []int64
		if err := json.Unmarshal([]byte(aidsJSON), &assetIDs); err != nil || len(assetIDs) == 0 {
			continue
		}
		anchors, _, endpointCount := d.retestPacketAnchors(0, assetIDs)
		if endpointCount != 1 {
			continue // 0 个没得绑；多个则本就无法判断是哪一份，保持「未指定」
		}
		pkt, err := parseRetestPacket(it.raw)
		if err != nil {
			continue
		}
		matched := packetMatchingEndpoints(anchors, pkt.Method, pkt.URL.Path)
		if len(matched) != 1 {
			continue
		}
		res, err := d.Exec(`
UPDATE finding_packets SET asset_id=$2 WHERE finding_id=$1 AND asset_id=0
  AND NOT EXISTS (SELECT 1 FROM finding_packets p2 WHERE p2.finding_id=$1 AND p2.asset_id=$2)`,
			it.findingID, matched[0].ID)
		if err != nil {
			return bound, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			bound++
		}
	}
	return bound, nil
}

// ---- 校验内部工具 ----

func packetEndpointAnchors(anchors []*Asset) []*Asset {
	out := make([]*Asset, 0, len(anchors))
	for _, a := range anchors {
		if a != nil && a.Type == "endpoint" && strings.TrimSpace(a.URL) != "" {
			out = append(out, a)
		}
	}
	return out
}

func packetEndpointLabels(endpoints []*Asset) string {
	labels := make([]string, 0, len(endpoints))
	for _, a := range endpoints {
		method := strings.ToUpper(strings.TrimSpace(a.Method))
		if method == "" {
			method = "*"
		}
		labels = append(labels, method+" "+strings.TrimSpace(a.URL))
	}
	return strings.Join(labels, " / ")
}

// packetMatchEndpoint 返回方法与路径都对得上的锚定接口；都不匹配时返回 nil。
func packetMatchEndpoint(endpoints []*Asset, method, path string) *Asset {
	for _, a := range endpoints {
		if want := strings.ToUpper(strings.TrimSpace(a.Method)); want != "" && want != method {
			continue
		}
		if packetPathMatches(a.URL, path) {
			return a
		}
	}
	return nil
}

// packetMatchingEndpoints 返回所有方法与路径都对得上的锚定接口。
// 存量报文回填只认「恰好命中一个」的情形：命中多个说明光看报文无法判断它属于哪个接口，
// 那时保持「未指定」比猜一个更诚实。
func packetMatchingEndpoints(endpoints []*Asset, method, path string) []*Asset {
	var out []*Asset
	for _, a := range endpoints {
		if want := strings.ToUpper(strings.TrimSpace(a.Method)); want != "" && want != method {
			continue
		}
		if packetPathMatches(a.URL, path) {
			out = append(out, a)
		}
	}
	return out
}

// packetCheckParams 把报文里的 query / 正文参数与接口资产登记的 params 对照，
// 只产出警告：模型多写一个参数不致命，但使用者必须知道它没有代码依据。
func packetCheckParams(query url.Values, body []byte, contentType string, anchor *Asset) []string {
	allowed := map[string]bool{}
	for _, p := range anchor.Params {
		if p == nil {
			continue
		}
		if name, ok := p["name"].(string); ok && strings.TrimSpace(name) != "" {
			allowed[strings.ToLower(strings.TrimSpace(name))] = true
		}
	}
	if len(allowed) == 0 {
		return nil
	}
	var unknown []string
	check := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" || allowed[strings.ToLower(name)] {
			return
		}
		unknown = append(unknown, name)
	}
	for name := range query {
		check(name)
	}
	switch {
	case len(body) > 0 && strings.Contains(contentType, "json"):
		var obj map[string]any
		if json.Unmarshal(body, &obj) == nil {
			for name := range obj {
				check(name)
			}
		}
	case len(body) > 0 && strings.Contains(contentType, "x-www-form-urlencoded"):
		if values, err := url.ParseQuery(string(body)); err == nil {
			for name := range values {
				check(name)
			}
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	return []string{"参数 " + strings.Join(unknown, "、") + " 未在锚定接口的 params 里登记（可能是新增参数或名称不符）"}
}

func packetCredentialWarnings(body map[string]any) []string {
	var hits []string
	for key := range body {
		lower := strings.ToLower(strings.TrimSpace(key))
		for _, needle := range packetCredentialBodyKeys {
			if strings.Contains(lower, needle) {
				hits = append(hits, key)
				break
			}
		}
	}
	if len(hits) == 0 {
		return nil
	}
	return []string{"正文含疑似凭证字段 " + strings.Join(hits, "、") + "，建议改为 <占位符> 而不是真实值"}
}

// packetHasPlaceholder 判断取值是否用了占位写法：<...> 或 {{...}}。
func packetHasPlaceholder(value string) bool {
	if strings.Contains(value, "{{") {
		return true
	}
	return strings.Contains(value, "<") && strings.Contains(value, ">")
}

// packetPathMatches 比较接口资产登记的路径与报文里的路径。允许两种偏差：
//   - 一侧比另一侧多出前缀段（context-path / 网关 basePath / 版本前缀）；
//   - 路径参数段是占位写法（{id} / :id / <id> / *）。
func packetPathMatches(want, got string) bool {
	w := packetPathSegments(want)
	g := packetPathSegments(got)
	if len(w) == 0 || len(g) == 0 {
		return false
	}
	if len(g) >= len(w) {
		return packetSegmentsMatch(w, g[len(g)-len(w):])
	}
	return packetSegmentsMatch(w[len(w)-len(g):], g)
}

func packetPathSegments(path string) []string {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if u, err := url.Parse(path); err == nil && u.Path != "" {
		path = u.Path
	}
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}
	var out []string
	for _, seg := range strings.Split(path, "/") {
		if seg = strings.TrimSpace(seg); seg != "" {
			out = append(out, seg)
		}
	}
	return out
}

func packetSegmentsMatch(want, got []string) bool {
	if len(want) != len(got) {
		return false
	}
	for i := range want {
		if want[i] == got[i] || packetWildcardSegment(want[i]) || packetWildcardSegment(got[i]) {
			continue
		}
		return false
	}
	return true
}

func packetWildcardSegment(seg string) bool {
	seg = strings.TrimSpace(seg)
	if seg == "*" {
		return true
	}
	if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
		return true
	}
	if strings.HasPrefix(seg, ":") && len(seg) > 1 {
		return true
	}
	return strings.Contains(seg, "<") && strings.Contains(seg, ">")
}

// packetHostInScope 判断 Host（可带端口）是否落在企业范围规则内。
func packetHostInScope(host string, rules []ScopeRule) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if onlyHost, _, err := net.SplitHostPort(h); err == nil {
		h = onlyHost
	}
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return false
	}
	ip := net.ParseIP(strings.Trim(h, "[]"))
	for _, r := range rules {
		switch strings.ToLower(strings.TrimSpace(r.Kind)) {
		case "domain":
			domain := strings.ToLower(strings.TrimSpace(r.Domain))
			if domain == "" {
				continue
			}
			if h == domain || strings.HasSuffix(h, "."+domain) {
				return true
			}
		case "ip", "cidr":
			if ip == nil {
				continue
			}
			if _, network, err := net.ParseCIDR(strings.TrimSpace(r.Net)); err == nil && network.Contains(ip) {
				return true
			}
		case "keyword":
			value := strings.ToLower(strings.TrimSpace(r.Value))
			if value != "" && strings.Contains(h, value) {
				return true
			}
		}
	}
	return false
}

// cleanPacketStrings 去掉空串、限长、限条数。
func cleanPacketStrings(in []string, limit int) []string {
	out := make([]string, 0, len(in))
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if len(item) > 1024 {
			item = item[:1024]
		}
		out = append(out, item)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

func decodePacketStrings(raw []byte) []string {
	if len(raw) == 0 {
		return []string{}
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil || out == nil {
		return []string{}
	}
	return out
}
