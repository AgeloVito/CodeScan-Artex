package agent

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// reportFindingResult 拆开 report_finding 的返回文本：第一行是 node ID 契约，
// 第二行起是 JSON（见 addFinding 的 "finding recorded: %d\n%s"）。
func reportFindingResult(t *testing.T, text string) map[string]any {
	t.Helper()
	idx := strings.IndexByte(text, '\n')
	if idx < 0 {
		t.Fatalf("report_finding 返回缺少 JSON 行: %q", text)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(text[idx+1:]), &out); err != nil {
		t.Fatalf("解析 report_finding 返回失败: %v\nraw: %s", err, text)
	}
	return out
}

func callReportFinding(t *testing.T, ts *ToolSet, payload any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(payload)
	res, err := ts.addFinding().Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatalf("report_finding Call error: %v", err)
	}
	return reportFindingResult(t, res.Flatten())
}

// findingIDFrom 读取返回里的 finding_id：db.RecordedFinding 用 `,string` 标签，
// 所以 JSON 里是字符串而不是数字。
func findingIDFrom(t *testing.T, out map[string]any) int64 {
	t.Helper()
	text, ok := out["finding_id"].(string)
	if !ok {
		t.Fatalf("finding_id 不是字符串: %#v", out["finding_id"])
	}
	id, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		t.Fatalf("解析 finding_id 失败: %v", err)
	}
	return id
}

func TestReportFindingSavesRetestPacket(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTask("推演报文上报测试", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)

	// 报文要绑定接口，所以先登记一个接口资产：报文的方法/路径会拿它核对。
	epID, err := d.Assets().UpsertEndpoint(db.UpsertEndpointReq{
		URL: "https://app.example.com/api/login", Method: "POST", TaskID: task.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = d.Exec(`DELETE FROM assets WHERE id=$1`, epID) }()

	ts := NewToolSet(d.Exploration(task.ExplorationID), "worker-1")
	ts.SetTaskID(task.ID)

	// 1) 不带报文：结果里不应出现报文状态（老行为完全不变）。
	out := callReportFinding(t, ts, map[string]any{
		"vulnclass": "配置缺陷", "severity": "medium", "summary": "硬编码密钥",
		"evidence": "src/main/resources/application.yml:12",
	})
	if out["packet_status"] != nil || out["packet_note"] != nil {
		t.Fatalf("未提供报文时不该有 packet 字段: %v", out)
	}
	if out["finding_id"] == nil {
		t.Fatalf("缺少 finding_id: %v", out)
	}

	// 2) 合法报文：按接口提交，状态 saved，且确实落库到那个接口下。
	valid := "POST /api/login HTTP/1.1\r\n" +
		"Host: app.example.com\r\n" +
		"Content-Type: application/json\r\n" +
		"Cookie: <会话 Cookie>\r\n" +
		"\r\n" +
		`{"username":"admin","password":"<密码>"}`
	out = callReportFinding(t, ts, map[string]any{
		"vulnclass": "越权", "severity": "high", "summary": "登录接口未限制重试",
		"evidence":  "src/main/java/com/x/LoginController.java:40",
		"asset_ids": []int64{epID},
		"retest_packets": []map[string]any{{
			"asset_id":      epID,
			"raw_request":   valid,
			"grounded_refs": []string{"src/main/java/com/x/LoginController.java:40"},
			"assumptions":   []string{"会话 Cookie 需登录后获取"},
		}},
	})
	if out["packet_status"] != "saved" {
		t.Fatalf("packet_status = %v, note = %v", out["packet_status"], out["packet_note"])
	}
	fid := findingIDFrom(t, out)
	p, err := d.GetFindingPacket(fid, epID)
	if err != nil || p == nil {
		t.Fatalf("报文未落到接口 %d 下: %v %v", epID, p, err)
	}
	if p.RawRequest != valid || p.Source != db.RetestPacketSourceLLM || !p.Valid {
		t.Fatalf("落库内容不符: %+v", p)
	}
	if p.AssetID != epID {
		t.Fatalf("报文应绑定接口 %d，实际 %d", epID, p.AssetID)
	}
	if len(p.Assumptions) != 1 || p.Generator != "worker-1" {
		t.Fatalf("假设/生成者不符: %+v", p)
	}

	// 3) 非法报文：漏洞照常入库，报文保存但标记 invalid，且提示不要重复上报。
	//    这里刻意用改造前的单份参数 retest_packet，顺带守住兼容性：老库的工具 schema
	//    与老模型仍会发它，丢掉一份已写好的报文比兼容它更糟。
	bad := callReportFinding(t, ts, map[string]any{
		"vulnclass": "XSS", "severity": "high", "summary": "反射型 XSS",
		"evidence":      "src/main/webapp/index.jsp:5",
		"asset_ids":     []int64{epID},
		"retest_packet": map[string]any{"raw_request": "GET /x HTTP/1.1\r\nHost: app.example.com\r\nCookie: session=abc123\r\n\r\n"},
	})
	if bad["packet_status"] != "invalid" {
		t.Fatalf("packet_status = %v", bad["packet_status"])
	}
	if note, _ := bad["packet_note"].(string); !strings.Contains(note, "重复上报") {
		t.Fatalf("未通过校验时应提示不要重复上报: %q", note)
	}
	badID := findingIDFrom(t, bad)
	p, err = d.GetFindingPacket(badID, 0)
	if err != nil || p == nil {
		t.Fatalf("非法报文也应保存以便人工修订: %v %v", p, err)
	}
	if p.Valid {
		t.Fatalf("非法报文不应标记为有效: %+v", p)
	}
	if len(p.Validation.Errors) == 0 {
		t.Fatalf("应记录校验错误: %+v", p.Validation)
	}
}

// TestReportFindingSavesPacketPerInterface 守住这次改造的核心：一个漏洞锚定多个接口时，
// 每个接口各交一份报文，全部落库且各自绑定自己的接口。
func TestReportFindingSavesPacketPerInterface(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTask("逐接口报文上报测试", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)

	ep1, err := d.Assets().UpsertEndpoint(db.UpsertEndpointReq{
		URL: "https://pi.example.com/api/user", Method: "GET", TaskID: task.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	ep2, err := d.Assets().UpsertEndpoint(db.UpsertEndpointReq{
		URL: "https://pi.example.com/api/order", Method: "POST", TaskID: task.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = d.Exec(`DELETE FROM assets WHERE id IN ($1,$2)`, ep1, ep2) }()

	ts := NewToolSet(d.Exploration(task.ExplorationID), "worker-1")
	ts.SetTaskID(task.ID)

	out := callReportFinding(t, ts, map[string]any{
		"vulnclass": "SQL 注入", "severity": "critical", "summary": "同一处拼接在多个接口可达",
		"evidence":  "src/main/java/com/x/UserMapper.java:88",
		"asset_ids": []int64{ep1, ep2},
		"retest_packets": []map[string]any{
			{
				"asset_id":      ep1,
				"raw_request":   "GET /api/user?id=1 HTTP/1.1\r\nHost: pi.example.com\r\nCookie: <会话 Cookie>\r\n\r\n",
				"grounded_refs": []string{"src/main/java/com/x/UserMapper.java:88"},
			},
			{
				"asset_id":      ep2,
				"raw_request":   "POST /api/order HTTP/1.1\r\nHost: pi.example.com\r\nCookie: <会话 Cookie>\r\nContent-Type: application/json\r\n\r\n{\"id\":\"1 OR 1=1\"}",
				"grounded_refs": []string{"src/main/java/com/x/OrderMapper.java:41"},
			},
		},
	})
	if out["packet_status"] != "saved" {
		t.Fatalf("packet_status = %v, note = %v", out["packet_status"], out["packet_note"])
	}
	fid := findingIDFrom(t, out)
	list, err := d.ListFindingPackets(fid)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("两个接口应各有一份报文，实际 %d 份", len(list))
	}
	seen := map[int64]bool{}
	for _, p := range list {
		seen[p.AssetID] = true
	}
	if !seen[ep1] || !seen[ep2] {
		t.Fatalf("报文归属不符: %v (ep1=%d ep2=%d)", seen, ep1, ep2)
	}
}

func TestReportFindingRetestPacketSchema(t *testing.T) {
	ts := NewToolSet(nil, "fixture")
	raw, _ := json.Marshal(ts.addFinding().InputSchema())
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	props, _ := schema["properties"].(map[string]any)
	packets, ok := props["retest_packets"].(map[string]any)
	if !ok {
		t.Fatalf("report_finding 缺少 retest_packets: %v", props)
	}
	if packets["type"] != "array" {
		t.Fatalf("retest_packets 必须是数组（每个接口一份），实际 %v", packets["type"])
	}
	item, _ := packets["items"].(map[string]any)
	nested, _ := item["properties"].(map[string]any)
	for _, key := range []string{"asset_id", "raw_request", "raw_response", "grounded_refs", "assumptions"} {
		if nested[key] == nil {
			t.Fatalf("retest_packets 的元素缺少 %s", key)
		}
	}
	// asset_id 与 raw_request 是元素内必填：不声明接口的报文会被当成「覆盖全部资产」。
	required, _ := item["required"].([]any)
	if len(required) != 2 || required[0] != "asset_id" || required[1] != "raw_request" {
		t.Fatalf("retest_packets.items.required = %v", required)
	}
	topRequired, _ := schema["required"].([]any)
	for _, key := range topRequired {
		if key == "retest_packets" {
			t.Fatal("retest_packets 不能是 report_finding 的顶层必填参数")
		}
	}
	if desc, _ := nested["raw_request"].(map[string]any)["description"].(string); !strings.Contains(desc, "非证据") {
		t.Fatalf("raw_request 描述应说明它不是证据: %q", desc)
	}
	// 旧的单份参数必须彻底消失，否则模型会继续只写一份。
	if props["retest_packet"] != nil {
		t.Fatal("retest_packet 应被 retest_packets 取代")
	}
}
