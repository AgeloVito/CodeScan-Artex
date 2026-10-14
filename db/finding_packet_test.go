package db

import (
	"context"
	"strings"
	"testing"
)

func packetEndpointAsset() *Asset {
	return &Asset{
		ID:     1,
		Type:   "endpoint",
		URL:    "/api/user/{id}",
		Method: "GET",
		Params: []map[string]any{
			{"location": "path", "name": "id"},
			{"location": "query", "name": "verbose"},
		},
	}
}

func TestValidateRetestPacket(t *testing.T) {
	anchor := packetEndpointAsset()
	scope := []ScopeRule{{Kind: "domain", Domain: "example.com"}}

	tests := []struct {
		name        string
		raw         string
		anchors     []*Asset
		scope       []ScopeRule
		wantErrors  []string
		wantWarning []string
	}{
		{
			name: "合法报文：占位凭证 + 路径参数 + 已登记 query",
			raw: "GET /api/user/42?verbose=1 HTTP/1.1\r\n" +
				"Host: app.example.com\r\n" +
				"Cookie: <会话 Cookie>\r\n" +
				"Accept: */*\r\n\r\n",
			anchors: anchor2slice(anchor),
			scope:   scope,
		},
		{
			name:       "方法不匹配",
			raw:        "POST /api/user/42 HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
			anchors:    anchor2slice(anchor),
			scope:      scope,
			wantErrors: []string{"方法与路径不在锚定接口里"},
		},
		{
			name:       "路径完全不符",
			raw:        "GET /other/path HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
			anchors:    anchor2slice(anchor),
			scope:      scope,
			wantErrors: []string{"方法与路径不在锚定接口里"},
		},
		{
			name:    "容忍框架前缀：资产路径是报文路径的后缀",
			raw:     "GET /gateway/v1/api/user/7 HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
			anchors: anchor2slice(&Asset{ID: 2, Type: "endpoint", URL: "/api/user/{id}", Method: "GET"}),
			scope:   scope,
		},
		{
			name:        "未登记的参数只警告",
			raw:         "GET /api/user/42?debug=1 HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
			anchors:     anchor2slice(anchor),
			scope:       scope,
			wantWarning: []string{"参数 debug 未在锚定接口的 params 里登记"},
		},
		{
			name: "JSON 正文不合法",
			raw: "POST /api/user/42 HTTP/1.1\r\nHost: app.example.com\r\n" +
				"Content-Type: application/json\r\n\r\n{not json",
			anchors:    anchor2slice(&Asset{ID: 3, Type: "endpoint", URL: "/api/user/{id}", Method: "POST"}),
			scope:      scope,
			wantErrors: []string{"不是合法 JSON 对象"},
		},
		{
			name: "凭证必须占位",
			raw: "GET /api/user/42 HTTP/1.1\r\nHost: app.example.com\r\n" +
				"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.real.token\r\n\r\n",
			anchors:    anchor2slice(anchor),
			scope:      scope,
			wantErrors: []string{"Authorization 必须用 <占位符>"},
		},
		{
			name:        "Host 不在企业范围只警告",
			raw:         "GET /api/user/42 HTTP/1.1\r\nHost: other.test\r\n\r\n",
			anchors:     anchor2slice(anchor),
			scope:       scope,
			wantWarning: []string{"不在锚定资产所属企业的范围规则内"},
		},
		{
			name:       "无法解析",
			raw:        "这不是一个 HTTP 报文",
			anchors:    anchor2slice(anchor),
			scope:      scope,
			wantErrors: []string{"起始行"},
		},
		{
			name:       "空报文",
			raw:        "   ",
			wantErrors: []string{"报文为空"},
			anchors:    nil,
			scope:      nil,
		},
		{
			name:        "没有锚定接口时降级为警告",
			raw:         "GET /api/user/42 HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
			anchors:     nil,
			scope:       nil,
			wantWarning: []string{"漏洞未锚定接口资产"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ValidateRetestPacket(tc.raw, tc.anchors, tc.scope)
			for _, want := range tc.wantErrors {
				if !containsSubstring(got.Errors, want) {
					t.Fatalf("errors = %v, want 含 %q", got.Errors, want)
				}
			}
			for _, want := range tc.wantWarning {
				if !containsSubstring(got.Warnings, want) {
					t.Fatalf("warnings = %v, want 含 %q", got.Warnings, want)
				}
			}
			wantValid := len(tc.wantErrors) == 0
			if got.Valid != wantValid {
				t.Fatalf("valid = %v (errors=%v), want %v", got.Valid, got.Errors, wantValid)
			}
		})
	}
}

func TestValidateRetestResponse(t *testing.T) {
	if errs := ValidateRetestResponse("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}", "GET"); len(errs) != 0 {
		t.Fatalf("合法响应被判错: %v", errs)
	}
	if errs := ValidateRetestResponse("200 OK\r\n\r\n", "GET"); len(errs) == 0 {
		t.Fatal("非法响应应当报错")
	}
	if errs := ValidateRetestResponse("", "GET"); len(errs) != 0 {
		t.Fatalf("空响应不该报错: %v", errs)
	}
}

// TestValidateRetestPacketLenient 覆盖模型常见的「不够标准但完全可用」的写法：
// 省略 Content-Length、缺少结尾空行、POST 正文直接跟在空行后面。
func TestValidateRetestPacketLenient(t *testing.T) {
	anchor := &Asset{
		ID: 9, Type: "endpoint", URL: "/api/login", Method: "POST",
		Params: []map[string]any{{"location": "body", "name": "username"}, {"location": "body", "name": "password"}},
	}
	raw := "POST /api/login HTTP/1.1\r\n" +
		"Host: app.example.com\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"username":"admin","password":"<密码>"}`
	got := ValidateRetestPacket(raw, anchor2slice(anchor), nil)
	if !got.Valid {
		t.Fatalf("省略 Content-Length 的报文应通过: %v", got.Errors)
	}
	if got.Method != "POST" || got.Path != "/api/login" {
		t.Fatalf("解析结果不符: %+v", got)
	}
	if !containsSubstring(got.Warnings, "疑似凭证字段 password") {
		t.Fatalf("应提示正文里的凭证字段: %v", got.Warnings)
	}

	// 头部没有结尾空行（模型常见）也要能解析。
	noBlank := "GET /api/user/1 HTTP/1.1\r\nHost: app.example.com"
	if got = ValidateRetestPacket(noBlank, nil, nil); !got.Valid {
		t.Fatalf("缺少结尾空行应容忍: %v", got.Errors)
	}

	// chunked 正文不做格式校验，只提示。
	chunked := "POST /api/login HTTP/1.1\r\nHost: app.example.com\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n{\"a\":1}\r\n0\r\n\r\n"
	if got = ValidateRetestPacket(chunked, anchor2slice(anchor), nil); !got.Valid {
		t.Fatalf("chunked 报文不该判错: %v", got.Errors)
	} else if !containsSubstring(got.Warnings, "chunked") {
		t.Fatalf("chunked 应给出提示: %v", got.Warnings)
	}
}

func TestCapRetestPacketText(t *testing.T) {
	small := "GET /api/user/1 HTTP/1.1\r\nHost: app.example.com\r\n\r\n"
	if got := capRetestPacketText(small); got != small {
		t.Fatalf("未超限不应改动: %q", got)
	}
	big := strings.Repeat("A", MaxRetestPacketBytes+4096)
	got := capRetestPacketText(big)
	if len(got) > MaxRetestPacketBytes+200 {
		t.Fatalf("截断后仍过长: %d", len(got))
	}
	if !strings.Contains(got, "已截断") {
		t.Fatal("截断必须留下说明，避免看起来像完整报文")
	}
}

func TestSaveRetestPacketRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	tk, err := d.CreateTask("复测报文测试", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID)

	es := d.Exploration(tk.ExplorationID)
	nodeID, err := es.AddNode(KindFinding, map[string]any{"summary": "x"}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	fid, err := d.AddFinding(tk.ID, nodeID, "越权", "未鉴权接口", "high", "summary", "poc", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	raw := "GET /api/user/1 HTTP/1.1\r\nHost: app.example.com\r\nCookie: <会话 Cookie>\r\n\r\n"
	v, err := d.SaveRetestPacket(ctx, fid, 0, nil, RetestPacketInput{
		RawRequest:   raw,
		GroundedRefs: []string{"src/main/java/com/x/UserController.java:88"},
		Generator:    "worker-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !v.Valid {
		t.Fatalf("合法报文应通过校验: %v", v.Errors)
	}
	if !containsSubstring(v.Warnings, "漏洞未锚定接口资产") {
		t.Fatalf("warnings = %v, want 含未锚定接口提示", v.Warnings)
	}

	p, err := d.GetFindingPacket(fid, 0)
	if err != nil || p == nil {
		t.Fatalf("读取报文失败: %v %v", p, err)
	}
	if p.RawRequest != raw || p.Source != RetestPacketSourceLLM || p.Revision != 1 || !p.Valid {
		t.Fatalf("落库字段不符: %+v", p)
	}
	if len(p.GroundedRefs) != 1 || len(p.Validation.Errors) != 0 {
		t.Fatalf("依据/校验结果不符: %+v", p)
	}

	// 重写：revision 递增，source 变 manual。
	if _, err = d.SaveRetestPacket(ctx, fid, 0, nil, RetestPacketInput{
		RawRequest: raw, Source: RetestPacketSourceManual, Generator: "human",
	}); err != nil {
		t.Fatal(err)
	}
	p, err = d.GetFindingPacket(fid, 0)
	if err != nil || p == nil {
		t.Fatalf("重写后读取失败: %v %v", p, err)
	}
	if p.Revision != 2 || p.Source != RetestPacketSourceManual {
		t.Fatalf("重写结果不符: %+v", p)
	}
	if !containsSubstring(p.Validation.Warnings, "未给出源码依据") {
		t.Fatalf("缺依据应给警告: %v", p.Validation.Warnings)
	}

	// 非法报文照样保存，但 valid=false 且原因可读。
	if v, err = d.SaveRetestPacket(ctx, fid, 0, nil, RetestPacketInput{RawRequest: "垃圾报文"}); err != nil {
		t.Fatal(err)
	}
	if v.Valid || !containsSubstring(v.Errors, "起始行不合法") {
		t.Fatalf("非法报文校验结果不符: %+v", v)
	}

	if deleted, err := d.DeleteFindingPacket(ctx, fid, 0); err != nil || !deleted {
		t.Fatalf("删除失败: %v %v", deleted, err)
	}
	if p, err = d.GetFindingPacket(fid, 0); err != nil || p != nil {
		t.Fatalf("删除后仍能读到: %+v %v", p, err)
	}
}

func TestFindingPacketCascadesOnFindingDelete(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	tk, err := d.CreateTask("复测报文级联测试", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID)

	es := d.Exploration(tk.ExplorationID)
	nodeID, err := es.AddNode(KindFinding, map[string]any{"summary": "x"}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	fid, err := d.AddFinding(tk.ID, nodeID, "越权", "未鉴权接口", "high", "summary", "poc", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.SaveRetestPacket(context.Background(), fid, 0, nil, RetestPacketInput{
		RawRequest: "GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = d.DeleteFinding(fid); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = d.QueryRow(`SELECT count(*) FROM finding_packets WHERE finding_id=$1`, fid).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("漏洞删除后报文应级联删除，仍剩 %d 行", count)
	}
}

// TestSaveRetestPacketPerInterface 覆盖「一个漏洞 × 每个接口一份报文」这个核心语义：
// 同一个漏洞能存下多份报文，各自绑定自己的接口、各自递增 revision，互不覆盖。
// 改造前 finding_id 是主键，这里第二份报文根本存不进去——正是复测卡住的根因。
func TestSaveRetestPacketPerInterface(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	tk, err := d.CreateTask("逐接口报文测试", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID)

	ep1 := seedTreeAsset(t, d, "endpoint", map[string]any{"url": "https://pi.example.com/api/user", "method": "GET"})
	ep2 := seedTreeAsset(t, d, "endpoint", map[string]any{"url": "https://pi.example.com/api/order", "method": "POST"})
	defer func() { _, _ = d.Exec(`DELETE FROM assets WHERE id IN ($1,$2)`, ep1, ep2) }()

	es := d.Exploration(tk.ExplorationID)
	nodeID, err := es.AddNode(KindFinding, map[string]any{"summary": "x"}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	fid, err := d.AddFinding(tk.ID, nodeID, "越权", "未鉴权接口", "high", "summary", "poc", "worker", []int64{ep1, ep2})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	raw1 := "GET /api/user HTTP/1.1\r\nHost: pi.example.com\r\nCookie: <会话 Cookie>\r\n\r\n"
	raw2 := "POST /api/order HTTP/1.1\r\nHost: pi.example.com\r\nCookie: <会话 Cookie>\r\n\r\n"

	if v, err := d.SaveRetestPacket(ctx, fid, ep1, []int64{ep1, ep2}, RetestPacketInput{
		RawRequest: raw1, GroundedRefs: []string{"a.java:1"},
	}); err != nil || !v.Valid {
		t.Fatalf("接口1的报文应保存并通过校验: %+v %v", v, err)
	}
	if v, err := d.SaveRetestPacket(ctx, fid, ep2, []int64{ep1, ep2}, RetestPacketInput{
		RawRequest: raw2, GroundedRefs: []string{"b.java:2"},
	}); err != nil || !v.Valid {
		t.Fatalf("接口2的报文应保存并通过校验: %+v %v", v, err)
	}

	list, err := d.ListFindingPackets(fid)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("一个漏洞两个接口应存下 2 份报文，实际 %d", len(list))
	}
	byAsset := map[int64]*FindingPacket{}
	for _, p := range list {
		byAsset[p.AssetID] = p
	}
	if p := byAsset[ep1]; p == nil || p.RawRequest != raw1 {
		t.Fatalf("接口1的报文不符: %+v", p)
	}
	if p := byAsset[ep2]; p == nil || p.RawRequest != raw2 {
		t.Fatalf("接口2的报文不符: %+v", p)
	}

	// 重写接口1只递增它自己的 revision，接口2不受影响。
	if _, err := d.SaveRetestPacket(ctx, fid, ep1, []int64{ep1, ep2}, RetestPacketInput{
		RawRequest: raw1, Source: RetestPacketSourceManual,
	}); err != nil {
		t.Fatal(err)
	}
	if p, _ := d.GetFindingPacket(fid, ep1); p == nil || p.Revision != 2 || p.Source != RetestPacketSourceManual {
		t.Fatalf("接口1 revision 应为 2 且 source=manual: %+v", p)
	}
	if p, _ := d.GetFindingPacket(fid, ep2); p == nil || p.Revision != 1 {
		t.Fatalf("接口2的 revision 不该被接口1的重写带动: %+v", p)
	}

	// 删掉一份不影响另一份。
	if deleted, err := d.DeleteFindingPacket(ctx, fid, ep1); err != nil || !deleted {
		t.Fatalf("删除接口1的报文失败: %v %v", deleted, err)
	}
	if p, _ := d.GetFindingPacket(fid, ep2); p == nil {
		t.Fatal("删除接口1后接口2的报文应仍在")
	}
}

// TestSaveRetestPacketAssetGuards 覆盖 asset_id 的两道闸门：
//  1. 指向不属于本漏洞的接口 → 不能挂上去（复测会打错目标），降级为「未指定」并报错；
//  2. 未指定接口但漏洞锚定了多个接口 → 必须给出警告，否则一份报文会被读成覆盖了全部。
func TestSaveRetestPacketAssetGuards(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	tk, err := d.CreateTask("报文接口归属校验", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID)

	ep1 := seedTreeAsset(t, d, "endpoint", map[string]any{"url": "https://ag.example.com/api/user", "method": "GET"})
	ep2 := seedTreeAsset(t, d, "endpoint", map[string]any{"url": "https://ag.example.com/api/order", "method": "POST"})
	foreign := seedTreeAsset(t, d, "endpoint", map[string]any{"url": "https://ag.example.com/api/other", "method": "GET"})
	defer func() { _, _ = d.Exec(`DELETE FROM assets WHERE id IN ($1,$2,$3)`, ep1, ep2, foreign) }()

	es := d.Exploration(tk.ExplorationID)
	nodeID, err := es.AddNode(KindFinding, map[string]any{"summary": "x"}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	fid, err := d.AddFinding(tk.ID, nodeID, "越权", "未鉴权接口", "high", "summary", "poc", "worker", []int64{ep1, ep2})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	raw := "GET /api/user HTTP/1.1\r\nHost: ag.example.com\r\nCookie: <会话 Cookie>\r\n\r\n"

	// 1) 外来 asset_id：报文仍然保存（辅助产物不该丢），但落到「未指定接口」并给出错误。
	v, err := d.SaveRetestPacket(ctx, fid, foreign, []int64{ep1, ep2}, RetestPacketInput{RawRequest: raw})
	if err != nil {
		t.Fatal(err)
	}
	if !containsSubstring(v.Errors, "不是本漏洞锚定的接口") {
		t.Fatalf("外来 asset_id 必须报错，实际 errors=%v", v.Errors)
	}
	if p, _ := d.GetFindingPacket(fid, 0); p == nil {
		t.Fatal("外来 asset_id 的报文应落在「未指定接口」槽位")
	}
	if p, _ := d.GetFindingPacket(fid, foreign); p != nil {
		t.Fatal("外来 asset_id 不该在它的接口槽位下留下报文")
	}

	// 2) 未指定接口 + 多个接口锚点：必须警告，让人知道这份报文没说是哪个接口。
	if _, err := d.DeleteFindingPacket(ctx, fid, 0); err != nil {
		t.Fatal(err)
	}
	v, err = d.SaveRetestPacket(ctx, fid, 0, []int64{ep1, ep2}, RetestPacketInput{RawRequest: raw})
	if err != nil {
		t.Fatal(err)
	}
	if !containsSubstring(v.Warnings, "未指定对应接口") {
		t.Fatalf("多接口下未指定 asset_id 必须警告，实际 warnings=%v", v.Warnings)
	}
}

// TestBackfillFindingPacketAssets 覆盖存量回填：老报文没有接口信息，只有「恰好能确定」
// 归属时才绑上；光看报文分不清是哪个接口的，保持「未指定」而不是猜一个。
func TestBackfillFindingPacketAssets(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	tk, err := d.CreateTask("报文接口回填测试", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID)

	// 单接口漏洞：报文的方法/路径能唯一确定归属 → 应被绑上。
	only := seedTreeAsset(t, d, "endpoint", map[string]any{"url": "https://bf.example.com/api/single", "method": "GET"})
	// 多接口漏洞：报文只可能对上其中一个，无法判断是哪一份 → 应保持未指定。
	multi1 := seedTreeAsset(t, d, "endpoint", map[string]any{"url": "https://bf.example.com/api/multi", "method": "GET"})
	multi2 := seedTreeAsset(t, d, "endpoint", map[string]any{"url": "https://bf.example.com/api/multi2", "method": "POST"})
	defer func() { _, _ = d.Exec(`DELETE FROM assets WHERE id IN ($1,$2,$3)`, only, multi1, multi2) }()

	es := d.Exploration(tk.ExplorationID)
	addFinding := func(assets []int64) int64 {
		t.Helper()
		nodeID, err := es.AddNode(KindFinding, map[string]any{"summary": "x"}, 5, "confirmed", "worker", nil)
		if err != nil {
			t.Fatal(err)
		}
		fid, err := d.AddFinding(tk.ID, nodeID, "越权", "未鉴权接口", "high", "summary", "poc", "worker", assets)
		if err != nil {
			t.Fatal(err)
		}
		return fid
	}
	singleFID := addFinding([]int64{only})
	multiFID := addFinding([]int64{multi1, multi2})

	ctx := context.Background()
	// 以「未指定接口」写入，模拟改造前遗留的报文。
	if _, err := d.SaveRetestPacket(ctx, singleFID, 0, nil, RetestPacketInput{
		RawRequest: "GET /api/single HTTP/1.1\r\nHost: bf.example.com\r\n\r\n",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SaveRetestPacket(ctx, multiFID, 0, nil, RetestPacketInput{
		RawRequest: "GET /api/multi HTTP/1.1\r\nHost: bf.example.com\r\n\r\n",
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := d.BackfillFindingPacketAssets(); err != nil {
		t.Fatal(err)
	}

	if p, _ := d.GetFindingPacket(singleFID, only); p == nil {
		t.Fatal("单接口漏洞的历史报文应被回填到那个唯一接口")
	}
	if p, _ := d.GetFindingPacket(multiFID, 0); p == nil {
		t.Fatal("分不清归属的报文应保持「未指定接口」")
	}
}

func anchor2slice(a *Asset) []*Asset { return []*Asset{a} }

func containsSubstring(items []string, want string) bool {
	for _, item := range items {
		if strings.Contains(item, want) {
			return true
		}
	}
	return false
}
