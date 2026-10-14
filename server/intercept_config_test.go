package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
)

// 拦截总开关的 HTTP 往返（前端 Switch → api.interceptSetConfig → 落库 → guard 读取）。
//
// 这条链路就是「出个按钮把拦截关掉」的后端部分：关掉之后工具调用不再匹配规则、
// 不走模型兜底、也不请求人工审批。内置规则是对整个 tool_input 做子串/正则匹配的，
// 所以 Write 一个内容里带 "DROP TABLE"、TRUNCATE、"/delete" 的文件也会被 deny——
// 代码审计平台写报告/写 PoC 时很容易踩到。
func TestInterceptMasterSwitchHTTP(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("no test database configured")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	// 用完把开关恢复成「未设置」（=默认开启），别影响其它用例。
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM settings WHERE key='intercept_enabled'`) })
	m := &Manager{pg: d, interceptor: intercept.New(d)}
	s := &Server{m: m, jwtKey: []byte("intercept-master-switch-key")}
	h := s.Handler()
	token := testAdminToken(t, s)

	call := func(method, body string) *httptest.ResponseRecorder {
		var r io.Reader
		if body != "" {
			r = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, "/api/intercept/config", r)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	enabled := func(rec *httptest.ResponseRecorder) bool {
		var out struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("解析响应失败: %v %s", err, rec.Body.String())
		}
		return out.Enabled
	}

	// 未鉴权必须被拒。
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/intercept/config", nil))
	if rec.Code != 401 {
		t.Fatalf("未鉴权的配置读取应 401: %d", rec.Code)
	}

	// 未设置 = 默认开启（老库升级上来不能被静默关掉）。
	if _, err := d.Exec(`DELETE FROM settings WHERE key='intercept_enabled'`); err != nil {
		t.Fatal(err)
	}
	m.interceptor.Invalidate()
	if rec := call(http.MethodGet, ""); rec.Code != 200 || !enabled(rec) {
		t.Fatalf("默认应为开启: %d %s", rec.Code, rec.Body)
	}

	if rec := call(http.MethodPut, `{"enabled":false}`); rec.Code != 200 || enabled(rec) {
		t.Fatalf("关闭失败: %d %s", rec.Code, rec.Body)
	}
	if rec := call(http.MethodGet, ""); rec.Code != 200 || enabled(rec) {
		t.Fatalf("关闭后再读取仍为开启: %d %s", rec.Code, rec.Body)
	}
	// 缺字段必须拒绝：不能把「没传」当成 false 把拦截悄悄关掉。
	if rec := call(http.MethodPut, `{}`); rec.Code != 400 {
		t.Fatalf("缺少 enabled 应 400: %d %s", rec.Code, rec.Body)
	}
	if rec := call(http.MethodPut, `{"enabled":true}`); rec.Code != 200 || !enabled(rec) {
		t.Fatalf("重新开启失败: %d %s", rec.Code, rec.Body)
	}
}
