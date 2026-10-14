package agent

import (
	"context"
	"encoding/json"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

// fakeTool 是一个只有名字的最小工具，用来模拟「自定义工具 / MCP 工具」这类
// 名字由用户或外部配置决定、handler 任意的工具。
func fakeTool(name string) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:   name,
		Schema: map[string]any{"type": "object"},
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			return actool.Text("ok"), nil
		},
	})
}

func toolNames(tools []actool.CoreTool) []string {
	out := make([]string, 0, len(tools))
	for _, t := range tools {
		out = append(out, t.Name())
	}
	return out
}

func containsName(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

// 代码审计平台的核心性质：出网 / 执行命令 / 攻击测试类工具不能进入 agent 工具表——
// 无论它来自 SDK 默认集、DB 绑定、MCP 还是宿主工具注入。
func TestStripCodeAuditDeniedToolsDropsNetworkAndExecTools(t *testing.T) {
	in := append([]actool.CoreTool{}, CodeAuditTools()...)
	in = append(in,
		fakeTool("Bash"),                   // SDK 默认出网/执行工具
		fakeTool("Sleep"),                  // 等待
		fakeTool("WebFetch"),               // 直接抓取
		fakeTool("WebSearch"),              // 联网搜索
		fakeTool("mcp__browser__navigate"), // MCP 外部进程
		fakeTool("http"),                   // 自定义 http 工具（默认 key）
		fakeTool("command"),                // 自定义 command 工具（默认 key）
		fakeTool("script"),                 // 自定义 script 工具（默认 key）
		fakeTool("nmap_scan"),              // 常见攻击工具前缀
		fakeTool("traffic_search"),         // 流量回放
		fakeTool("Task"),                   // 子代理：会把上面的能力递归带进去
		fakeTool("create_mcp"),             // 平台内自建 MCP
	)
	got := toolNames(stripCodeAuditDeniedTools(in))

	for _, banned := range []string{
		"Bash", "Sleep", "WebFetch", "WebSearch", "mcp__browser__navigate", "http",
		"command", "script", "nmap_scan", "traffic_search", "Task", "create_mcp",
	} {
		if containsName(got, banned) {
			t.Fatalf("工具 %q 不应出现在代码审计工具表里（实际: %v）", banned, got)
		}
	}
	for _, keep := range []string{"Read", "Write", "Edit", "MultiEdit", "LS", "Glob", "Grep"} {
		if !containsName(got, keep) {
			t.Fatalf("通用文件工具 %q 被误删（实际: %v）", keep, got)
		}
	}
}

// 宿主注入的本地工具必须原样保留：编排/复测/平台工具与测试里的探针工具都不是
// 出网工具，黑名单不该按「不认识」就把它们删掉（否则装配层注入的工具会被静默吞掉）。
func TestStripCodeAuditDeniedToolsKeepsLocalHostTools(t *testing.T) {
	in := []actool.CoreTool{
		fakeTool("probe"), fakeTool("Skill"), fakeTool("insert_assets"),
		fakeTool("list_tasks"), fakeTool("update_finding_report"), fakeTool("create_skill"),
	}
	got := toolNames(stripCodeAuditDeniedTools(in))
	if len(got) != len(in) {
		t.Fatalf("本地宿主工具被误删：得到 %v，期望 %v", got, toolNames(in))
	}
}

// 黑名单按名字匹配（前缀 * 结尾表示前缀匹配）。
func TestIsCodeAuditDenied(t *testing.T) {
	denied := []string{
		"Bash", "bash", "WebFetch", "websearch", "mcp__x__y", "traffic_get", "http",
		"curl", "sleep", "Task", "command", "script", "nmap_scan", "sqlmap_run",
	}
	for _, n := range denied {
		if !isCodeAuditDenied(n) {
			t.Fatalf("%q 应该被判为禁止工具", n)
		}
	}
	for _, n := range []string{"Read", "Grep", "insert_assets", "add_finding", "Skill", "probe", "list_tasks"} {
		if isCodeAuditDenied(n) {
			t.Fatalf("%q 不应被判为禁止工具", n)
		}
	}
}
