package agent

import (
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// =====================================================================
// 代码审计工具策略
//
// 这是 SCA Audit 对「agent 能调用什么」的唯一真源：agent 只能读写本地代码、
// 记录资产/漏洞、与平台交互。任何能对外发起网络请求、测试、攻击的工具都被移除：
//
//   - Bash / Sleep：Bash 可执行 curl/wget/nc/nmap/python -c 等，等价于给出网能力；
//   - WebFetch / WebSearch：直接出网抓取与搜索；
//   - traffic_search / traffic_get / traffic_blob：渗透期的流量录制与回放工具；
//   - MCP（mcp__*）：用户可配置任意外部进程（如浏览器/扫描器）；
//   - 自定义工具（command/script/http）：用户可写入任意命令或 HTTP 调用；
//   - Task/Monitor 等子代理与后台执行工具：会把上述能力递归带进子代理。
//
// 保留的是纯本地能力：Read/Write/Edit/MultiEdit/LS/Glob/Grep + artex 自己的资产/
// 漏洞/图谱读写工具（它们只操作数据库与本地文件）。
//
// 三层防线（缺一不可）：
//  1. CodeAuditTools()：各 agent 的通用工具集只从这七个本地文件工具构造；
//  2. 装配层不再注入危险来源：server/hostTools() 不返回流量工具、自定义工具与 MCP
//     （见 server/orchestration.go），server/assembly.go 也不再展开 MCP；
//  3. 本文件的兜底黑名单：即使 DB tools 表、可见性配置或宿主工具把它们塞进来，
//     也会在 AugmentTools 的最后一步按名字剔除。
// =====================================================================

// codeAuditDeniedTools 是兜底黑名单（小写名，前缀用 * 结尾匹配）。
// 即使 DB 的 tools 表、可见性配置或宿主工具想把它们塞给 agent，也会在
// AugmentTools 的最后一步被剔除，保证「不存在出网工具」这条性质不被配置绕过。
//
// 注意：黑名单只能按名字匹配，所以它必须和上面第 2 层（装配层不注入）一起用——
// 自定义工具的 key 由用户自由命名，单靠黑名单无法穷举（"run_scan" 这类名字不在表里）。
var codeAuditDeniedTools = []string{
	"bash", "shell", "shell_session", "sleep", "monitor",
	"webfetch", "websearch", "web_search", "fetch", "curl", "wget", "http", "http_request",
	// 自定义工具三种 kind 的默认 key：command(命令) / script(Python) / http(API)。
	"command", "script",
	"task", "taskoutput", "taskstop", "tasklist",
	"mcp__*",
	"traffic_*",
	"intercept_execute", "intercept_approve",
	"browser*", "playwright*", "selenium*",
	"nmap*", "nuclei*", "sqlmap*", "ffuf*", "dirsearch*", "hydra*", "metasploit*",
	"create_custom_tool", "update_custom_tool", "create_mcp", "update_mcp", "test_custom_tool",
}

// CodeAuditTools returns the通用工具集 for every code-audit agent: file-oriented,
// local-only tools. It deliberately mirrors a subset of the SDK DefaultTools().
func CodeAuditTools() []actool.CoreTool {
	return []actool.CoreTool{
		actool.NewRead(),
		actool.NewWrite(),
		actool.NewEdit(),
		actool.NewMultiEdit(),
		actool.NewLS(),
		actool.NewGlob(),
		actool.NewGrep(),
	}
}

// isCodeAuditDenied reports whether a tool name is removed from the code-audit
// surface for any agent.
func isCodeAuditDenied(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	for _, pattern := range codeAuditDeniedTools {
		if strings.HasSuffix(pattern, "*") {
			if strings.HasPrefix(n, strings.TrimSuffix(pattern, "*")) {
				return true
			}
			continue
		}
		if n == pattern {
			return true
		}
	}
	return false
}

// stripCodeAuditDeniedTools removes every denied tool, preserving order. Applied
// last in AugmentTools, so it also covers tools injected by the DB tools table,
// MCP, skills and host-tool providers.
func stripCodeAuditDeniedTools(tools []actool.CoreTool) []actool.CoreTool {
	out := make([]actool.CoreTool, 0, len(tools))
	for _, t := range tools {
		if t == nil || isCodeAuditDenied(t.Name()) {
			continue
		}
		out = append(out, t)
	}
	return out
}
