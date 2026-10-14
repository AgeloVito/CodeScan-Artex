package server

import "log"

// =====================================================================
// 代码审计工具面收口（每次启动幂等执行）
//
// 运行时的权威闸门在 agent 层：server/hostTools() 不再注入流量工具/自定义工具/MCP，
// server/assembly.go 不再展开 MCP，agent.AugmentTools 最后再用黑名单剔除一遍。
// 也就是说这些工具即使留在 tools 表里也到不了 agent 手里。
//
// 但「表里还写着 enabled + 绑定 worker/reporter」会在「系统配置 → 工具」页面上
// 显示成 agent 仍可使用，与「去掉任何能对外发起网络请求、测试、攻击的工具」矛盾，
// 也会误导管理员。所以这里把它们在表里明确关掉并解绑：
//   - 行保留（历史配置/审计留痕不丢），只置 enabled=false、agents='[]'；
//   - 每次启动都跑，因此像 seedFindingWorkflowTools() 这类老迁移即使把流量工具
//     重新绑回去，也会被这一步再收回（调用顺序：本函数在那些迁移之后）；
//   - 只动 system 行（我们自己 seed 的），用户自建工具保持原样。
// =====================================================================

// codeAuditRetiredExactKeys 是「出网 / 执行命令 / 攻击测试 / 自建可执行能力」类工具键。
// 与 agent/codeaudit_tools.go 的黑名单一致：那边负责运行时剔除，这边负责表内状态。
var codeAuditRetiredExactKeys = []string{
	// 流量录制与回放（渗透期取证能力）
	"traffic_search", "traffic_get", "traffic_blob",
	"get_finding_traffic", "bind_finding_traffic",
	// 平台内自建可执行能力：自定义工具（命令/脚本/HTTP）与 MCP（任意外部进程）
	"create_custom_tool", "update_custom_tool", "test_custom_tool",
	"create_mcp", "update_mcp",
	// SDK 默认的危险工具（若被早期版本 seed 过）
	"bash", "shell", "shell_session", "monitor", "sleep",
	"webfetch", "websearch", "web_search", "fetch", "curl", "wget", "http", "http_request",
	"task", "taskoutput", "taskstop", "tasklist",
}

// codeAuditRetiredPrefixes 是前缀匹配（SQL LIKE 模式，已转义下划线）。
var codeAuditRetiredPrefixes = []string{
	`mcp\_%`, `traffic\_%`,
	"browser%", "playwright%", "selenium%",
	"nmap%", "nuclei%", "sqlmap%", "ffuf%", "dirsearch%", "hydra%", "metasploit%",
}

// retireCodeAuditDangerousTools disables and unbinds every network/exec-capable
// built-in tool so the tools admin page reflects what agents can actually call.
func (s *Server) retireCodeAuditDangerousTools() {
	res, err := s.m.pg.Exec(`
UPDATE tools
   SET enabled = false, agents = '[]'::jsonb, updated_at = now()
 WHERE system
   AND (enabled OR jsonb_array_length(agents) > 0)
   AND (lower(key) = ANY($1) OR lower(key) LIKE ANY($2))`,
		codeAuditRetiredExactKeys, codeAuditRetiredPrefixes)
	if err != nil {
		log.Printf("[codeaudit] 收口出网/执行类工具失败: %v", err)
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("[codeaudit] 已停用并解绑 %d 个出网/执行类工具（traffic_* / mcp / 自定义工具等）", n)
	}
}
