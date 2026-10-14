package server

import "testing"

// 代码审计平台不再给出网/执行类工具：除了运行时剔除（agent 层黑名单 + 装配层不注入），
// tools 表里的状态也要如实反映——否则「系统配置 → 工具」会把它们显示成 agent 仍可使用。
// 这个测试锁住收口逻辑：出网/执行类工具被 enabled=false + agents=[]，本地工具不受影响。
func TestRetireCodeAuditDangerousTools(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg

	// 先把几个危险工具摆成「启用 + 已绑定」的状态（模拟老库/老迁移的结果）。
	dangerous := []struct{ key, agent string }{
		{"traffic_search", "worker"},
		{"traffic_get", "reporter"},
		{"create_custom_tool", "auto"},
		{"create_mcp", "auto"},
	}
	// 本平台全新初始化不再 seed 这些工具（orchestrationTools() 已不含流量/自建工具），
	// 而这一步收口是为「老渗透库」保留的。先把老库的行造出来，再验证收口效果——
	// 不能假设它们已经在表里（与下面 TestRetireCodeAuditDangerousToolsPatterns 同一做法）。
	for _, d := range dangerous {
		seedLegacyToolRow(t, s, d.key, "legacy "+d.key+" tool", "")
	}
	for _, d := range dangerous {
		row, err := pg.GetTool(d.key)
		if err != nil || row == nil {
			t.Fatalf("load %s: %v", d.key, err)
		}
		if _, err := pg.Exec(`UPDATE tools SET enabled=true, agents=$2::jsonb WHERE key=$1`, d.key, `["`+d.agent+`"]`); err != nil {
			t.Fatalf("arm %s: %v", d.key, err)
		}
	}

	s.retireCodeAuditDangerousTools()

	for _, d := range dangerous {
		row, err := pg.GetTool(d.key)
		if err != nil || row == nil {
			t.Fatalf("reload %s: %v", d.key, err)
		}
		if row.Enabled {
			t.Fatalf("%s 仍是 enabled，工具页面会显示成 agent 可用", d.key)
		}
		if len(row.Agents) != 0 {
			t.Fatalf("%s 仍绑定 %v，应被解绑", d.key, row.Agents)
		}
	}

	// 本地审计工具必须原样保留（不能误伤）。
	for _, key := range []string{"insert_assets", "list_assets", "report_finding", "create_skill"} {
		row, err := pg.GetTool(key)
		if err != nil || row == nil {
			t.Fatalf("load %s: %v", key, err)
		}
		if !row.Enabled {
			t.Fatalf("本地审计工具 %s 被误停用", key)
		}
	}

	// 幂等：再跑一次不应报错、状态不变。
	s.retireCodeAuditDangerousTools()
	for _, d := range dangerous {
		row, _ := pg.GetTool(d.key)
		if row.Enabled || len(row.Agents) != 0 {
			t.Fatalf("%s 在第二次收口后状态被改回", d.key)
		}
	}
}

// 名字前缀（mcp__ / traffic_ / 攻击工具）也要覆盖：老库可能留下没在精确列表里的同类行。
func TestRetireCodeAuditDangerousToolsPatterns(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg

	if _, err := pg.Exec(`
INSERT INTO tools (key, description, schema, enabled, system, agents, kind)
VALUES ('mcp__legacy__navigate', 'legacy mcp tool', '{"type":"object"}'::jsonb, true, true, '["worker"]'::jsonb, 'mcp')
ON CONFLICT (key) DO UPDATE SET enabled=true, agents='["worker"]'::jsonb`); err != nil {
		t.Fatalf("seed legacy mcp tool: %v", err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM tools WHERE key=$1`, "mcp__legacy__navigate") })

	s.retireCodeAuditDangerousTools()

	var enabled bool
	var agents string
	if err := pg.QueryRow(`SELECT enabled, agents::text FROM tools WHERE key=$1`, "mcp__legacy__navigate").Scan(&enabled, &agents); err != nil {
		t.Fatalf("reload mcp tool: %v", err)
	}
	if enabled || agents != "[]" {
		t.Fatalf("mcp 工具未被收口: enabled=%v agents=%s", enabled, agents)
	}
}
