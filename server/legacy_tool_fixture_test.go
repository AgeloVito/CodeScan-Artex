package server

import (
	"encoding/json"
	"testing"
)

// seedLegacyToolRow 为「从渗透模式升级过来的老库」补一行内置工具，返回时已在测试结束时登记删除。
//
// 代码审计平台在全新初始化时不再 seed 流量工具与自建可执行工具（orchestrationTools()
// 已不含它们，见 server/orchestration.go），所以新库的 tools 表里根本没有这些行。
// 而 retireCodeAuditDangerousTools 与 seedFindingWorkflowTools 里的流量迁移，都是为
// 「老库」保留的收口/升级逻辑——要测它们，就必须先把老库的行造出来，不能假设它已经在表里。
//
// 只在行不存在时插入；已存在的行原样保留（调用方自己负责恢复它改过的内容）。
func seedLegacyToolRow(t *testing.T, s *Server, key, description, agents string) {
	t.Helper()
	pg := s.m.pg
	row, err := pg.GetTool(key)
	if err != nil {
		t.Fatalf("load %s: %v", key, err)
	}
	if row != nil {
		return
	}
	if agents == "" {
		agents = "[]"
	}
	if err := pg.SeedTool(key, description, json.RawMessage(`{"type":"object","properties":{}}`), json.RawMessage(agents)); err != nil {
		t.Fatalf("seed legacy tool %s: %v", key, err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM tools WHERE key=$1`, key) })
}
