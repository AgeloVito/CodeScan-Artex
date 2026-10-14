package db

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
)

func retestDB(t *testing.T) (*DB, int64) {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	fid, err := d.AddFinding(0, 0, "retest-test", "测试漏洞", "high", "original summary", "original evidence", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM conversations WHERE id IN (SELECT conversation_id FROM finding_retests WHERE finding_id=$1)`, fid)
		_, _ = d.DeleteFinding(fid)
		d.Close()
	})
	return d, fid
}

func TestRetestAtomicDeduplicationAndHistory(t *testing.T) {
	d, fid := retestDB(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	createdCount := 0
	ids := make([]int64, 0, 8)
	for range 8 {
		wg.Go(func() {
			r, c, created, err := d.CreateFindingRetest(t.Context(), fid, "  修复版本 v2  ")
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			ids = append(ids, r.ID)
			if created {
				createdCount++
				if c == nil {
					t.Error("created without conversation")
				}
			}
		})
	}
	wg.Wait()
	if createdCount != 1 || len(ids) != 8 {
		t.Fatalf("created=%d ids=%v", createdCount, ids)
	}
	for _, id := range ids {
		if id != ids[0] {
			t.Fatal("duplicate active retests", ids)
		}
	}
	rows, err := d.ListFindingRetests(fid)
	if err != nil || len(rows) != 1 {
		t.Fatalf("history=%v err=%v", rows, err)
	}
	r := rows[0]
	if r.Snapshot != nil {
		t.Fatal("history leaks large snapshot")
	}
	ctx := t.Context()
	full, err := d.FindingRetestForConversation(ctx, *r.ConversationID)
	if err != nil || !strings.Contains(string(full.Snapshot), "original evidence") {
		t.Fatalf("snapshot=%+v err=%v", full, err)
	}
	var messages int
	if err := d.QueryRow(`SELECT count(*) FROM conversation_activities WHERE conversation_id=$1 AND kind='user'`, *r.ConversationID).Scan(&messages); err != nil || messages != 1 {
		t.Fatalf("messages=%d err=%v", messages, err)
	}
	_, _ = d.Exec(`UPDATE findings SET evidence='changed evidence' WHERE id=$1`, fid)
	full, err = d.FindingRetestForConversation(ctx, *r.ConversationID)
	if err != nil || strings.Contains(string(full.Snapshot), "changed evidence") {
		t.Fatal("snapshot changed", err)
	}
	if err = d.RecordFindingRetestResult(ctx, *r.ConversationID, "confirmed", "summary", "proof"); !errors.Is(err, ErrRetestNotRunning) {
		t.Fatal("pending accepted result", err)
	}
	if ok, err := d.StartFindingRetest(ctx, r.ID); err != nil || !ok {
		t.Fatalf("start=%t %v", ok, err)
	}
	if err := d.RecordFindingRetestResult(ctx, 0, "confirmed", "summary", "proof"); !errors.Is(err, ErrRetestNotRunning) {
		t.Fatal("unscoped write accepted", err)
	}
	for range 2 {
		if err := d.RecordFindingRetestResult(ctx, *r.ConversationID, "confirmed", "复核通过", "回到源码核对：触发路径可达、输入可控、危险操作闭合"); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.RecordFindingRetestResult(ctx, *r.ConversationID, "refuted", "different", "proof"); !errors.Is(err, ErrRetestNotRunning) {
		t.Fatal("overwrote staged result", err)
	}
	if err := d.FinishFindingRetest(r.ID, "completed", ""); err != nil {
		t.Fatal(err)
	}
	if err := d.RecordFindingRetestResult(ctx, *r.ConversationID, "confirmed", "summary", "proof"); !errors.Is(err, ErrRetestNotRunning) {
		t.Fatal("overwrote sealed result", err)
	}
	f, _ := d.GetFinding(fid)
	if f.Status != FindingConfirmed || f.Evidence != "changed evidence" || f.Report != "" {
		t.Fatal("confirmed retest did not update only triage", f)
	}
	next, _, created, err := d.CreateFindingRetest(ctx, fid, "second")
	if err != nil || !created || next.ID == r.ID {
		t.Fatalf("new history=%+v created=%t err=%v", next, created, err)
	}
	if err := d.FinishFindingRetest(next.ID, "completed", ""); err != nil {
		t.Fatal(err)
	}
	rows, _ = d.ListFindingRetests(fid)
	if len(rows) != 2 || rows[0].Status != "failed" || rows[0].Error == "" || rows[1].Verdict != "confirmed" {
		t.Fatal("missing verdict treated as successful", rows)
	}
}

func TestRetestDeletionAndRestart(t *testing.T) {
	d, fid := retestDB(t)
	r, c, _, err := d.CreateFindingRetest(t.Context(), fid, "delete")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteConversation(c.ID); err != nil {
		t.Fatal(err)
	}
	rows, _ := d.ListFindingRetests(fid)
	if len(rows) != 1 || rows[0].ConversationID != nil || rows[0].Status != "stopped" {
		t.Fatal(rows)
	}
	next, c2, created, err := d.CreateFindingRetest(t.Context(), fid, "restart")
	if err != nil || !created {
		t.Fatal("deleted session blocks retry", err)
	}
	if ok, err := d.StartFindingRetest(t.Context(), next.ID); err != nil || !ok {
		t.Fatal(err)
	}
	if err := d.RecoverFindingRetests(); err != nil {
		t.Fatal(err)
	}
	if err := d.FinishFindingRetest(next.ID, "completed", ""); err != nil {
		t.Fatal(err)
	}
	full, _ := d.FindingRetestForConversation(t.Context(), c2.ID)
	if full.Status != "stopped" || full.FinishedAt == nil {
		t.Fatal("restart result overwritten", full)
	}
	if _, err := d.DeleteFinding(fid); err != nil {
		t.Fatal(err)
	}
	var count int
	_ = d.QueryRow(`SELECT count(*) FROM finding_retests WHERE id IN ($1,$2)`, r.ID, next.ID).Scan(&count)
	if count != 0 {
		t.Fatal("finding deletion did not cascade")
	}
	_ = d.DeleteConversation(c2.ID)
}

func TestRetestValidationAndRollback(t *testing.T) {
	d, fid := retestDB(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, _, err := d.CreateFindingRetest(ctx, fid, ""); err == nil {
		t.Fatal("cancelled creation succeeded")
	}
	for _, args := range [][3]string{{"unknown", "summary", "proof"}, {"confirmed", " ", "proof"}, {"confirmed", "summary", ""}, {"confirmed", strings.Repeat("x", 16001), "proof"}} {
		if err := d.RecordFindingRetestResult(t.Context(), 0, args[0], args[1], args[2]); err == nil {
			t.Fatal("bad result accepted", args[0])
		}
	}
	r, c, _, err := d.CreateFindingRetest(t.Context(), fid, "snapshot")
	if err != nil {
		t.Fatal(err)
	}
	full, err := d.FindingRetestForConversation(t.Context(), c.ID)
	var snap map[string]json.RawMessage
	if err != nil || json.Unmarshal(full.Snapshot, &snap) != nil || len(snap["finding"]) == 0 {
		t.Fatal("invalid snapshot", err)
	}
	if r.Notes != "snapshot" {
		t.Fatal("notes lost")
	}
}

func TestRetestFixedTriageOnlyAfterSuccessfulCompletion(t *testing.T) {
	for _, tc := range []struct{ verdict, terminal, want string }{
		{"confirmed", "completed", FindingConfirmed},
		{"refuted", "completed", FindingFalsePositive},
		{"confirmed", "failed", FindingInProgress},
		{"confirmed", "stopped", FindingInProgress},
		{"refuted", "failed", FindingInProgress},
		{"inconclusive", "completed", FindingInProgress},
		{"", "completed", FindingInProgress},
	} {
		t.Run(tc.verdict+"/"+tc.terminal, func(t *testing.T) {
			d, fid := retestDB(t)
			if _, err := d.SetFindingStatus(fid, FindingInProgress); err != nil {
				t.Fatal(err)
			}
			r, c, _, err := d.CreateFindingRetest(t.Context(), fid, "check triage")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := d.StartFindingRetest(t.Context(), r.ID); err != nil {
				t.Fatal(err)
			}
			if tc.verdict != "" {
				if err := d.RecordFindingRetestResult(t.Context(), c.ID, tc.verdict, "summary", "proof"); err != nil {
					t.Fatal(err)
				}
			}
			f, err := d.GetFinding(fid)
			if err != nil || f.Status != FindingInProgress {
				t.Fatal("staged verdict changed triage", err, f)
			}
			if err := d.FinishFindingRetest(r.ID, tc.terminal, ""); err != nil {
				t.Fatal(err)
			}
			f, err = d.GetFinding(fid)
			if err != nil || f.Status != tc.want || f.Evidence != "original evidence" {
				t.Fatalf("finding=%+v err=%v want=%s", f, err, tc.want)
			}
			// Re-delivering completion must not undo a later user decision.
			if _, err := d.SetFindingStatus(fid, FindingIgnored); err != nil {
				t.Fatal(err)
			}
			if err := d.FinishFindingRetest(r.ID, "completed", ""); err != nil {
				t.Fatal(err)
			}
			f, err = d.GetFinding(fid)
			if err != nil || f.Status != FindingIgnored {
				t.Fatal("replayed completion overwrote triage", err, f)
			}
		})
	}
}

// 老库的 finding_retests.verdict 约束只允许旧值（'','reproduced','fixed','inconclusive'）。
// schema.sql 用的是 CREATE TABLE IF NOT EXISTS，对已存在的表不会改约束——所以必须靠
// migrateFindingRetestVerdicts 放宽。不放宽的话「漏洞复核」的新结论写入直接撞 CHECK
// 约束（SQLSTATE 23514），复核永远存不下结论，而且只在老库上复现、新库测不出来。
//
// 这里把约束显式还原成老库版本再跑迁移，验证迁移确实解决了它。
func TestFindingRetestVerdictConstraintMigration(t *testing.T) {
	d, fid := retestDB(t)
	ctx := t.Context()

	// 还原成老库状态：旧约束 + 迁移标记缺失。
	if _, err := d.Exec(`ALTER TABLE finding_retests DROP CONSTRAINT IF EXISTS finding_retests_verdict_check`); err != nil {
		t.Fatal(err)
	}
	// NOT VALID：只约束「新写入/更新」，不回溯校验已有行——测试库里可能残留别的
	// 用例写下的新结论行，回溯校验会让这条 ADD 直接失败。而本用例要验证的正是
	// 「新结论被老约束拒绝」，NOT VALID 已经足够（新行/新更新同样受约束）。
	if _, err := d.Exec(`ALTER TABLE finding_retests ADD CONSTRAINT finding_retests_verdict_check
CHECK (verdict IN ('','reproduced','fixed','inconclusive')) NOT VALID`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`DELETE FROM settings WHERE key='finding_retests_verdict_review_v1'`); err != nil {
		t.Fatal(err)
	}

	r, _, _, err := d.CreateFindingRetest(ctx, fid, "迁移验证")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := d.StartFindingRetest(ctx, r.ID); err != nil || !ok {
		t.Fatalf("start=%v err=%v", ok, err)
	}
	// 前提：老约束确实拒绝新结论，否则本用例什么也证明不了。
	if err := d.RecordFindingRetestResult(ctx, *r.ConversationID, VerdictConfirmed, "s", "e"); err == nil {
		t.Fatal("老约束竟然接受了 confirmed——本用例前提不成立")
	}
	if err := d.migrateFindingRetestVerdicts(); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	if err := d.RecordFindingRetestResult(ctx, *r.ConversationID, VerdictConfirmed, "s", "e"); err != nil {
		t.Fatalf("迁移后 confirmed 仍写不进去: %v", err)
	}
	// 历史行的旧结论必须仍可写：迁移只放宽约束，不追认旧值。
	// 用 UPDATE 而不是新 INSERT：一个 finding 只允许一条活跃复测（唯一索引），
	// 另插一行会撞 idx_finding_retests_active，与本次要验证的约束无关。
	if _, err := d.Exec(`UPDATE finding_retests SET verdict='reproduced' WHERE id=$1`, r.ID); err != nil {
		t.Fatalf("历史 reproduced 值被迁移误伤: %v", err)
	}
	// 标记已落库：正常启动不会重复执行。
	if v, ok, err := d.GetSetting("finding_retests_verdict_review_v1"); err != nil || !ok || v != "done" {
		t.Fatalf("迁移标记未落库: v=%q ok=%t err=%v", v, ok, err)
	}
	// 标记丢失后重复执行必须幂等（DROP IF EXISTS + ADD 落在已放宽的约束上）。
	if _, err := d.Exec(`DELETE FROM settings WHERE key='finding_retests_verdict_review_v1'`); err != nil {
		t.Fatal(err)
	}
	if err := d.migrateFindingRetestVerdicts(); err != nil {
		t.Fatalf("重复迁移失败: %v", err)
	}
}
