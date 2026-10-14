package db

import (
	"testing"
)

// TestDependencyStoreRoundTrip verifies the task_dependencies schema applies on a
// live PostgreSQL and that the store's full lifecycle works: upsert (idempotent),
// list, find by coordinate, materialisation bookkeeping, and cascade delete.
//
// This is the "does the new table actually exist and behave" check for
// docs/java-m2依赖读取与反编译方案.md; it skips when no database is configured.
func TestDependencyStoreRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	// The new column must exist (added via ALTER TABLE ... IF NOT EXISTS).
	var depsPath string
	if err := d.QueryRow(`SELECT deps_path FROM tasks LIMIT 1`).Scan(&depsPath); err != nil {
		// No rows is fine — the column existing is what matters; a missing column
		// returns a different error, so probe with a count instead.
		var n int
		if err2 := d.QueryRow(`SELECT count(deps_path) FROM tasks`).Scan(&n); err2 != nil {
			t.Fatalf("tasks.deps_path 列不存在或不可查询: %v / %v", err, err2)
		}
	}

	tk, err := d.CreateTask("依赖测试", "验证 task_dependencies", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID) //nolint:errcheck

	store := d.Dependencies()

	dep := &Dependency{
		TaskID:       tk.ID,
		GroupID:      "org.apache.logging.log4j",
		Artifact:     "log4j-core",
		Version:      "2.17.0",
		GAVSource:    "pom.properties",
		Scope:        "compile",
		Direct:       true,
		JarPath:      "deps/jars/org/apache/logging/log4j/log4j-core/2.17.0/log4j-core-2.17.0.jar",
		JarSHA256:    "abc123",
		SizeBytes:    1789339,
		ClassCount:   644,
		PackageCount: 37,
		TopPackages:  []string{"org.apache.logging.log4j.core", "org.apache.logging.log4j.message"},
	}
	got, err := store.UpsertDependency(dep)
	if err != nil {
		t.Fatalf("UpsertDependency 失败: %v", err)
	}
	if got.ID == 0 {
		t.Fatal("UpsertDependency 未返回 id")
	}
	if got.SourceState != "none" {
		t.Errorf("新依赖 source_state = %q, 期望 none（默认不反编译）", got.SourceState)
	}
	if got.GAV != "org.apache.logging.log4j:log4j-core:2.17.0" {
		t.Errorf("GAV = %q", got.GAV)
	}
	if len(got.TopPackages) != 2 {
		t.Errorf("top_packages 未往返: %v", got.TopPackages)
	}
	if !got.CanMaterialize() {
		t.Error("普通 jar 应该可以按需反编译")
	}

	// Upsert must be idempotent on the coordinate (no duplicate rows)...
	dep.ClassCount = 645
	again, err := store.UpsertDependency(dep)
	if err != nil {
		t.Fatalf("第二次 Upsert 失败: %v", err)
	}
	if again.ID != got.ID {
		t.Errorf("重复 upsert 生成了新行: %d != %d", again.ID, got.ID)
	}
	if again.ClassCount != 645 {
		t.Errorf("重复 upsert 未更新类数: %d", again.ClassCount)
	}
	if n, err := store.CountDependencies(tk.ID); err != nil || n != 1 {
		t.Errorf("依赖数 = %d (err=%v), 期望 1", n, err)
	}

	// ...and must NOT clobber already-materialised source.
	if err := store.MarkMaterialized(got.ID, "decompiled", "deps/src/org/apache/logging/log4j/log4j-core/2.17.0", 644, 2626000, "cfr (java 11)", ""); err != nil {
		t.Fatalf("MarkMaterialized 失败: %v", err)
	}
	if _, err := store.UpsertDependency(dep); err != nil {
		t.Fatal(err)
	}
	refetched, err := store.GetDependency(got.ID)
	if err != nil || refetched == nil {
		t.Fatalf("GetDependency 失败: %v", err)
	}
	if refetched.SourceState != "decompiled" {
		t.Errorf("重新扫描后 source_state = %q, 期望 decompiled（不能被扫描覆盖）", refetched.SourceState)
	}
	if refetched.SourceFiles != 644 || refetched.SourcePath == "" || refetched.Materialized == nil {
		t.Errorf("反编译记录未持久化: files=%d path=%q at=%v",
			refetched.SourceFiles, refetched.SourcePath, refetched.Materialized)
	}

	// Find by coordinate, both with and without a group.
	found, err := store.FindDependency(tk.ID, "org.apache.logging.log4j", "log4j-core", "2.17.0", "")
	if err != nil || found == nil {
		t.Fatalf("FindDependency 未命中: %v", err)
	}
	if found.ID != got.ID {
		t.Errorf("FindDependency 命中错误行: %d != %d", found.ID, got.ID)
	}
	missing, err := store.FindDependency(tk.ID, "org.apache.logging.log4j", "log4j-core", "9.9.9", "")
	if err != nil {
		t.Fatalf("FindDependency 未知坐标应返回 nil,nil: %v", err)
	}
	if missing != nil {
		t.Error("未知坐标不应命中")
	}

	// Failure bookkeeping: an error is stored so callers don't retry blindly.
	if err := store.MarkMaterialized(got.ID, "", "", 0, 0, "", "没有可用的反编译器"); err != nil {
		t.Fatal(err)
	}
	failed, _ := store.GetDependency(got.ID)
	if failed.Error == "" {
		t.Error("失败原因未记录")
	}
	if failed.SourceState != "decompiled" {
		t.Errorf("记录失败不应清空已有源码状态: %q", failed.SourceState)
	}

	// A flat-repository jar (no groupId) must render without a leading colon.
	flat, err := store.UpsertDependency(&Dependency{
		TaskID: tk.ID, Artifact: "flat-lib", Version: "1.0", GAVSource: "filename",
		JarPath: "deps/jars/flat-lib-1.0.jar",
	})
	if err != nil {
		t.Fatal(err)
	}
	if flat.GAV != "flat-lib:1.0" {
		t.Errorf("无 groupId 的坐标渲染为 %q, 期望 flat-lib:1.0", flat.GAV)
	}
	if n, _ := store.CountDependencies(tk.ID); n != 2 {
		t.Errorf("依赖数 = %d, 期望 2", n)
	}

	list, err := store.ListDependencies(tk.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("ListDependencies 返回 %d 行, 期望 2", len(list))
	}
	// Ordering must be stable (group, artifact, version).
	if list[0].GroupID != "" || list[1].GroupID != "org.apache.logging.log4j" {
		t.Errorf("排序不符合预期: %q 在 %q 之前", list[0].GAV, list[1].GAV)
	}

	// Deleting the task must cascade to its dependencies.
	if err := store.DeleteTaskDependencies(tk.ID); err != nil {
		t.Fatal(err)
	}
	if n, _ := store.CountDependencies(tk.ID); n != 0 {
		t.Errorf("删除后仍有 %d 行", n)
	}

	// The FK itself must cascade too: dropping the task has to remove its
	// dependency rows, otherwise deleting a task would leave orphans behind.
	tk2, err := d.CreateTask("依赖级联测试", "验证 ON DELETE CASCADE", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertDependency(&Dependency{
		TaskID: tk2.ID, GroupID: "com.example", Artifact: "cascade-lib", Version: "1.0",
		JarPath: "deps/jars/cascade-lib-1.0.jar",
	}); err != nil {
		t.Fatal(err)
	}
	if n, _ := store.CountDependencies(tk2.ID); n != 1 {
		t.Fatalf("级联测试前依赖数 = %d, 期望 1", n)
	}
	if err := d.DeleteTask(tk2.ID); err != nil {
		t.Fatal(err)
	}
	var orphans int
	if err := d.QueryRow(`SELECT count(*) FROM task_dependencies WHERE task_id=$1`, tk2.ID).Scan(&orphans); err != nil {
		t.Fatal(err)
	}
	if orphans != 0 {
		t.Errorf("删除任务后仍残留 %d 行依赖（ON DELETE CASCADE 未生效）", orphans)
	}
}
