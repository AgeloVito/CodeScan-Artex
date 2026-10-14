package javadeps

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- coordinate validation: the path-safety boundary -------------------------

func TestGAVValidateRejectsPathEscape(t *testing.T) {
	bad := []struct {
		name string
		gav  GAV
	}{
		{"group is dotdot", GAV{Group: "..", Artifact: "a", Version: "1"}},
		{"group has slash", GAV{Group: "com/evil", Artifact: "a", Version: "1"}},
		{"group has backslash", GAV{Group: `com\evil`, Artifact: "a", Version: "1"}},
		{"artifact is dotdot", GAV{Group: "com.a", Artifact: "..", Version: "1"}},
		{"artifact escapes", GAV{Group: "com.a", Artifact: "../../b", Version: "1"}},
		{"version is dotdot", GAV{Group: "com.a", Artifact: "b", Version: ".."}},
		{"classifier escapes", GAV{Group: "com.a", Artifact: "b", Version: "1", Classifier: "../../x"}},
		{"classifier has slash", GAV{Group: "com.a", Artifact: "b", Version: "1", Classifier: "a/b"}},
		{"classifier has backslash", GAV{Group: "com.a", Artifact: "b", Version: "1", Classifier: `a\b`}},
		{"classifier has colon", GAV{Group: "com.a", Artifact: "b", Version: "1", Classifier: "a:b"}},
		{"artifact missing", GAV{Group: "com.a", Artifact: "", Version: "1"}},
		{"version missing", GAV{Group: "com.a", Artifact: "b", Version: ""}},
		{"padded artifact", GAV{Group: "com.a", Artifact: " b", Version: "1"}},
		{"control char", GAV{Group: "com.a", Artifact: "b\x00c", Version: "1"}},
		{"newline in version", GAV{Group: "com.a", Artifact: "b", Version: "1\n2"}},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			if err := c.gav.Validate(); err == nil {
				t.Errorf("Validate(%q) 应当拒绝", c.gav.String())
			}
			if err := c.gav.SafeValidate(); !errors.Is(err, ErrUnsafeGAV) {
				t.Errorf("SafeValidate(%q) 应包 ErrUnsafeGAV，得到 %v", c.gav.String(), err)
			}
		})
	}

	good := []GAV{
		{Group: "org.apache.logging.log4j", Artifact: "log4j-core", Version: "2.17.0"},
		{Group: "com.example", Artifact: "demo", Version: "1.0-SNAPSHOT", Classifier: "sources"},
		{Group: "com.example", Artifact: "demo", Version: "1.0-alpha-1"},
		// 无 group 的扁平 jar 在通用校验里是合法的（本地仓库查找才会额外要求 group）
		{Artifact: "demo", Version: "1.0"},
	}
	for _, g := range good {
		if err := g.Validate(); err != nil {
			t.Errorf("Validate(%q) 不应报错: %v", g.String(), err)
		}
	}
}

// --- local repository resolution ---------------------------------------------

// writeFakeArtifact lays down <root>/<rel> and returns its absolute path.
func writeFakeArtifact(t *testing.T, root, rel, content string) string {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("建目录失败: %v", err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("写文件失败: %v", err)
	}
	return p
}

// sameFile compares two paths by identity rather than by string. NewLocalRepo
// resolves symlinks and Windows short names, so the returned path can legitimately
// differ textually from the one a test built.
func sameFile(t *testing.T, a, b string) bool {
	t.Helper()
	fa, errA := os.Stat(a)
	fb, errB := os.Stat(b)
	if errA != nil || errB != nil {
		return false
	}
	return os.SameFile(fa, fb)
}

func TestNewLocalRepoDisabled(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	for _, dir := range []string{"", "   ", missing} {
		if NewLocalRepo(dir).Enabled() {
			t.Errorf("NewLocalRepo(%q) 应当是 disabled", dir)
		}
	}
	// A file is not a repository either.
	f := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if NewLocalRepo(f).Enabled() {
		t.Error("指向普通文件的配置应当是 disabled")
	}

	// nil receiver must be safe everywhere.
	var r *LocalRepo
	if r.Enabled() || r.Path() != "" {
		t.Error("nil *LocalRepo 应当表现为 disabled")
	}
	if _, err := r.Resolve(GAV{Group: "a.b", Artifact: "c", Version: "1"}); !errors.Is(err, ErrNoLocalRepo) {
		t.Errorf("nil 仓库解析应返回 ErrNoLocalRepo，得到 %v", err)
	}
	if _, err := r.ResolveSources(GAV{Group: "a.b", Artifact: "c", Version: "1"}); !errors.Is(err, ErrNoLocalRepo) {
		t.Errorf("nil 仓库解析 sources 应返回 ErrNoLocalRepo，得到 %v", err)
	}
}

func TestLocalRepoResolve(t *testing.T) {
	root := t.TempDir()
	jar := writeFakeArtifact(t, root, "org/example/demo/1.0/demo-1.0.jar", "JARBYTES")
	src := writeFakeArtifact(t, root, "org/example/demo/1.0/demo-1.0-sources.jar", "SOURCES")
	tests := writeFakeArtifact(t, root, "org/example/demo/1.0/demo-1.0-tests.jar", "TESTS")
	// A sibling artifact that must never be touched by a lookup of "demo".
	writeFakeArtifact(t, root, "org/example/other/1.0/other-1.0.jar", "OTHER")

	repo := NewLocalRepo(root)
	if !repo.Enabled() {
		t.Fatal("仓库应当可用")
	}

	g := GAV{Group: "org.example", Artifact: "demo", Version: "1.0"}
	got, err := repo.Resolve(g)
	if err != nil || !sameFile(t, got, jar) {
		t.Fatalf("Resolve = %q, %v；期望 %q", got, err, jar)
	}
	if s, err := repo.ResolveSources(g); err != nil || !sameFile(t, s, src) {
		t.Fatalf("ResolveSources = %q, %v；期望 %q", s, err, src)
	}
	if !repo.HasSources(g) {
		t.Error("HasSources 应当为 true")
	}

	// A classifier resolves that variant, not the main jar.
	if got, err := repo.Resolve(GAV{Group: "org.example", Artifact: "demo", Version: "1.0", Classifier: "tests"}); err != nil || !sameFile(t, got, tests) {
		t.Errorf("带 classifier 的 Resolve = %q, %v；期望 %q", got, err, tests)
	}

	// Missing artifact: the error must name the path that was searched.
	if _, err := repo.Resolve(GAV{Group: "org.example", Artifact: "nope", Version: "1.0"}); !errors.Is(err, ErrArtifactNotFound) {
		t.Errorf("不存在的坐标应返回 ErrArtifactNotFound，得到 %v", err)
	} else if !strings.Contains(err.Error(), "org/example/nope/1.0") {
		t.Errorf("错误信息应包含查找路径，得到 %v", err)
	}

	// A repository layout needs a groupId.
	if _, err := repo.Resolve(GAV{Artifact: "demo", Version: "1.0"}); err == nil {
		t.Error("缺 groupId 的坐标无法按仓库布局解析，应当报错")
	} else if !strings.Contains(err.Error(), "groupId") {
		t.Errorf("错误信息应说明缺 groupId，得到 %v", err)
	}

	// A directory that carries the jar's name is not an artifact.
	writeFakeArtifact(t, root, "org/example/dirjar/1.0/dirjar-1.0.jar/placeholder", "x")
	if _, err := repo.Resolve(GAV{Group: "org.example", Artifact: "dirjar", Version: "1.0"}); !errors.Is(err, ErrArtifactNotFound) {
		t.Errorf("同名目录不应被当成 jar，得到 %v", err)
	}
}

func TestLocalRepoRefusesTraversal(t *testing.T) {
	root := t.TempDir()
	// A file that a traversal would reach if the coordinate were joined blindly.
	outside := writeFakeArtifact(t, filepath.Dir(root), "secret-1.0.jar", "SECRET")
	writeFakeArtifact(t, root, "org/example/demo/1.0/demo-1.0.jar", "JARBYTES")

	repo := NewLocalRepo(root)
	for _, bad := range []GAV{
		{Group: "..", Artifact: "secret", Version: "1.0"},
		{Group: "org.example", Artifact: "../../../secret", Version: "1.0"},
		{Group: "org.example", Artifact: "demo", Version: ".."},
		{Group: "org.example", Artifact: "demo", Version: "1.0", Classifier: "../../../../secret-1.0"},
	} {
		if _, err := repo.Resolve(bad); err == nil {
			t.Errorf("Resolve(%q) 必须拒绝", bad.String())
		}
	}
	// Sanity: the file a traversal would have hit is still where it was.
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("测试装置被破坏了: %v", err)
	}
}

// --- import into a task -------------------------------------------------------

func TestImportFromLocalRepoPlacesJarAndSources(t *testing.T) {
	repoRoot := t.TempDir()
	srcJar := writeFakeArtifact(t, repoRoot, "org/example/demo/1.0/demo-1.0.jar", "JARBYTES")
	writeFakeArtifact(t, repoRoot, "org/example/demo/1.0/demo-1.0-sources.jar", "SOURCES")
	// Another coordinate in the same repository, which must NOT come along.
	writeFakeArtifact(t, repoRoot, "org/example/other/1.0/other-1.0.jar", "OTHER")

	dataDir := t.TempDir()
	svc := NewService(dataDir, nil)
	svc.LocalRepo = NewLocalRepo(repoRoot)

	g := GAV{Group: "org.example", Artifact: "demo", Version: "1.0"}
	res, err := svc.ImportFromLocalRepo("42", g)
	if err != nil {
		t.Fatalf("导入失败: %v", err)
	}
	const wantRel = "deps/jars/org/example/demo/1.0/demo-1.0.jar"
	if res.JarRelPath != wantRel {
		t.Errorf("JarRelPath = %q，期望 %q", res.JarRelPath, wantRel)
	}
	if !res.Linked {
		t.Error("首次导入应当是 Linked")
	}
	if !res.Sources || res.SourcesRel == "" {
		t.Error("仓库里有 sources jar 时应当一并导入")
	}
	if res.Bytes != int64(len("JARBYTES")) {
		t.Errorf("Bytes = %d，期望 %d", res.Bytes, len("JARBYTES"))
	}

	destAbs := filepath.Join(dataDir, "tasks", "42", filepath.FromSlash(wantRel))
	if b, err := os.ReadFile(destAbs); err != nil || string(b) != "JARBYTES" {
		t.Fatalf("落盘的 jar 内容不对: %q, %v", b, err)
	}
	// sourcesJarPath() looks next to the main jar, so this is what makes L1 work later.
	if _, err := os.Stat(filepath.Join(filepath.Dir(destAbs), "demo-1.0-sources.jar")); err != nil {
		t.Errorf("sources jar 应当落在主 jar 旁边: %v", err)
	}

	// The core invariant: only the named coordinate was taken out of the repository.
	var jars []string
	_ = filepath.WalkDir(filepath.Join(dataDir, "tasks", "42", "deps", "jars"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(dataDir, p)
		if rerr == nil {
			jars = append(jars, filepath.ToSlash(rel))
		}
		return nil
	})
	if len(jars) != 2 {
		t.Errorf("只应导入被点名坐标的 jar + sources，实际 %v", jars)
	}

	// The source repository is read-only.
	if b, err := os.ReadFile(srcJar); err != nil || string(b) != "JARBYTES" {
		t.Errorf("导入不应改动源仓库: %q, %v", b, err)
	}

	// Importing again is a no-op, not a duplicate.
	again, err := svc.ImportFromLocalRepo("42", g)
	if err != nil {
		t.Fatalf("重复导入报错: %v", err)
	}
	if again.Linked {
		t.Error("重复导入不应再次写入")
	}
}

func TestImportFromLocalRepoClassifierSkipsSourcesLookup(t *testing.T) {
	repoRoot := t.TempDir()
	writeFakeArtifact(t, repoRoot, "org/example/demo/1.0/demo-1.0.jar", "JARBYTES")
	writeFakeArtifact(t, repoRoot, "org/example/demo/1.0/demo-1.0-tests.jar", "TESTS")
	writeFakeArtifact(t, repoRoot, "org/example/demo/1.0/demo-1.0-sources.jar", "SOURCES")

	svc := NewService(t.TempDir(), nil)
	svc.LocalRepo = NewLocalRepo(repoRoot)

	res, err := svc.ImportFromLocalRepo("7", GAV{Group: "org.example", Artifact: "demo", Version: "1.0", Classifier: "tests"})
	if err != nil {
		t.Fatalf("导入失败: %v", err)
	}
	if res.JarRelPath != "deps/jars/org/example/demo/1.0/demo-1.0-tests.jar" {
		t.Errorf("JarRelPath = %q", res.JarRelPath)
	}
	if res.Sources {
		t.Error("带 classifier 的导入不应去找 sources")
	}
}

func TestImportFromLocalRepoErrors(t *testing.T) {
	dataDir := t.TempDir()

	// No repository configured.
	svc := NewService(dataDir, nil)
	if _, err := svc.ImportFromLocalRepo("1", GAV{Group: "a.b", Artifact: "c", Version: "1"}); !errors.Is(err, ErrNoLocalRepo) {
		t.Errorf("未配置仓库应返回 ErrNoLocalRepo，得到 %v", err)
	}
	if svc.LocalRepoEnabled() || svc.LocalRepoPath() != "" {
		t.Error("未配置仓库时 LocalRepoEnabled/Path 应为空")
	}

	// Configured, but the coordinate is absent.
	repoRoot := t.TempDir()
	writeFakeArtifact(t, repoRoot, "a/b/c/1/c-1.jar", "X")
	svc.LocalRepo = NewLocalRepo(repoRoot)
	if _, err := svc.ImportFromLocalRepo("1", GAV{Group: "a.b", Artifact: "nope", Version: "1"}); !errors.Is(err, ErrArtifactNotFound) {
		t.Errorf("仓库里没有的坐标应返回 ErrArtifactNotFound，得到 %v", err)
	}
	if !svc.LocalRepoEnabled() || svc.LocalRepoPath() == "" {
		t.Error("配置有效仓库后 LocalRepoEnabled 应当为 true")
	}
	// Nothing was written into the task for a failed import.
	if _, err := os.Stat(filepath.Join(dataDir, "tasks", "1", "deps", "jars")); !os.IsNotExist(err) {
		t.Error("失败的导入不应在任务目录里留下任何东西")
	}
}
