package javadeps

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// =====================================================================
// 本地 Maven 仓库（~/.m2/repository）——「配一次、所有任务全局可用」
//
// 与上传路线的关系：上传是「用户把 jar 给我」，这里是「按坐标去本地仓库取」。
// 两条路线产出的东西完全一样（deps/jars 下的一个真实 jar），所以后续的清单、
// 类名索引、按需反编译全部原样复用。
//
// 三条不可退让的红线（照抄 docs/java-m2依赖读取与反编译方案.md §3.4/§5）：
//  1. **绝不遍历仓库**。一次查找只点名一个坐标，只 stat/打开该坐标映射到的那几个
//     文件。「把整个 .m2 导进来」在这个类型上根本表达不出来。
//  2. **只读**。源仓库一个字节都不写；取走的文件用硬链接（同盘）或拷贝。
//  3. **坐标不可信**。groupId/artifactId/version 可能来自 jar 内 pom.properties、
//     用户粘贴的 pom.xml 或 agent 调用，一律先过 GAV.SafeValidate 再拼路径，
//     拼完还要确认结果仍在仓库根之下（双保险）。
// =====================================================================

// ErrNoLocalRepo is returned when no local repository is configured (or the
// configured path is not a readable directory).
var ErrNoLocalRepo = errors.New("未配置本地 Maven 仓库（config.json 的 java.local_repo 或环境变量 ARTEX_JAVA_LOCAL_REPO）")

// ErrArtifactNotFound is returned when a coordinate is well-formed but the local
// repository does not hold that artifact. The wrapped message names the exact path
// that was looked for, because "我明明有这个 jar" is the single most common
// support question about this feature.
var ErrArtifactNotFound = errors.New("本地仓库中没有该坐标")

// LocalRepo is a read-only view of a local Maven repository directory.
//
// The zero value (and a nil *LocalRepo) means "disabled"; every method is
// nil-safe so callers never have to guard.
type LocalRepo struct {
	// root is the absolute, symlink-resolved repository directory. Empty = disabled.
	root string
}

// NewLocalRepo builds a repository view for dir. An empty dir, a missing path or a
// non-directory yields a disabled repo (Enabled() == false) instead of an error:
// the feature is optional, and a bad path must not break dependency *uploads*.
//
// Symlinks in the configured path are resolved once here, so a repository reached
// through a link (e.g. /root/.m2 -> /data/m2) still passes the containment check
// that every lookup performs.
func NewLocalRepo(dir string) *LocalRepo {
	d := strings.TrimSpace(dir)
	if d == "" {
		return &LocalRepo{}
	}
	abs, err := filepath.Abs(d)
	if err != nil {
		return &LocalRepo{}
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real
	}
	fi, err := os.Stat(abs)
	if err != nil || !fi.IsDir() {
		return &LocalRepo{}
	}
	return &LocalRepo{root: abs}
}

// Enabled reports whether a usable repository is configured.
func (r *LocalRepo) Enabled() bool { return r != nil && r.root != "" }

// Path returns the resolved repository root, or "" when disabled.
func (r *LocalRepo) Path() string {
	if r == nil {
		return ""
	}
	return r.root
}

// Dir returns the directory a coordinate lives in:
//
//	<root>/<groupId as directories>/<artifactId>/<version>
func (r *LocalRepo) Dir(g GAV) (string, error) {
	if !r.Enabled() {
		return "", ErrNoLocalRepo
	}
	if err := g.SafeValidate(); err != nil {
		return "", err
	}
	if strings.TrimSpace(g.Group) == "" {
		return "", fmt.Errorf("%w: 本地仓库按 groupId/artifactId/version 布局，坐标缺少 groupId: %q", ErrArtifactNotFound, g.String())
	}
	// GroupPath turns every "." into a separator, so it can never emit "..", and
	// SafeValidate already rejected real separators in the group.
	dir := filepath.Join(r.root, filepath.FromSlash(GroupPath(g.Group)), g.Artifact, g.Version)
	if err := r.ensureInside(dir); err != nil {
		return "", err
	}
	return dir, nil
}

// JarPath returns the expected on-disk path of a coordinate's main jar. The
// coordinate's own classifier is ignored: this is always the main artifact.
func (r *LocalRepo) JarPath(g GAV) (string, error) { return r.artifactPath(g, "") }

// SourcesJarPath returns the expected on-disk path of a coordinate's
// "-sources.jar". Finding one is the cheapest possible win: the original source,
// no JVM, and line numbers that match upstream.
func (r *LocalRepo) SourcesJarPath(g GAV) (string, error) {
	return r.artifactPath(g, ClassifierSources)
}

// artifactPath builds one artifact's path and re-checks containment.
func (r *LocalRepo) artifactPath(g GAV, classifier string) (string, error) {
	dir, err := r.Dir(g)
	if err != nil {
		return "", err
	}
	// Build the file name from a classifier-free coordinate: the variant we want is
	// named by `classifier`, not by whatever the caller happened to pass in.
	base := GAV{Group: g.Group, Artifact: g.Artifact, Version: g.Version}
	p := filepath.Join(dir, base.ClassifierJarName(classifier))
	if err := r.ensureInside(p); err != nil {
		return "", err
	}
	return p, nil
}

// Resolve returns the absolute path of the artifact a coordinate names, honouring
// its classifier (a plain coordinate resolves the main jar), or an error naming the
// path that was missing.
func (r *LocalRepo) Resolve(g GAV) (string, error) {
	return r.resolveArtifact(g, strings.TrimSpace(g.Classifier))
}

// ResolveSources returns the absolute path of a coordinate's "-sources.jar", or an
// error when the repository does not have one (the common case for a plain build).
func (r *LocalRepo) ResolveSources(g GAV) (string, error) {
	return r.resolveArtifact(g, ClassifierSources)
}

// HasSources reports whether a real sources jar exists for the coordinate.
func (r *LocalRepo) HasSources(g GAV) bool {
	_, err := r.ResolveSources(g)
	return err == nil
}

func (r *LocalRepo) resolveArtifact(g GAV, classifier string) (string, error) {
	p, err := r.artifactPath(g, classifier)
	if err != nil {
		return "", err
	}
	// Only a regular file counts: a directory that happens to carry the jar's name
	// (some tools leave empty dirs behind) must not be mistaken for an artifact.
	if fi, serr := os.Stat(p); serr != nil || !fi.Mode().IsRegular() {
		rel, rerr := filepath.Rel(r.root, p)
		if rerr != nil {
			rel = p
		}
		return "", fmt.Errorf("%w: %s（查找路径 %s）", ErrArtifactNotFound, g.String(), filepath.ToSlash(rel))
	}
	return p, nil
}

// ensureInside verifies that p is still under the repository root. Lexical check
// only, which is exactly right here: the root itself was already symlink-resolved,
// and no coordinate component may contain a separator.
func (r *LocalRepo) ensureInside(p string) error {
	rel, err := filepath.Rel(r.root, p)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnsafeGAV, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("%w: 解析出的路径逃出了本地仓库（%s）", ErrUnsafeGAV, filepath.ToSlash(p))
	}
	return nil
}

// ImportResult reports what pulling one coordinate out of the local repository did.
type ImportResult struct {
	GAV GAV
	// JarRelPath is the TASK-relative path of the main jar (deps/jars/...), i.e. the
	// same shape an uploaded jar has.
	JarRelPath string
	// SourcesRel is the task-relative path of an imported "-sources.jar", if any.
	SourcesRel string
	// Linked is false when the jar was already in the task (a previous import, or an
	// upload that happened to use the repository layout).
	Linked bool
	// Sources is true when a real "-sources.jar" came along: source is then readable
	// without ever running a decompiler.
	Sources bool
	Bytes   int64
}

// ImportFromLocalRepo makes ONE coordinate available inside a task by taking the
// jar — and its "-sources.jar", when present — out of the configured local Maven
// repository and placing it in the task's own deps/jars tree, in Maven repository
// layout so the coordinate can be recovered from the path.
//
// This is the "configure once, every task benefits" path: no upload, no network, no
// decompilation. The caller then treats the jar exactly like an uploaded one —
// scan for the class index, and decompile only when somebody names it.
//
// The source repository is never modified: the file is hardlinked when the
// filesystem allows it (same volume, zero extra bytes) and copied otherwise.
func (s *Service) ImportFromLocalRepo(taskID string, g GAV) (ImportResult, error) {
	res := ImportResult{GAV: g}
	if s.LocalRepo == nil || !s.LocalRepo.Enabled() {
		return res, ErrNoLocalRepo
	}
	g = GAV{
		Group:      strings.TrimSpace(g.Group),
		Artifact:   strings.TrimSpace(g.Artifact),
		Version:    strings.TrimSpace(g.Version),
		Classifier: strings.TrimSpace(g.Classifier),
	}
	res.GAV = g

	srcJar, err := s.LocalRepo.Resolve(g)
	if err != nil {
		return res, err
	}

	rel := JarRelPathFor(g)
	destAbs := filepath.Join(s.DataDir, "tasks", taskID, filepath.FromSlash(rel))
	res.JarRelPath = filepath.ToSlash(rel)
	linked, bytes, err := linkOrCopyFile(srcJar, destAbs)
	if err != nil {
		return res, err
	}
	res.Linked, res.Bytes = linked, bytes

	// A real sources jar rides along for free and makes the dependency readable
	// without a JVM. sourcesJarPath() looks next to the main jar, so this is all it
	// takes for the L1 path to kick in later. Only the main artifact has a
	// meaningful "-sources.jar"; asking for one next to a "tests" classifier is
	// pointless, so skip the stat entirely in that case.
	if strings.TrimSpace(g.Classifier) == "" {
		if src, serr := s.LocalRepo.ResolveSources(g); serr == nil {
			srcRel := JarRelPathFor(GAV{Group: g.Group, Artifact: g.Artifact, Version: g.Version, Classifier: ClassifierSources})
			srcDest := filepath.Join(s.DataDir, "tasks", taskID, filepath.FromSlash(srcRel))
			if _, _, lerr := linkOrCopyFile(src, srcDest); lerr != nil {
				s.logf("[javadeps] 导入 sources jar 失败（忽略，仍可反编译）: %v", lerr)
			} else {
				res.SourcesRel = filepath.ToSlash(srcRel)
				res.Sources = true
			}
		}
	}
	return res, nil
}

// linkOrCopyFile hardlinks src at dst, falling back to a copy (cross-volume, or a
// filesystem without hardlinks). Returns linked=false when dst already existed as a
// regular file, so a repeat import is a no-op rather than a duplicate.
func linkOrCopyFile(src, dst string) (linked bool, bytes int64, err error) {
	if fi, serr := os.Stat(src); serr != nil || !fi.Mode().IsRegular() {
		return false, 0, fmt.Errorf("源文件不是普通文件: %s", filepath.ToSlash(src))
	}
	if fi, derr := os.Stat(dst); derr == nil && fi.Mode().IsRegular() {
		return false, fi.Size(), nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return false, 0, err
	}
	_ = os.Remove(dst) // a stale non-regular entry must not block the import
	if err := os.Link(src, dst); err == nil {
		fi, _ := os.Stat(dst)
		if fi != nil {
			return true, fi.Size(), nil
		}
		return true, 0, nil
	}
	in, err := os.Open(src)
	if err != nil {
		return false, 0, err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return false, 0, err
	}
	n, err := io.Copy(out, in)
	if err != nil {
		_ = out.Close()
		return false, n, err
	}
	if err := out.Close(); err != nil {
		return false, n, err
	}
	return true, n, nil
}
