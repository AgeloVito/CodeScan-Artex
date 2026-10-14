package javadeps

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// MaterializeResult reports what turning one dependency into readable source cost.
type MaterializeResult struct {
	GAV         GAV
	State       SourceState
	RelPath     string // task-relative directory holding the .java files
	AbsPath     string
	Files       int
	Bytes       int64
	FromCache   bool
	Decompiler  string
	Duration    time.Duration
	Attempts    []string
}

// MaxExtractedBytes caps what a single sources jar may expand to (zip-bomb guard).
// Kept far below the upload limits because a sources jar is normally a few MB.
const MaxExtractedBytes = 2 << 30 // 2 GiB

// maxExtractedFiles caps the file count of one sources jar.
const maxExtractedFiles = 200000

// Materialize turns one dependency into readable source under the task's deps/src,
// using the cheapest method that works:
//
//  1. If a real "-sources.jar" for this coordinate was uploaded, extract it. This is
//     the original source, needs no JVM, and is always preferred.
//  2. Otherwise decompile the main jar with the configured decompiler.
//
// The expensive step is cached by the jar's sha256, so the same artifact is
// decompiled once across all tasks; the task gets a hardlink (or copy) of the tree.
//
// Callers MUST pass the jar of the dependency being materialised; this function
// never walks a repository and never decompiles anything that was not named.
func (s *Service) Materialize(ctx context.Context, taskID string, dep DepView) (MaterializeResult, error) {
	var res MaterializeResult
	res.GAV = dep.GAV
	destAbs := SourceDir(s.DataDir, taskID, dep.GAV)
	res.AbsPath = destAbs
	res.RelPath = SourceRelPath(dep.GAV)

	// Already materialised (e.g. a previous request): reuse it, don't redo the work.
	if files, bytes, ok := countJavaAt(destAbs); ok {
		res.State = SourceDecompiled
		if dep.SourceState == SourceOriginal {
			res.State = SourceOriginal
		}
		res.Files, res.Bytes, res.FromCache = files, bytes, true
		return res, nil
	}

	// --- L1: a real sources jar wins, and costs nothing but a zip extraction. ---
	if srcJar := dep.sourcesJarPath(s.DataDir, taskID); srcJar != "" {
		if files, bytes, err := ExtractJavaSources(srcJar, destAbs); err == nil && files > 0 {
			res.State = SourceOriginal
			res.Files, res.Bytes, res.Decompiler = files, bytes, string(EngineSources)
			return res, nil
		}
	}

	// --- L2: decompile exactly this one jar. ---
	if dep.NativeHeavy {
		return res, fmt.Errorf("该依赖没有 class 文件（本地库/平台包），无需反编译")
	}
	if dep.Corrupt {
		return res, fmt.Errorf("该依赖不是合法的 jar（无法反编译）")
	}
	jarAbs := filepath.Join(s.DataDir, "tasks", taskID, filepath.FromSlash(dep.JarRelPath))
	if _, err := os.Stat(jarAbs); err != nil {
		return res, fmt.Errorf("jar 文件不存在: %s", dep.JarRelPath)
	}
	eng := s.Decompiler.PickEngine()
	if eng == EngineNone {
		return res, ErrNoDecompiler
	}

	// Content-addressed cache: the same artifact is decompiled once for all tasks.
	cacheDir := CacheEntryDir(s.DataDir, dep.SHA256)
	if files, bytes, ok := countJavaAt(cacheDir); ok {
		if err := linkOrCopyTree(cacheDir, destAbs); err != nil {
			return res, err
		}
		res.State = SourceDecompiled
		res.Files, res.Bytes, res.FromCache, res.Decompiler = files, bytes, true, string(eng)
		return res, nil
	}

	start := time.Now()
	tmpDir, err := os.MkdirTemp(s.tmpRoot(), "decompile-*")
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(tmpDir)

	outDir := filepath.Join(tmpDir, "out")
	dr, err := s.Decompiler.Decompile(ctx, jarAbs, outDir)
	res.Attempts = dr.Attempts
	if err != nil {
		return res, err
	}

	// Publish to the cache, then hand the task its own tree.
	if err := os.MkdirAll(filepath.Dir(cacheDir), 0o755); err == nil {
		_ = os.RemoveAll(cacheDir)
		if err := linkOrCopyTree(outDir, cacheDir); err != nil {
			s.logf("[javadeps] 写入缓存失败（忽略）: %v", err)
		}
	}
	if err := linkOrCopyTree(outDir, destAbs); err != nil {
		return res, err
	}
	res.State = SourceDecompiled
	res.Files, res.Bytes, res.Decompiler = dr.Files, dr.Bytes, string(dr.Engine)
	res.Duration = time.Since(start)
	return res, nil
}

// sourcesJarPath returns the on-disk path of a real "-sources.jar" for this
// coordinate if one was uploaded, else "".
func (dep DepView) sourcesJarPath(dataDir, taskID string) string {
	if dep.IsSources {
		return "" // this IS a sources jar; handled by the main path
	}
	g := dep.GAV
	g.Classifier = ""
	name := g.ClassifierJarName(ClassifierSources)
	// Look next to the main jar first (both repository layout and flat layout).
	jarAbs := filepath.Join(dataDir, "tasks", taskID, filepath.FromSlash(dep.JarRelPath))
	cand := filepath.Join(filepath.Dir(jarAbs), name)
	if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
		return cand
	}
	// Repository layout with the group path we would have stored.
	cand2 := filepath.Join(dataDir, "tasks", taskID, JarRelPathFor(GAV{Group: g.Group, Artifact: g.Artifact, Version: g.Version, Classifier: ClassifierSources}))
	if fi, err := os.Stat(cand2); err == nil && !fi.IsDir() {
		return cand2
	}
	return ""
}

// ExtractJavaSources unzips a "-sources.jar" into destDir, keeping only .java (and
// the handful of resource files an agent may want to see), and refusing path
// traversal and zip bombs. Returns the .java file count and their total size.
//
// A sources jar is a plain zip of the original sources: no JVM, no decompiler, and
// the resulting line numbers match upstream exactly.
func ExtractJavaSources(srcJar, destDir string) (int, int64, error) {
	zr, err := zip.OpenReader(srcJar)
	if err != nil {
		return 0, 0, fmt.Errorf("sources jar 不是合法 zip: %w", err)
	}
	defer zr.Close()
	if len(zr.File) > maxExtractedFiles {
		return 0, 0, fmt.Errorf("sources jar 内文件数超过 %d", maxExtractedFiles)
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return 0, 0, err
	}
	var files int
	var bytes int64
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if f.Mode()&os.ModeSymlink != 0 || f.Mode()&os.ModeDevice != 0 || f.Mode()&os.ModeNamedPipe != 0 {
			continue
		}
		rel, ok := safeZipEntry(f.Name)
		if !ok {
			continue
		}
		// Keep Java sources plus small metadata; skip the rest (images, huge resources).
		lower := strings.ToLower(rel)
		if !strings.HasSuffix(lower, ".java") && !strings.HasSuffix(lower, ".kt") &&
			!strings.HasSuffix(lower, ".properties") && !strings.HasSuffix(lower, ".xml") &&
			!strings.HasSuffix(lower, ".md") {
			continue
		}
		if bytes+int64(f.UncompressedSize64) > MaxExtractedBytes {
			return files, bytes, fmt.Errorf("sources jar 解压后超过上限（%d GiB）", MaxExtractedBytes>>30)
		}
		target := filepath.Join(destDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return files, bytes, err
		}
		rc, err := f.Open()
		if err != nil {
			return files, bytes, err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			_ = rc.Close()
			return files, bytes, err
		}
		n, err := io.Copy(out, io.LimitReader(rc, MaxExtractedBytes))
		_ = rc.Close()
		closeErr := out.Close()
		if err != nil {
			return files, bytes, err
		}
		if closeErr != nil {
			return files, bytes, closeErr
		}
		if strings.HasSuffix(lower, ".java") {
			files++
			bytes += n
		}
	}
	return files, bytes, nil
}

// safeZipEntry normalises an archive entry name and rejects anything that would
// escape destDir. Same rules as the source-upload path (server.safeZipPath).
func safeZipEntry(name string) (string, bool) {
	name = strings.ReplaceAll(name, "\\", "/")
	name = strings.TrimPrefix(name, "./")
	if name == "" || strings.ContainsRune(name, 0) {
		return "", false
	}
	if strings.HasPrefix(name, "/") || filepath.IsAbs(name) {
		return "", false
	}
	if len(name) >= 2 && name[1] == ':' {
		return "", false
	}
	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}
	return clean, true
}

// countJavaAt reports the .java file count/size under dir when the directory
// already holds a materialised tree.
func countJavaAt(dir string) (int, int64, bool) {
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return 0, 0, false
	}
	files, bytes := countJava(dir)
	if files == 0 {
		return 0, 0, false
	}
	return files, bytes, true
}

// linkOrCopyTree reproduces src at dst, hardlinking files when the filesystem
// allows it (the common case: same data root) and copying otherwise. Hardlinks keep
// the per-task tree cheap while the content-addressed cache stays authoritative.
func linkOrCopyTree(src, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		_ = os.Remove(target)
		if err := os.Link(p, target); err == nil {
			return nil
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			_ = out.Close()
			return err
		}
		return out.Close()
	})
}

// RemoveTaskDeps drops a task's whole dependency tree (task deletion / re-upload).
func RemoveTaskDeps(dataDir, taskID string) error {
	return os.RemoveAll(TaskDepsDir(dataDir, taskID))
}

// ListJars walks an ingest root and returns every jar's path relative to that root,
// sorted, so ingest order is deterministic.
func ListJars(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable subdirectory must not fail the whole ingest
		}
		if d.IsDir() {
			return nil
		}
		if !ValidateJarName(d.Name()) {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return nil
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}
