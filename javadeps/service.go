package javadeps

import (
	"os"
	"path/filepath"
)

// Service is the entry point the server uses: it owns the data-dir layout and the
// configured decompiler, and exposes exactly two operations.
//
//   - Ingest: cheap. Scan every uploaded jar (zip central directory only), producing
//     identity + class index. NEVER decompiles. This is what runs when a task is
//     created or a dependency pack is uploaded.
//   - Materialize: expensive, and only for one explicitly named dependency. This is
//     what runs when a human, the planner, or an agent asks to read a specific jar.
//
// Keeping those two apart is the core cost decision of the whole feature: the
// default path costs a zip read per jar, and a decompiler only ever runs on demand.
type Service struct {
	// DataDir is the artex data root (the directory holding tasks/ and cache/).
	DataDir string
	// Decompiler is optional; when it has no usable engine, Materialize degrades to
	// extracting real sources jars and reports ErrNoDecompiler otherwise.
	Decompiler *Decompiler
	// LocalRepo is optional. When enabled, a task can pull a jar BY COORDINATE from a
	// local Maven repository instead of requiring an upload — the "configure once,
	// every task benefits" path. Importing is still per-coordinate and on demand;
	// the repository is never walked. nil means upload-only.
	LocalRepo *LocalRepo
	// Logf receives one line per notable operation (server log; never agent-visible).
	Logf func(format string, args ...any)
}

// NewService builds a service rooted at dataDir.
func NewService(dataDir string, d *Decompiler) *Service {
	if d == nil {
		d = &Decompiler{}
	}
	return &Service{DataDir: dataDir, Decompiler: d}
}

func (s *Service) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// tmpRoot is where per-run scratch directories are created. It stays under the data
// root so the decompiler's output never lands outside the platform's own tree, and
// so a rename/link into place stays on one filesystem.
func (s *Service) tmpRoot() string {
	dir := filepath.Join(s.DataDir, "tmp")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return os.TempDir()
	}
	return dir
}

// Engine describes the active decompilation capability, for logs and the UI.
func (s *Service) Engine() string {
	if s.Decompiler == nil {
		return "none"
	}
	return s.Decompiler.Describe()
}

// LocalRepoPath returns the configured local Maven repository path, or "" when the
// feature is off. The UI shows it so "why can't I import" is answerable at a glance.
func (s *Service) LocalRepoPath() string {
	if s.LocalRepo == nil {
		return ""
	}
	return s.LocalRepo.Path()
}

// LocalRepoEnabled reports whether on-demand import from a local repository works.
func (s *Service) LocalRepoEnabled() bool {
	return s.LocalRepo != nil && s.LocalRepo.Enabled()
}

// Ingest scans every jar under the task's deps/jars directory. It is deliberately
// dumb and total: no JVM, no network, one zip central-directory read per jar.
//
// Returns the per-jar info in deterministic order. Individual unreadable jars are
// reported with Corrupt=true instead of failing the ingest.
func (s *Service) Ingest(taskID string) ([]JarInfo, error) {
	root := TaskJarsDir(s.DataDir, taskID)
	rels, err := ListJars(root)
	if err != nil {
		return nil, err
	}
	out := make([]JarInfo, 0, len(rels))
	for _, rel := range rels {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		// RelPath is TASK-relative (it includes the "deps/" prefix) so it matches
		// SourceRelPath and can be shown to the agent / stored in the DB verbatim.
		info, err := ScanJar(abs, filepath.ToSlash(filepath.Join(DepsDirName, JarsSubdir, rel)))
		if err != nil {
			// Only a hard I/O error reaches here (hash/stat); skip the jar, keep going.
			s.logf("[javadeps] 跳过 %s: %v", rel, err)
			continue
		}
		out = append(out, info)
	}
	return out, nil
}

// ClassIndexFor builds the per-coordinate class lists used by WriteClassIndex.
func ClassIndexFor(infos []JarInfo) map[string][]string {
	m := make(map[string][]string, len(infos))
	for _, in := range infos {
		if in.IsSources || len(in.Classes) == 0 {
			continue
		}
		key := in.GAV.Key()
		m[key] = append(m[key], in.Classes...)
	}
	return m
}

// EnsureDirs creates the task's dependency directory skeleton.
func (s *Service) EnsureDirs(taskID string) error {
	for _, d := range []string{
		TaskJarsDir(s.DataDir, taskID),
		TaskSrcDir(s.DataDir, taskID),
		filepath.Join(TaskDepsDir(s.DataDir, taskID), IndexSubdir),
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	return nil
}
