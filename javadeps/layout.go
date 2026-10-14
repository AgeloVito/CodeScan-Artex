package javadeps

import (
	"path/filepath"
	"strings"
)

// On-disk layout of a task's dependency tree. Everything lives under the task
// directory, next to source/, so the existing agent file tools (Read/Grep/Glob/LS)
// reach it with a plain relative path — no virtual filesystem, no new capability:
//
//	data/tasks/<id>/deps/
//	  INDEX.md                      <- the agent reads this first
//	  manifest.json                 <- machine-readable mirror of the DB rows
//	  jars/...                      <- uploaded jars, original bytes
//	  index/classes.txt             <- one FQCN per line (cheap Grep target)
//	  src/<group>/<artifact>/<ver>/ <- .java, materialised ONLY on demand
//
// The global decompile cache is content-addressed and shared across tasks:
//
//	data/cache/deps/<sha256>/
const (
	// DepsDirName is the per-task dependency root (sibling of "source").
	DepsDirName = "deps"
	// JarsSubdir holds the uploaded jars exactly as they arrived.
	JarsSubdir = "jars"
	// SrcSubdir holds materialised sources (extracted or decompiled).
	SrcSubdir = "src"
	// IndexSubdir holds generated indexes.
	IndexSubdir = "index"
	// CacheDirName is the global, content-addressed decompile cache.
	CacheDirName = "cache"
)

// TaskDepsDir returns the absolute dependency root for one task.
func TaskDepsDir(dataDir, taskID string) string {
	return filepath.Join(dataDir, "tasks", taskID, DepsDirName)
}

// TaskJarsDir returns where uploaded jars are kept for one task.
func TaskJarsDir(dataDir, taskID string) string {
	return filepath.Join(TaskDepsDir(dataDir, taskID), JarsSubdir)
}

// TaskSrcDir returns where materialised sources live for one task.
func TaskSrcDir(dataDir, taskID string) string {
	return filepath.Join(TaskDepsDir(dataDir, taskID), SrcSubdir)
}

// TaskIndexPath returns the generated class index path for one task.
func TaskIndexPath(dataDir, taskID string) string {
	return filepath.Join(TaskDepsDir(dataDir, taskID), IndexSubdir, "classes.txt")
}

// TaskIndexMDPath returns the agent-facing index document path.
func TaskIndexMDPath(dataDir, taskID string) string {
	return filepath.Join(TaskDepsDir(dataDir, taskID), "INDEX.md")
}

// TaskManifestPath returns the machine-readable manifest path.
func TaskManifestPath(dataDir, taskID string) string {
	return filepath.Join(TaskDepsDir(dataDir, taskID), "manifest.json")
}

// CacheRoot returns the global decompile cache root.
func CacheRoot(dataDir string) string {
	return filepath.Join(dataDir, CacheDirName, DepsDirName)
}

// CacheEntryDir returns the cache directory for a jar hash.
func CacheEntryDir(dataDir, sha256 string) string {
	return filepath.Join(CacheRoot(dataDir), sha256)
}

// GroupPath converts a groupId to its directory form (dots become slashes). An
// empty group (flat repository) maps to "_" so the layout stays predictable.
func GroupPath(group string) string {
	g := strings.Trim(strings.TrimSpace(group), ".")
	if g == "" {
		return "_"
	}
	return strings.ReplaceAll(g, ".", "/")
}

// SourceRelPath is the task-relative directory where a coordinate's sources live,
// e.g. "deps/src/org/apache/logging/log4j/log4j-core/2.17.0".
func SourceRelPath(g GAV) string {
	segs := []string{DepsDirName, SrcSubdir}
	if gp := GroupPath(g.Group); gp != "" {
		segs = append(segs, filepath.FromSlash(gp))
	}
	segs = append(segs, g.Artifact, g.Version)
	return filepath.Join(segs...)
}

// SourceDir joins the task-relative source path onto the data dir.
func SourceDir(dataDir, taskID string, g GAV) string {
	return filepath.Join(dataDir, "tasks", taskID, SourceRelPath(g))
}

// JarRelPathFor returns the task-relative jar path we would store for a coordinate,
// used when a jar has to be located by coordinate rather than by its upload path.
func JarRelPathFor(g GAV) string {
	name := g.JarName()
	if g.Classifier != "" {
		name = g.ClassifierJarName(g.Classifier)
	}
	return filepath.Join(DepsDirName, JarsSubdir, GroupPath(g.Group), g.Artifact, g.Version, name)
}
