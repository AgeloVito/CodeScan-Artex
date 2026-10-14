package javadeps

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path"
	"sort"
	"strings"
)

// ClassifierSources is the Maven classifier of a sources artifact.
const ClassifierSources = "sources"

// GAVSource records where a coordinate came from, so callers can tell an exact
// coordinate from a guessed one. Ordering of trust: pom.properties > repo path >
// file name.
type GAVSource string

const (
	GAVSrcPom      GAVSource = "pom.properties"
	GAVSrcRepoPath GAVSource = "repository-path"
	GAVSrcFilename GAVSource = "filename"
)

// Trusted reports whether the coordinate is authoritative enough to be used for
// vulnerability lookups without a human double-check.
func (s GAVSource) Trusted() bool {
	return s == GAVSrcPom || s == GAVSrcRepoPath
}

// JarInfo is what a cheap scan of a jar can tell us WITHOUT a JVM: identity,
// hashes, and the class index. This is the L1 tier of the design — it costs a zip
// central-directory read, never a decompilation.
type JarInfo struct {
	GAV       GAV
	GAVSource GAVSource
	// Path is the absolute path on disk; RelPath is relative to the ingest root.
	Path    string
	RelPath string
	Size    int64
	SHA256  string

	// Classes holds fully-qualified class names (dots, no ".class"). Multi-release
	// duplicates (META-INF/versions/N/...) are excluded from the index but counted
	// in MultiReleaseEntries.
	Classes      []string
	ClassCount   int
	PackageCount int

	// IsSources marks a "-sources.jar": its entries are .java, and it is used
	// directly instead of decompiling the main jar.
	IsSources bool
	// MultiReleaseEntries counts META-INF/versions/... entries (multi-release jar).
	MultiReleaseEntries int
	// HasPomProperties marks that the authoritative coordinate came from inside the jar.
	HasPomProperties bool
	// Corrupt is set when the file is not a readable zip (skipped, not fatal).
	Corrupt bool
	// Err carries the reason when Corrupt is true.
	Err string
}

// IsNativeHeavy reports whether the jar looks like a native/platform bundle with
// almost no JVM bytecode (e.g. rocksdbjni, netty natives). Decompiling those wastes
// a JVM start for nothing, so callers should surface them as "no source".
func (j JarInfo) IsNativeHeavy() bool {
	return !j.IsSources && j.ClassCount == 0
}

// TopPackages returns up to n most common package prefixes, for the index and for
// the UI's "what is this jar" hint.
func (j JarInfo) TopPackages(n int) []string {
	counts := map[string]int{}
	for _, c := range j.Classes {
		if i := strings.LastIndexByte(c, '.'); i > 0 {
			counts[c[:i]]++
		}
	}
	type kv struct {
		k string
		v int
	}
	all := make([]kv, 0, len(counts))
	for k, v := range counts {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].v != all[j].v {
			return all[i].v > all[j].v
		}
		return all[i].k < all[j].k
	})
	out := make([]string, 0, n)
	for i := 0; i < len(all) && i < n; i++ {
		out = append(out, all[i].k)
	}
	return out
}

// ScanJar reads a jar's central directory and returns its identity + class index.
// No JVM, no decompilation, no network: safe to run over every uploaded jar.
//
// A file that is not a readable zip is reported as Corrupt rather than as an error,
// because one bad jar in a dependency set must not fail the whole ingest.
func ScanJar(absPath, relPath string) (JarInfo, error) {
	info := JarInfo{Path: absPath, RelPath: relPath}
	sum, size, err := hashFile(absPath)
	if err != nil {
		return info, err
	}
	info.SHA256, info.Size = sum, size

	zr, err := zip.OpenReader(absPath)
	if err != nil {
		info.Corrupt = true
		info.Err = err.Error()
		info.GAV, info.GAVSource = fallbackGAV(relPath)
		info.IsSources = IsSourcesClassifier(info.GAV.Classifier)
		return info, nil
	}
	defer zr.Close()

	pkgs := map[string]bool{}
	var classes []string
	var pomProps string
	for _, f := range zr.File {
		name := strings.ReplaceAll(f.Name, "\\", "/")
		if strings.HasSuffix(name, ".class") {
			if strings.HasPrefix(name, "META-INF/versions/") {
				info.MultiReleaseEntries++
				continue
			}
			if strings.HasSuffix(name, "module-info.class") || strings.HasSuffix(name, "package-info.class") {
				continue
			}
			cls := strings.TrimSuffix(name, ".class")
			cls = strings.ReplaceAll(cls, "/", ".")
			classes = append(classes, cls)
			if i := strings.LastIndexByte(cls, '.'); i > 0 {
				pkgs[cls[:i]] = true
			}
			continue
		}
		if pomProps == "" && strings.HasPrefix(name, "META-INF/maven/") && strings.HasSuffix(name, "/pom.properties") {
			if rc, err := f.Open(); err == nil {
				b, _ := io.ReadAll(io.LimitReader(rc, 64<<10))
				_ = rc.Close()
				pomProps = string(b)
			}
		}
	}
	sort.Strings(classes)
	info.Classes = classes
	info.ClassCount = len(classes)
	info.PackageCount = len(pkgs)

	// Identity: pom.properties is authoritative; the repository path is next; the
	// bare file name is a last resort.
	if g, ok := parsePomProperties(pomProps); ok {
		info.GAV, info.GAVSource, info.HasPomProperties = g, GAVSrcPom, true
	} else {
		info.GAV, info.GAVSource = fallbackGAV(relPath)
	}
	info.IsSources = IsSourcesClassifier(info.GAV.Classifier)
	return info, nil
}

// fallbackGAV derives a coordinate from the repository-relative path, then from the
// bare file name.
func fallbackGAV(relPath string) (GAV, GAVSource) {
	if g, ok := GAVFromRepoPath(relPath); ok {
		return g, GAVSrcRepoPath
	}
	if g, ok := ParseJarFilename(path.Base(relPath)); ok {
		return g, GAVSrcFilename
	}
	return GAV{}, GAVSrcFilename
}

// parsePomProperties extracts groupId/artifactId/version from a Maven
// pom.properties body (a java.util.Properties file with "key=value" lines).
func parsePomProperties(body string) (GAV, bool) {
	if strings.TrimSpace(body) == "" {
		return GAV{}, false
	}
	var g GAV
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		i := strings.IndexByte(line, '=')
		if i <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:i])
		val := strings.TrimSpace(line[i+1:])
		switch key {
		case "groupId":
			g.Group = val
		case "artifactId":
			g.Artifact = val
		case "version":
			g.Version = val
		case "classifier":
			g.Classifier = val
		}
	}
	if g.Artifact == "" || g.Version == "" {
		return GAV{}, false
	}
	return g, true
}

// hashFile returns the hex sha256 and size of a file. The hash is the cache key
// for decompiled output, so identical jars across tasks are decompiled once.
func hashFile(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// SourcesJarFor reports the expected file name of the sources jar for a coordinate.
func SourcesJarFor(g GAV) string {
	return g.ClassifierJarName(ClassifierSources)
}

// ValidateJarName reports whether name looks like a jar we should ingest.
func ValidateJarName(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".jar")
}
