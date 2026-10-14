// Package javadeps implements the "read and decompile Java .m2 dependencies"
// pipeline described in docs/java-m2依赖读取与反编译方案.md.
//
// Invariants this package must keep (they are the whole point of the design):
//
//   - Nothing here ever touches the network. Fetching artifacts is the caller's job.
//   - Decompilation is ON DEMAND. Scanning a jar for its class index is cheap and
//     needs no JVM; turning a jar into .java files is expensive (tens of seconds per
//     jar) and only happens for a jar somebody explicitly asked for. Never
//     decompile a whole repository "just in case".
//   - Decompiled output is NOT the original source. Line numbers and local names
//     differ; callers must label it as such wherever it is shown or cited.
package javadeps

import (
	"errors"
	"fmt"
	"strings"
)

// GAV is a Maven coordinate: groupId:artifactId:version, plus an optional
// classifier (sources, javadoc, linux-x86_64, ...).
type GAV struct {
	Group      string
	Artifact   string
	Version    string
	Classifier string
}

// String renders the canonical "groupId:artifactId:version" form. The classifier
// is appended after a colon when present, matching the "group:artifact:version:classifier"
// shorthand people use in dependency declarations. A coordinate with no group (a
// flat-repository jar) renders as "artifact:version" rather than ":artifact:version".
func (g GAV) String() string {
	s := g.coordinate()
	if g.Classifier != "" {
		s += ":" + g.Classifier
	}
	return s
}

// Key is the identity used for caching and lookups: the coordinate without the
// classifier, because a sources/javadoc classifier is the same dependency.
func (g GAV) Key() string {
	return g.coordinate()
}

// coordinate renders group:artifact:version, omitting an empty group.
func (g GAV) coordinate() string {
	if strings.TrimSpace(g.Group) == "" {
		return g.Artifact + ":" + g.Version
	}
	return g.Group + ":" + g.Artifact + ":" + g.Version
}

// IsZero reports whether the coordinate carries no usable identity.
func (g GAV) IsZero() bool {
	return strings.TrimSpace(g.Artifact) == "" && strings.TrimSpace(g.Group) == ""
}

// Validate reports whether every component of the coordinate is safe to turn into
// filesystem path segments.
//
// This is a security boundary, not a formatting nicety. Coordinates reach this
// package from untrusted places — a jar's own META-INF/maven/**/pom.properties, a
// pasted pom.xml, an agent tool call — and every caller that builds a repository or
// task path out of one MUST validate first. A groupId of "../../etc" or a classifier
// of "x/../../y" would otherwise escape the directory the caller intended.
//
// Rules: no path separators, no NUL/control characters, no ":" (the coordinate
// separator itself), and no bare "." / ".." segment. Maven allows a lot of exotic
// characters inside a coordinate, so anything else is accepted.
func (g GAV) Validate() error {
	if err := validateSegment("groupId", g.Group, false); err != nil {
		return err
	}
	if err := validateSegment("artifactId", g.Artifact, true); err != nil {
		return err
	}
	if err := validateSegment("version", g.Version, true); err != nil {
		return err
	}
	return validateSegment("classifier", g.Classifier, false)
}

// validateSegment enforces the per-component rules described on Validate.
func validateSegment(name, v string, required bool) error {
	if v == "" {
		if required {
			return fmt.Errorf("坐标缺少 %s", name)
		}
		return nil
	}
	if strings.TrimSpace(v) != v {
		return fmt.Errorf("%s 首尾不能有空白: %q", name, v)
	}
	if v == "." || v == ".." {
		return fmt.Errorf("%s 不能是 %q", name, v)
	}
	if strings.ContainsAny(v, `/\:`) {
		return fmt.Errorf("%s 不能包含路径分隔符或冒号: %q", name, v)
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s 含有控制字符: %q", name, v)
		}
	}
	return nil
}

// ErrUnsafeGAV wraps a coordinate that failed Validate, so callers can tell "this
// coordinate would escape the repository/task directory" apart from "not found".
var ErrUnsafeGAV = errors.New("坐标包含不安全的路径字符")

// SafeValidate is Validate with the error wrapped in ErrUnsafeGAV.
func (g GAV) SafeValidate() error {
	if err := g.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrUnsafeGAV, err)
	}
	return nil
}

// RepoPath is the Maven repository layout path for this coordinate, using forward
// slashes: group dots become directories. Classifier is not part of the directory.
//
//	org.apache.logging.log4j:log4j-core:2.17.0 -> org/apache/logging/log4j/log4j-core/2.17.0
func (g GAV) RepoPath() string {
	group := strings.ReplaceAll(strings.Trim(g.Group, "."), ".", "/")
	return group + "/" + g.Artifact + "/" + g.Version
}

// JarName is the file name Maven uses for this coordinate's main artifact.
func (g GAV) JarName() string {
	return g.Artifact + "-" + g.Version + ".jar"
}

// ClassifierJarName is the file name for a classifier variant, e.g.
// log4j-core-2.17.0-sources.jar.
func (g GAV) ClassifierJarName(classifier string) string {
	if classifier == "" {
		return g.JarName()
	}
	return g.Artifact + "-" + g.Version + "-" + classifier + ".jar"
}

// ParseGAV parses "group:artifact:version" or "group:artifact:version:classifier".
// A 2-part "artifact:version" is accepted with an empty group (flat-repository jars
// carry no groupId).
func ParseGAV(s string) (GAV, error) {
	parts := strings.Split(strings.TrimSpace(s), ":")
	switch len(parts) {
	case 2:
		g := GAV{Artifact: strings.TrimSpace(parts[0]), Version: strings.TrimSpace(parts[1])}
		if g.Artifact == "" || g.Version == "" {
			return GAV{}, fmt.Errorf("坐标不完整: %q", s)
		}
		return g, nil
	case 3, 4:
		g := GAV{
			Group:    strings.TrimSpace(parts[0]),
			Artifact: strings.TrimSpace(parts[1]),
			Version:  strings.TrimSpace(parts[2]),
		}
		if len(parts) == 4 {
			g.Classifier = strings.TrimSpace(parts[3])
		}
		if g.Group == "" || g.Artifact == "" || g.Version == "" {
			return GAV{}, fmt.Errorf("坐标不完整: %q", s)
		}
		return g, nil
	default:
		return GAV{}, fmt.Errorf("无法解析 Maven 坐标（应为 group:artifact:version）: %q", s)
	}
}

// GAVFromRepoPath recovers a coordinate from a path inside a Maven repository
// layout. It expects .../<group as dirs>/<artifact>/<version>/<file>.jar and
// cross-checks the file name against artifact-version, so a stray file in a
// version directory does not produce a bogus coordinate.
//
// Returns ok=false when the path does not look like a repository layout; callers
// should then fall back to the jar's embedded pom.properties.
func GAVFromRepoPath(rel string) (GAV, bool) {
	p := strings.ReplaceAll(strings.TrimSpace(rel), "\\", "/")
	p = strings.Trim(p, "/")
	if p == "" {
		return GAV{}, false
	}
	segs := strings.Split(p, "/")
	// Need at least: group.../artifact/version/file.jar => 4 segments.
	if len(segs) < 4 {
		return GAV{}, false
	}
	file := segs[len(segs)-1]
	if !strings.HasSuffix(strings.ToLower(file), ".jar") {
		return GAV{}, false
	}
	version := segs[len(segs)-2]
	artifact := segs[len(segs)-3]
	groupDirs := segs[:len(segs)-3]
	if artifact == "" || version == "" || len(groupDirs) == 0 {
		return GAV{}, false
	}
	// Cross-check: the file must be <artifact>-<version>[-classifier].jar.
	base := strings.TrimSuffix(file, ".jar")
	base = strings.TrimSuffix(base, ".JAR")
	prefix := artifact + "-" + version
	if base != prefix && !strings.HasPrefix(base, prefix+"-") {
		return GAV{}, false
	}
	g := GAV{
		Group:    strings.Join(groupDirs, "."),
		Artifact: artifact,
		Version:  version,
	}
	if base != prefix {
		g.Classifier = strings.TrimPrefix(base, prefix+"-")
	}
	return g, true
}

// ParseJarFilename recovers a coordinate from a bare jar file name, for flat
// directories produced by `mvn dependency:copy-dependencies` (no group id, so
// Group stays empty).
//
// This is the LEAST reliable source and must only be used after trying the jar's
// embedded pom.properties and the repository path: Maven version strings may
// themselves contain dashes ("1.0-alpha-1"), which makes "artifactId-version"
// ambiguous from the file name alone. We split on the LAST dash followed by a
// digit, which is right for the common case and wrong for the rare one.
func ParseJarFilename(name string) (GAV, bool) {
	base := strings.TrimSpace(name)
	if i := strings.LastIndexAny(base, "/\\"); i >= 0 {
		base = base[i+1:]
	}
	if !strings.HasSuffix(strings.ToLower(base), ".jar") {
		return GAV{}, false
	}
	base = base[:len(base)-4]
	if base == "" {
		return GAV{}, false
	}
	cut := -1
	for i := len(base) - 1; i > 0; i-- {
		if base[i-1] != '-' {
			continue
		}
		if base[i] >= '0' && base[i] <= '9' {
			cut = i - 1
			break
		}
	}
	if cut <= 0 || cut >= len(base)-1 {
		return GAV{}, false
	}
	artifact := base[:cut]
	rest := base[cut+1:]
	version := rest
	classifier := ""
	if i := strings.IndexByte(rest, '-'); i > 0 {
		version = rest[:i]
		classifier = rest[i+1:]
	}
	if artifact == "" || version == "" {
		return GAV{}, false
	}
	return GAV{Artifact: artifact, Version: version, Classifier: classifier}, true
}

// IsSourcesClassifier reports whether a classifier denotes a sources artifact.
func IsSourcesClassifier(classifier string) bool {
	return strings.EqualFold(classifier, "sources")
}
