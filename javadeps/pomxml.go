package javadeps

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// =====================================================================
// 源码工程里的 pom.xml —— 回答「我该导入哪些坐标」
//
// 有了本地仓库之后，「配一次、全局可用」还剩最后一个缺口：用户不知道坐标列表。
// 上传的源码工程里本来就有 pom.xml，直接依赖（groupId/artifactId/version）就写在
// 里面，所以让后端读它一遍即可 —— 用户不需要在服务器上装 Maven。
//
// 这是**尽力而为**的解析，不是 Maven 实现。明确不做（做不到就如实标注，绝不猜）：
//   - 不解析 parent POM / BOM import（`<scope>import</scope>`）：拿不到就标记未解析；
//   - 不做 version range / profile 激活 / property 文件外部化；
//   - 不递归传递依赖（传递依赖由 agent 按需按坐标取，或用户补坐标）。
//
// 能做的：同文件内的 ${property} 插值、从 `<dependencyManagement>` 继承版本、
// 识别 test-jar 分类器、跳过 BOM import 与 system scope。
// =====================================================================

// PomDep is one <dependency> declaration read from a pom.xml.
type PomDep struct {
	Group      string
	Artifact   string
	Version    string
	Classifier string
	Scope      string
	Optional   bool

	// VersionRaw is the version exactly as written, which may be a property
	// reference ("${log4j.version}") that we could not resolve.
	VersionRaw string
	// Resolved is false when the version is missing or still holds a ${...}
	// reference. Such an entry is REPORTED to the user, never guessed at.
	Resolved bool
	// Source is the pom file the declaration came from (task-relative or absolute,
	// whichever the caller passed in).
	Source string
}

// Key is the group:artifact identity, used for de-duplication.
func (d PomDep) Key() string { return d.Group + ":" + d.Artifact }

// GAV converts the declaration to a coordinate when it is complete and safe.
func (d PomDep) GAV() (GAV, bool) {
	g := GAV{Group: d.Group, Artifact: d.Artifact, Version: d.Version, Classifier: d.Classifier}
	if err := g.Validate(); err != nil {
		return GAV{}, false
	}
	if g.Artifact == "" || g.Version == "" {
		return GAV{}, false
	}
	return g, true
}

// pomXML mirrors only the parts of a POM this package needs.
type pomXML struct {
	XMLName    xml.Name `xml:"project"`
	GroupID    string   `xml:"groupId"`
	ArtifactID string   `xml:"artifactId"`
	Version    string   `xml:"version"`
	Parent     struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
	} `xml:"parent"`
	Properties struct {
		Entries []struct {
			XMLName xml.Name
			Value   string `xml:",chardata"`
		} `xml:",any"`
	} `xml:"properties"`
	Dependencies struct {
		Dep []pomDepXML `xml:"dependency"`
	} `xml:"dependencies"`
	DependencyManagement struct {
		Dependencies struct {
			Dep []pomDepXML `xml:"dependency"`
		} `xml:"dependencies"`
	} `xml:"dependencyManagement"`
}

type pomDepXML struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Classifier string `xml:"classifier"`
	Scope      string `xml:"scope"`
	Type       string `xml:"type"`
	Optional   string `xml:"optional"`
}

var pomPropRefRe = regexp.MustCompile(`\$\{([^}]+)\}`)

// ParsePomDependencies extracts the dependency declarations of one pom.xml body.
//
// source is echoed into every result so a caller can tell the user *which* module a
// coordinate came from. Malformed XML is an error; the caller should log it and move
// on to the next pom rather than failing the whole import.
func ParsePomDependencies(data []byte, source string) ([]PomDep, error) {
	var p pomXML
	if err := xml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("解析 %s 失败: %w", filepath.Base(source), err)
	}
	props := pomProperties(&p)

	// Versions pinned in <dependencyManagement> are inherited by declarations that
	// omit <version> — the single most common reason a naive parser reports nothing.
	managed := map[string]string{}
	for _, d := range p.DependencyManagement.Dependencies.Dep {
		g, a := strings.TrimSpace(d.GroupID), strings.TrimSpace(d.ArtifactID)
		v := strings.TrimSpace(d.Version)
		if g == "" || a == "" || v == "" {
			continue
		}
		// A BOM import pins nothing by itself; we cannot see inside it.
		if strings.EqualFold(strings.TrimSpace(d.Scope), "import") {
			continue
		}
		if iv, ok := interpolate(v, props); ok {
			managed[g+":"+a] = iv
		}
	}

	out := make([]PomDep, 0, len(p.Dependencies.Dep))
	for _, d := range p.Dependencies.Dep {
		group := strings.TrimSpace(d.GroupID)
		artifact := strings.TrimSpace(d.ArtifactID)
		scope := strings.TrimSpace(d.Scope)
		typ := strings.TrimSpace(d.Type)

		// A BOM import and a system-scoped dep are not artifacts we can pull from a
		// repository by coordinate.
		if group == "" || artifact == "" {
			continue
		}
		if strings.EqualFold(scope, "import") || strings.EqualFold(scope, "system") {
			continue
		}
		if strings.EqualFold(typ, "pom") {
			continue
		}
		// Interpolate the identity too: some projects write ${project.groupId}.
		if ig, ok := interpolate(group, props); ok {
			group = ig
		} else {
			continue
		}
		if ia, ok := interpolate(artifact, props); ok {
			artifact = ia
		} else {
			continue
		}

		rawVersion := strings.TrimSpace(d.Version)
		version := rawVersion
		if version == "" {
			version = managed[group+":"+artifact]
		}
		resolved := false
		if version != "" {
			if iv, ok := interpolate(version, props); ok {
				version, resolved = iv, true
			} else {
				// Unresolved: drop the half-built version rather than hand downstream
				// code something that looks usable. VersionRaw keeps the original text
				// so the UI can show the user exactly what the pom said.
				version = ""
			}
		}

		classifier := strings.TrimSpace(d.Classifier)
		if classifier == "" && strings.EqualFold(typ, "test-jar") {
			classifier = "tests"
		}
		if classifier != "" {
			if ic, ok := interpolate(classifier, props); ok {
				classifier = ic
			} else {
				classifier = ""
			}
		}

		out = append(out, PomDep{
			Group:      group,
			Artifact:   artifact,
			Version:    version,
			Classifier: classifier,
			Scope:      scope,
			Optional:   strings.EqualFold(strings.TrimSpace(d.Optional), "true"),
			VersionRaw: rawVersion,
			Resolved:   resolved,
			Source:     source,
		})
	}
	return out, nil
}

// pomProperties builds the ${...} lookup table: the pom's own <properties> plus the
// implicit project.* / parent.* coordinates Maven always defines.
func pomProperties(p *pomXML) map[string]string {
	props := map[string]string{}
	for _, e := range p.Properties.Entries {
		name := strings.TrimSpace(e.XMLName.Local)
		if name == "" {
			continue
		}
		props[name] = strings.TrimSpace(e.Value)
	}
	group := strings.TrimSpace(p.GroupID)
	if group == "" {
		group = strings.TrimSpace(p.Parent.GroupID)
	}
	version := strings.TrimSpace(p.Version)
	if version == "" {
		version = strings.TrimSpace(p.Parent.Version)
	}
	artifact := strings.TrimSpace(p.ArtifactID)
	set := func(k, v string) {
		if v != "" {
			props[k] = v
		}
	}
	set("project.groupId", group)
	set("project.artifactId", artifact)
	set("project.version", version)
	set("pom.groupId", group)
	set("pom.artifactId", artifact)
	set("pom.version", version)
	set("groupId", group)
	set("artifactId", artifact)
	set("version", version)
	set("project.parent.groupId", strings.TrimSpace(p.Parent.GroupID))
	set("project.parent.artifactId", strings.TrimSpace(p.Parent.ArtifactID))
	set("project.parent.version", strings.TrimSpace(p.Parent.Version))
	set("parent.groupId", strings.TrimSpace(p.Parent.GroupID))
	set("parent.version", strings.TrimSpace(p.Parent.Version))
	return props
}

// interpolate resolves ${...} references against props, repeatedly so a property
// defined in terms of another still resolves. Returns ok=false when any reference
// is left unresolved — callers must treat that as "unknown", not as "empty".
func interpolate(s string, props map[string]string) (string, bool) {
	out := s
	for i := 0; i < 10; i++ {
		if !strings.Contains(out, "${") {
			break
		}
		replaced := false
		out = pomPropRefRe.ReplaceAllStringFunc(out, func(m string) string {
			key := strings.TrimSpace(m[2 : len(m)-1])
			if v, ok := props[key]; ok && v != "" {
				replaced = true
				return v
			}
			return m
		})
		if !replaced {
			break
		}
	}
	out = strings.TrimSpace(out)
	if out == "" || strings.Contains(out, "${") {
		return out, false
	}
	return out, true
}

// pomSkipDirs are directory names that never hold a project pom worth reading.
// Skipping them keeps the walk cheap on a source tree that carries build output.
var pomSkipDirs = map[string]bool{
	".git": true, ".svn": true, ".hg": true, ".idea": true, ".vscode": true,
	"node_modules": true, "target": true, "build": true, "out": true,
	"dist": true, "vendor": true, "__pycache__": true, ".gradle": true,
}

// FindPoms walks a PROJECT SOURCE tree and returns the pom.xml files in it, sorted
// for deterministic output.
//
// This walks source code, never a Maven repository — the "never walk the repository"
// invariant is about repositories, where a walk means hundreds of MB and thousands
// of irrelevant artifacts. A project tree is bounded by maxPoms and a depth cap so a
// hostile upload cannot make the server crawl.
func FindPoms(root string, maxPoms int) []string {
	if maxPoms <= 0 {
		maxPoms = 200
	}
	const maxDepth = 12
	var out []string
	rootDepth := strings.Count(filepath.ToSlash(filepath.Clean(root)), "/")
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // an unreadable subdirectory must not fail the scan
		}
		if len(out) >= maxPoms {
			return filepath.SkipAll
		}
		name := d.Name()
		if d.IsDir() {
			if p != root && pomSkipDirs[strings.ToLower(name)] {
				return filepath.SkipDir
			}
			if strings.Count(filepath.ToSlash(filepath.Clean(p)), "/")-rootDepth > maxDepth {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.EqualFold(name, "pom.xml") {
			out = append(out, p)
		}
		return nil
	})
	sort.Strings(out)
	return out
}
