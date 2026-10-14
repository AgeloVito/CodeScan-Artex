package javadeps

import (
	"os"
	"path/filepath"
	"testing"
)

// A pom that exercises every branch the parser claims to handle: property
// interpolation, dependencyManagement inheritance, test-jar classifiers, a BOM
// import, a system scope, and a version we deliberately cannot resolve.
const samplePom = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.2.3</version>
  <properties>
    <log4j.version>2.17.0</log4j.version>
    <spring.version>5.3.20</spring.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-core</artifactId>
        <version>${spring.version}</version>
      </dependency>
      <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-dependencies</artifactId>
        <version>2.7.0</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>${log4j.version}</version>
    </dependency>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>app-tests</artifactId>
      <version>${project.version}</version>
      <type>test-jar</type>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>com.unknown</groupId>
      <artifactId>mystery</artifactId>
      <version>${external.version}</version>
    </dependency>
    <dependency>
      <groupId>com.sys</groupId>
      <artifactId>syslib</artifactId>
      <version>1.0</version>
      <scope>system</scope>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>optional-lib</artifactId>
      <version>1.0</version>
      <optional>true</optional>
    </dependency>
  </dependencies>
</project>`

func TestParsePomDependencies(t *testing.T) {
	deps, err := ParsePomDependencies([]byte(samplePom), "pom.xml")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	byKey := map[string]PomDep{}
	for _, d := range deps {
		byKey[d.Key()] = d
	}

	// system scope and BOM imports are not pullable artifacts.
	if len(deps) != 5 {
		t.Fatalf("期望 5 条依赖，得到 %d 条: %+v", len(deps), deps)
	}
	if _, ok := byKey["com.sys:syslib"]; ok {
		t.Error("system scope 的依赖不应被当成可导入坐标")
	}
	if _, ok := byKey["org.springframework.boot:spring-boot-dependencies"]; ok {
		t.Error("dependencyManagement 里的 BOM import 不应被当成依赖")
	}

	// ${property} interpolation.
	l4j, ok := byKey["org.apache.logging.log4j:log4j-core"]
	if !ok {
		t.Fatal("缺少 log4j-core")
	}
	if !l4j.Resolved || l4j.Version != "2.17.0" {
		t.Errorf("log4j-core 版本 = %q resolved=%v，期望 2.17.0/true", l4j.Version, l4j.Resolved)
	}
	if l4j.Source != "pom.xml" {
		t.Errorf("Source = %q", l4j.Source)
	}

	// Version inherited from <dependencyManagement>.
	spring, ok := byKey["org.springframework:spring-core"]
	if !ok {
		t.Fatal("缺少 spring-core")
	}
	if !spring.Resolved || spring.Version != "5.3.20" {
		t.Errorf("spring-core 版本 = %q resolved=%v，期望从 dependencyManagement 继承 5.3.20", spring.Version, spring.Resolved)
	}

	// test-jar type becomes the "tests" classifier, and ${project.version} resolves.
	tests, ok := byKey["com.example:app-tests"]
	if !ok {
		t.Fatal("缺少 app-tests")
	}
	if tests.Classifier != "tests" {
		t.Errorf("test-jar 的 classifier = %q，期望 tests", tests.Classifier)
	}
	if !tests.Resolved || tests.Version != "1.2.3" {
		t.Errorf("app-tests 版本 = %q resolved=%v，期望 1.2.3/true", tests.Version, tests.Resolved)
	}
	if tests.Scope != "test" {
		t.Errorf("app-tests scope = %q，期望 test", tests.Scope)
	}
	if g, ok := tests.GAV(); !ok || g.Classifier != "tests" {
		t.Errorf("app-tests 坐标 = %v, ok=%v", g, ok)
	}

	// An unresolvable version is REPORTED, never guessed.
	mystery, ok := byKey["com.unknown:mystery"]
	if !ok {
		t.Fatal("缺少 mystery")
	}
	if mystery.Resolved {
		t.Error("${external.version} 无法解析，Resolved 必须是 false")
	}
	if mystery.VersionRaw != "${external.version}" {
		t.Errorf("VersionRaw = %q，应当保留原文", mystery.VersionRaw)
	}
	if mystery.Version != "" {
		t.Errorf("未解析时 Version 应为空，得到 %q", mystery.Version)
	}
	if _, ok := mystery.GAV(); ok {
		t.Error("未解析的依赖不应产出可用坐标")
	}

	// <optional> is carried through.
	opt, ok := byKey["com.example:optional-lib"]
	if !ok {
		t.Fatal("缺少 optional-lib")
	}
	if !opt.Optional {
		t.Error("optional 标记没有解析出来")
	}
	if !opt.Resolved || opt.Version != "1.0" {
		t.Errorf("optional-lib 版本 = %q resolved=%v", opt.Version, opt.Resolved)
	}
}

func TestParsePomDependenciesParentInheritance(t *testing.T) {
	const withParent = `<?xml version="1.0"?>
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>9.9.9</version>
  </parent>
  <artifactId>child</artifactId>
  <dependencies>
    <dependency>
      <groupId>${project.groupId}</groupId>
      <artifactId>sibling</artifactId>
      <version>${project.version}</version>
    </dependency>
  </dependencies>
</project>`
	deps, err := ParsePomDependencies([]byte(withParent), "child/pom.xml")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("期望 1 条依赖，得到 %d", len(deps))
	}
	d := deps[0]
	if d.Group != "com.example" || d.Version != "9.9.9" {
		t.Errorf("parent 继承失败: group=%q version=%q", d.Group, d.Version)
	}
	if !d.Resolved {
		t.Error("应能从 parent 解析出坐标")
	}
}

func TestParsePomDependenciesMalformed(t *testing.T) {
	if _, err := ParsePomDependencies([]byte("<project><dependencies>"), "broken/pom.xml"); err == nil {
		t.Error("畸形 XML 应当报错，由调用方跳过该 pom")
	}
	// An empty but well-formed pom yields no dependencies and no error.
	deps, err := ParsePomDependencies([]byte(`<project><artifactId>a</artifactId></project>`), "empty/pom.xml")
	if err != nil {
		t.Fatalf("合法但无依赖的 pom 不应报错: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("期望 0 条依赖，得到 %d", len(deps))
	}
}

func TestFindPoms(t *testing.T) {
	root := t.TempDir()
	mk := func(rel string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("<project/>"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("pom.xml")
	mk("module-a/pom.xml")
	mk("module-a/target/pom.xml")  // build output: skipped
	mk("node_modules/pkg/pom.xml") // dependency tree: skipped
	mk("module-b/.git/pom.xml")    // VCS metadata: skipped
	mk("module-b/README.md")       // not a pom

	got := FindPoms(root, 50)
	if len(got) != 2 {
		t.Fatalf("期望 2 个 pom，得到 %d: %v", len(got), got)
	}
	// Sorted for deterministic output.
	if filepath.Base(filepath.Dir(got[0])) != "module-a" && filepath.Base(filepath.Dir(got[0])) != "." {
		t.Errorf("结果未按路径排序: %v", got)
	}

	// The cap is honoured (a hostile source tree must not make the server crawl).
	if capped := FindPoms(root, 1); len(capped) != 1 {
		t.Errorf("maxPoms=1 时应只返回 1 个，得到 %d", len(capped))
	}

	// A missing root is not an error, just nothing to scan.
	if poms := FindPoms(filepath.Join(root, "does-not-exist"), 10); len(poms) != 0 {
		t.Errorf("不存在的目录应返回空，得到 %v", poms)
	}
}
