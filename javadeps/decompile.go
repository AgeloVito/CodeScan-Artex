package javadeps

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Engine identifies a decompiler backend.
type Engine string

const (
	EngineNone       Engine = "none"
	EngineVineflower Engine = "vineflower"
	EngineCFR        Engine = "cfr"
	// EngineSources is not a decompiler: it means the source came from a real
	// "-sources.jar" and is byte-for-byte the original.
	EngineSources Engine = "sources"
)

// DefaultTimeout is deliberately generous: CFR is single-threaded and a large jar
// can take a minute. Measured reference: log4j-core 2.17.0 (1.7 MB, 644 classes)
// took ~57 s with CFR on a JRE 11. This is exactly why decompilation is on demand.
const DefaultTimeout = 180 * time.Second

// DefaultMaxHeap caps the decompiler JVM so a hostile jar cannot eat the host.
const DefaultMaxHeap = "2g"

// Decompiler runs a headless decompiler JAR as a subprocess.
//
// Safety posture (mirrors how the platform already shells out to ripgrep):
//   - subprocess only: classes are never loaded in-process;
//   - hard timeout + heap cap;
//   - output goes to a caller-provided directory under the data root;
//   - nothing here opens a network connection. The decompilers are pure local
//     bytecode parsers, and we pass no network-related flags.
type Decompiler struct {
	// JavaPath is the java executable; empty means "not found" (no decompilation).
	JavaPath string
	// VineflowerJar / CFRJar are optional; at least one is needed to decompile.
	VineflowerJar string
	CFRJar        string
	Timeout       time.Duration
	MaxHeap       string
	// Logf, if set, receives one line per attempt (never agent-visible).
	Logf func(format string, args ...any)

	javaMajor int // cached major version; 0 = unknown/not probed
	probed    bool
}

func (d *Decompiler) logf(format string, args ...any) {
	if d.Logf != nil {
		d.Logf(format, args...)
	}
}

func (d *Decompiler) timeout() time.Duration {
	return d.TimeoutOr(DefaultTimeout)
}

// TimeoutOr returns the effective per-jar decompilation timeout, falling back to
// def when none was configured.
func (d *Decompiler) TimeoutOr(def time.Duration) time.Duration {
	if d.Timeout > 0 {
		return d.Timeout
	}
	return def
}

func (d *Decompiler) heap() string {
	if strings.TrimSpace(d.MaxHeap) != "" {
		return d.MaxHeap
	}
	return DefaultMaxHeap
}

// JavaMajor returns the detected java major version (e.g. 11, 17), or 0 when java
// is unavailable. Cached after the first probe.
func (d *Decompiler) JavaMajor() int {
	if d.probed {
		return d.javaMajor
	}
	d.probed = true
	if strings.TrimSpace(d.JavaPath) == "" {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, d.JavaPath, "-version")
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return 0
	}
	d.javaMajor = parseJavaMajor(string(out))
	return d.javaMajor
}

var javaVersionRe = regexp.MustCompile(`version\s+"([^"]+)"`)

// parseJavaMajor extracts the major version from `java -version` output:
// `openjdk version "11.0.10"` -> 11, `java version "1.8.0_292"` -> 8.
func parseJavaMajor(out string) int {
	m := javaVersionRe.FindStringSubmatch(out)
	if len(m) < 2 {
		return 0
	}
	v := m[1]
	parts := strings.Split(v, ".")
	if len(parts) == 0 {
		return 0
	}
	first, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0
	}
	if first == 1 && len(parts) > 1 { // 1.8.0_292 style
		if second, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
			return second
		}
	}
	return first
}

// PickEngine decides which decompiler to use, honouring the JRE floor: Vineflower
// 1.11+ requires JRE 17, CFR runs on JRE 6+. Returns EngineNone when nothing usable
// is configured — callers must degrade gracefully (index only), never fail the task.
func (d *Decompiler) PickEngine() Engine {
	if strings.TrimSpace(d.JavaPath) == "" {
		return EngineNone
	}
	major := d.JavaMajor()
	if major == 0 {
		return EngineNone
	}
	if d.VineflowerJar != "" && major >= 17 {
		return EngineVineflower
	}
	if d.CFRJar != "" && major >= 6 {
		return EngineCFR
	}
	// Vineflower present but JRE too old, and no CFR: nothing usable.
	return EngineNone
}

// Describe renders the current capability for logs and for the UI ("which level is
// active"), e.g. "cfr (java 11)" or "none (未找到 java)".
func (d *Decompiler) Describe() string {
	switch e := d.PickEngine(); e {
	case EngineVineflower, EngineCFR:
		return fmt.Sprintf("%s (java %d)", e, d.JavaMajor())
	default:
		if strings.TrimSpace(d.JavaPath) == "" {
			return "none (未找到 java，依赖仅索引不可反编译)"
		}
		return fmt.Sprintf("none (java %d 且未配置可用的反编译器 jar)", d.JavaMajor())
	}
}

// Result summarises one successful decompilation.
type Result struct {
	Engine   Engine
	Files    int
	Bytes    int64
	Duration time.Duration
	// Attempts records each engine tried, in order, with its outcome.
	Attempts []string
}

// ErrNoDecompiler is returned when no usable engine is configured. Callers should
// treat it as "source unavailable", not as a task failure.
var ErrNoDecompiler = errors.New("没有可用的反编译器（需要 JRE + Vineflower/CFR jar）")

// Decompile turns one jar into .java files under outDir.
//
// It tries the preferred engine and falls back to the other one on failure, so a
// jar that trips Vineflower still gets a CFR pass (and vice versa). Both are pure
// local parsers; no network is involved at any point.
func (d *Decompiler) Decompile(ctx context.Context, jarPath, outDir string) (Result, error) {
	var res Result
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return res, err
	}
	order := d.engineOrder()
	if len(order) == 0 {
		return res, ErrNoDecompiler
	}
	start := time.Now()
	for _, eng := range order {
		res.Attempts = append(res.Attempts, string(eng))
		engStart := time.Now()
		err := d.runEngine(ctx, eng, jarPath, outDir)
		files, bytes := countJava(outDir)
		if err == nil && files > 0 {
			res.Engine = eng
			res.Files = files
			res.Bytes = bytes
			res.Duration = time.Since(start)
			d.logf("[javadeps] %s → %s：%d 个 .java / %.1f KB / %v",
				filepath.Base(jarPath), eng, files, float64(bytes)/1024, time.Since(engStart).Round(time.Millisecond))
			return res, nil
		}
		if err == nil && files == 0 {
			err = fmt.Errorf("%s 未产出任何 .java", eng)
		}
		d.logf("[javadeps] %s 用 %s 反编译失败（%v），尝试下一个", filepath.Base(jarPath), eng, err)
		// A half-written tree from a failed attempt would corrupt the next attempt's
		// result, so clear it before retrying.
		_ = os.RemoveAll(outDir)
		_ = os.MkdirAll(outDir, 0o755)
	}
	res.Duration = time.Since(start)
	return res, fmt.Errorf("反编译失败（已尝试 %s）", strings.Join(res.Attempts, ", "))
}

// engineOrder returns the engines to try, most preferred first.
func (d *Decompiler) engineOrder() []Engine {
	major := d.JavaMajor()
	var out []Engine
	if d.VineflowerJar != "" && major >= 17 {
		out = append(out, EngineVineflower)
	}
	if d.CFRJar != "" && major >= 6 {
		out = append(out, EngineCFR)
	}
	return out
}

// runEngine executes one decompiler against one jar.
func (d *Decompiler) runEngine(ctx context.Context, eng Engine, jarPath, outDir string) error {
	ctx, cancel := context.WithTimeout(ctx, d.timeout())
	defer cancel()

	var args []string
	switch eng {
	case EngineVineflower:
		// --folder forces directory output; --thread-count uses its internal
		// multithreading (default 4); --silent keeps stderr readable.
		args = []string{
			"-Xmx" + d.heap(),
			"-jar", d.VineflowerJar,
			"--folder",
			"--thread-count=4",
			"--silent",
			jarPath,
			outDir,
		}
	case EngineCFR:
		// CFR is single-threaded; --silent suppresses its banner, --outputdir picks
		// the destination.
		args = []string{
			"-Xmx" + d.heap(),
			"-jar", d.CFRJar,
			jarPath,
			"--outputdir", outDir,
			"--silent", "true",
		}
	default:
		return fmt.Errorf("未知反编译器: %s", eng)
	}
	cmd := exec.CommandContext(ctx, d.JavaPath, args...)
	cmd.Dir = outDir
	// Never let a decompiler inherit an interactive stdin.
	cmd.Stdin = nil
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("%s 超时（>%v）", eng, d.timeout())
	}
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 400 {
			msg = msg[:400] + "…"
		}
		return fmt.Errorf("%s 退出异常: %v %s", eng, err, msg)
	}
	return nil
}

// countJava counts .java files and their total size under dir.
func countJava(dir string) (int, int64) {
	var files int
	var bytes int64
	_ = filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(p), ".java") {
			files++
			if fi, err := e.Info(); err == nil {
				bytes += fi.Size()
			}
		}
		return nil
	})
	return files, bytes
}

// DiscoverTools looks for decompiler jars under dir (typically data/tools) and
// returns the paths for Vineflower and CFR by file-name convention. Missing files
// yield empty strings, which simply disables that engine.
func DiscoverTools(dir string) (vineflowerJar, cfrJar string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", ""
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !ValidateJarName(e.Name()) {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, n := range names {
		lower := strings.ToLower(n)
		switch {
		case strings.Contains(lower, "vineflower"):
			if vineflowerJar == "" {
				vineflowerJar = filepath.Join(dir, n)
			}
		case strings.Contains(lower, "cfr"):
			if cfrJar == "" {
				cfrJar = filepath.Join(dir, n)
			}
		}
	}
	return vineflowerJar, cfrJar
}

// FindJava resolves the java executable, preferring an explicit path.
func FindJava(explicit string) string {
	if p := strings.TrimSpace(explicit); p != "" {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
		if resolved, err := exec.LookPath(p); err == nil {
			return resolved
		}
	}
	if p, err := exec.LookPath("java"); err == nil {
		return p
	}
	return ""
}
