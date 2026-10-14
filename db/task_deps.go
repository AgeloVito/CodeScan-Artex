package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// =====================================================================
// 第三方依赖（Java jar / .m2）
//
// 与 docs/java-m2依赖读取与反编译方案.md 对应：
//   - 入库只写「清单 + 类名索引」这一层（source_state 默认 none，不反编译）；
//   - 源码按需产生：Materialize 成功后回写 source_state/source_path/...；
//   - jar 路径一律是【任务相对】路径（deps/jars/...），与 agent 看到的一致。
// =====================================================================

// Dependency is a row in task_dependencies.
type Dependency struct {
	ID        int64  `json:"id"`
	TaskID    int64  `json:"task_id"`
	GroupID   string `json:"group_id"`
	Artifact  string `json:"artifact_id"`
	Version   string `json:"version"`
	Classifier string `json:"classifier,omitempty"`
	GAVSource string `json:"gav_source"`

	// GAV renders the coordinate the way agents and the UI should refer to it.
	GAV string `json:"gav"`

	Scope       string `json:"scope,omitempty"`
	Direct      bool   `json:"direct"`
	JarPath     string `json:"jar_path"`
	JarSHA256   string `json:"jar_sha256"`
	SizeBytes   int64  `json:"size_bytes"`
	ClassCount  int    `json:"class_count"`
	PackageCount int   `json:"package_count"`
	IsSources   bool   `json:"is_sources"`
	MultiRelease bool  `json:"multi_release"`
	Corrupt     bool   `json:"corrupt"`
	NativeHeavy bool   `json:"native_heavy"`

	// SourceState is none | original | decompiled.
	SourceState  string     `json:"source_state"`
	SourcePath   string     `json:"source_path,omitempty"`
	SourceFiles  int        `json:"source_files"`
	SourceBytes  int64      `json:"source_bytes"`
	Decompiler   string     `json:"decompiler,omitempty"`
	Materialized *time.Time `json:"materialized_at,omitempty"`
	Error        string     `json:"error,omitempty"`

	TopPackages []string  `json:"top_packages,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CanMaterialize reports whether requesting source for this dependency makes sense.
func (d *Dependency) CanMaterialize() bool {
	return !d.Corrupt && !d.NativeHeavy && !d.IsSources
}

// DependencyStore operates on task_dependencies.
type DependencyStore struct{ db *DB }

// Dependencies returns the dependency store.
func (d *DB) Dependencies() *DependencyStore { return &DependencyStore{db: d} }

const dependencyCols = `id, task_id, group_id, artifact_id, version, classifier, gav_source,
	scope, direct, jar_path, jar_sha256, size_bytes, class_count, package_count,
	is_sources, multi_release, corrupt, native_heavy,
	source_state, source_path, source_files, source_bytes, decompiler, materialized_at, error,
	top_packages, created_at, updated_at`

func scanDependency(sc interface {
	Scan(dest ...any) error
}) (*Dependency, error) {
	var d Dependency
	var top []byte
	if err := sc.Scan(&d.ID, &d.TaskID, &d.GroupID, &d.Artifact, &d.Version, &d.Classifier, &d.GAVSource,
		&d.Scope, &d.Direct, &d.JarPath, &d.JarSHA256, &d.SizeBytes, &d.ClassCount, &d.PackageCount,
		&d.IsSources, &d.MultiRelease, &d.Corrupt, &d.NativeHeavy,
		&d.SourceState, &d.SourcePath, &d.SourceFiles, &d.SourceBytes, &d.Decompiler, &d.Materialized, &d.Error,
		&top, &d.CreatedAt, &d.UpdatedAt); err != nil {
		return nil, err
	}
	if len(top) > 0 {
		_ = json.Unmarshal(top, &d.TopPackages)
	}
	d.GAV = dependencyGAV(d.GroupID, d.Artifact, d.Version, d.Classifier)
	return &d, nil
}

// dependencyGAV renders a coordinate, omitting an empty group so a flat-repository
// jar does not read as ":artifact:version".
func dependencyGAV(group, artifact, version, classifier string) string {
	s := artifact + ":" + version
	if group != "" {
		s = group + ":" + s
	}
	if classifier != "" {
		s += ":" + classifier
	}
	return s
}

// UpsertDependency inserts or refreshes one dependency's scan results. It preserves
// the materialisation columns (source_*) so a re-scan never throws away already
// decompiled source.
//
// It also preserves scope/direct rather than overwriting them with the empty values
// an upload produces: those two columns are only ever filled by the pom.xml scan
// (a rescan has no idea about scopes), so clobbering them would lose the information
// on the very next "重新扫描".
func (s *DependencyStore) UpsertDependency(d *Dependency) (*Dependency, error) {
	top, _ := json.Marshal(d.TopPackages)
	if d.TopPackages == nil {
		top = []byte("[]")
	}
	row := s.db.QueryRow(`
INSERT INTO task_dependencies
  (task_id, group_id, artifact_id, version, classifier, gav_source, scope, direct,
   jar_path, jar_sha256, size_bytes, class_count, package_count,
   is_sources, multi_release, corrupt, native_heavy, top_packages)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
ON CONFLICT (task_id, group_id, artifact_id, version, classifier) DO UPDATE SET
   gav_source=EXCLUDED.gav_source,
   scope=CASE WHEN EXCLUDED.scope <> '' THEN EXCLUDED.scope ELSE task_dependencies.scope END,
   direct=task_dependencies.direct OR EXCLUDED.direct,
   jar_path=EXCLUDED.jar_path,
   jar_sha256=EXCLUDED.jar_sha256,
   size_bytes=EXCLUDED.size_bytes,
   class_count=EXCLUDED.class_count,
   package_count=EXCLUDED.package_count,
   is_sources=EXCLUDED.is_sources,
   multi_release=EXCLUDED.multi_release,
   corrupt=EXCLUDED.corrupt,
   native_heavy=EXCLUDED.native_heavy,
   top_packages=EXCLUDED.top_packages,
   updated_at=now()
RETURNING `+dependencyCols,
		d.TaskID, d.GroupID, d.Artifact, d.Version, d.Classifier, d.GAVSource, d.Scope, d.Direct,
		d.JarPath, d.JarSHA256, d.SizeBytes, d.ClassCount, d.PackageCount,
		d.IsSources, d.MultiRelease, d.Corrupt, d.NativeHeavy, top)
	return scanDependency(row)
}

// ListDependencies returns a task's dependencies, ordered for stable display.
func (s *DependencyStore) ListDependencies(taskID int64) ([]*Dependency, error) {
	rows, err := s.db.Query(`SELECT `+dependencyCols+` FROM task_dependencies
WHERE task_id=$1 ORDER BY group_id, artifact_id, version`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Dependency{}
	for rows.Next() {
		d, err := scanDependency(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetDependency loads one row by id.
func (s *DependencyStore) GetDependency(id int64) (*Dependency, error) {
	row := s.db.QueryRow(`SELECT `+dependencyCols+` FROM task_dependencies WHERE id=$1`, id)
	d, err := scanDependency(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return d, nil
}

// FindDependency resolves a coordinate string to a row within one task. It accepts
// "group:artifact:version", "artifact:version" (flat) and an optional classifier.
func (s *DependencyStore) FindDependency(taskID int64, group, artifact, version, classifier string) (*Dependency, error) {
	row := s.db.QueryRow(`SELECT `+dependencyCols+` FROM task_dependencies
WHERE task_id=$1 AND group_id=$2 AND artifact_id=$3 AND version=$4 AND classifier=$5`,
		taskID, group, artifact, version, classifier)
	d, err := scanDependency(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return d, nil
}

// MarkMaterialized records the outcome of turning a dependency into readable
// source. state is "original" or "decompiled"; on failure pass state="" and the
// reason in errMsg so the UI/agent can show why and not retry blindly.
func (s *DependencyStore) MarkMaterialized(id int64, state, sourcePath string, files int, bytes int64, decompiler, errMsg string) error {
	if state == "" {
		_, err := s.db.Exec(`UPDATE task_dependencies
SET error=$2, updated_at=now() WHERE id=$1`, id, errMsg)
		return err
	}
	_, err := s.db.Exec(`UPDATE task_dependencies
SET source_state=$2, source_path=$3, source_files=$4, source_bytes=$5,
    decompiler=$6, materialized_at=now(), error='', updated_at=now()
WHERE id=$1`, id, state, sourcePath, files, bytes, decompiler)
	return err
}

// DeleteTaskDependencies drops every dependency row for a task (re-upload / reset).
func (s *DependencyStore) DeleteTaskDependencies(taskID int64) error {
	_, err := s.db.Exec(`DELETE FROM task_dependencies WHERE task_id=$1`, taskID)
	return err
}

// CountDependencies reports how many dependencies a task has (0 = none uploaded).
func (s *DependencyStore) CountDependencies(taskID int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM task_dependencies WHERE task_id=$1`, taskID).Scan(&n)
	return n, err
}
