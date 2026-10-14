package db

import (
	"database/sql"
	"errors"
	"time"
)

// =====================================================================
// 源码包上传（任务创建流程的第一步）
//
// 上传的 zip 先落盘并解压到一个 staging 目录，记录在 task_uploads；
// 用户随后创建任务时把这份源码「消费」进该任务的源码目录。
// 磁盘目录是真实数据，表只记录元数据，便于重启后继续使用未消费的上传。
// =====================================================================

// TaskUpload is a row in task_uploads.
type TaskUpload struct {
	ID         string     `json:"id"`
	Filename   string     `json:"filename"`
	StoredPath string     `json:"-"` // 服务器绝对路径，不对外暴露
	SourcePath string     `json:"-"` // 解压后的源码根目录，不对外暴露
	FileCount  int64      `json:"file_count"`
	TotalBytes int64      `json:"total_bytes"`
	CreatedBy  *int64     `json:"created_by,omitempty"`
	ConsumedBy *int64     `json:"consumed_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
}

// TaskUploadStore operates on task_uploads.
type TaskUploadStore struct{ db *DB }

// TaskUploads returns the upload store.
func (d *DB) TaskUploads() *TaskUploadStore { return &TaskUploadStore{db: d} }

// ErrTaskUploadNotFound is returned when an upload id is unknown or already consumed.
var ErrTaskUploadNotFound = errors.New("upload not found")

// CreateTaskUpload records one uploaded + extracted source archive.
func (s *TaskUploadStore) CreateTaskUpload(id, filename, storedPath, sourcePath string, fileCount, totalBytes int64, createdBy *int64) (*TaskUpload, error) {
	_, err := s.db.Exec(`
INSERT INTO task_uploads(id, filename, stored_path, source_path, file_count, total_bytes, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7)`, id, filename, storedPath, sourcePath, fileCount, totalBytes, createdBy)
	if err != nil {
		return nil, err
	}
	return s.GetTaskUpload(id)
}

// GetTaskUpload loads one upload row.
func (s *TaskUploadStore) GetTaskUpload(id string) (*TaskUpload, error) {
	var u TaskUpload
	err := s.db.QueryRow(`
SELECT id, filename, stored_path, source_path, file_count, total_bytes, created_by, consumed_by, created_at, consumed_at
FROM task_uploads WHERE id=$1`, id).
		Scan(&u.ID, &u.Filename, &u.StoredPath, &u.SourcePath, &u.FileCount, &u.TotalBytes,
			&u.CreatedBy, &u.ConsumedBy, &u.CreatedAt, &u.ConsumedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTaskUploadNotFound
		}
		return nil, err
	}
	return &u, nil
}

// MarkTaskUploadConsumed binds an upload to the task created from it. It refuses to
// consume an upload twice (compare-and-set) so two concurrent creates cannot share
// the same staging directory.
func (s *TaskUploadStore) MarkTaskUploadConsumed(id string, taskID int64) (bool, error) {
	res, err := s.db.Exec(`
UPDATE task_uploads SET consumed_by=$2, consumed_at=now()
WHERE id=$1 AND consumed_by IS NULL`, id, taskID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// ListOpenTaskUploads lists uploads that were never bound to a task (newest first).
func (s *TaskUploadStore) ListOpenTaskUploads(limit int) ([]*TaskUpload, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.Query(`
SELECT id, filename, stored_path, source_path, file_count, total_bytes, created_by, consumed_by, created_at, consumed_at
FROM task_uploads WHERE consumed_by IS NULL ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*TaskUpload{}
	for rows.Next() {
		var u TaskUpload
		if err := rows.Scan(&u.ID, &u.Filename, &u.StoredPath, &u.SourcePath, &u.FileCount, &u.TotalBytes,
			&u.CreatedBy, &u.ConsumedBy, &u.CreatedAt, &u.ConsumedAt); err != nil {
			return nil, err
		}
		out = append(out, &u)
	}
	return out, rows.Err()
}

// DeleteTaskUpload removes an upload row (its directory is removed by the caller).
func (s *TaskUploadStore) DeleteTaskUpload(id string) error {
	_, err := s.db.Exec(`DELETE FROM task_uploads WHERE id=$1`, id)
	return err
}
