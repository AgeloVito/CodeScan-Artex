package server

import (
	"archive/zip"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// =====================================================================
// 源码包上传（任务创建流程第一步：上传压缩包 → 后端自动解压 → 创建任务）
//
// 上传只做两件事：把原始 www.zip 落盘、把源码解压到一个 staging 目录。
// 创建任务时才把 staging 目录搬进该任务的目录（data/tasks/<id>/source），
// 因此未消费的上传不会污染任何任务，也能在重启后继续使用。
// =====================================================================

const (
	// maxUploadBytes 是上传压缩包的大小上限。
	maxUploadBytes = 1 << 30 // 1 GiB
	// maxExtractBytes 是解压后所有文件的总大小上限（zip bomb 兜底）。
	maxExtractBytes = 4 << 30 // 4 GiB
	// maxExtractFiles 是解压出的文件条数上限。
	maxExtractFiles = 200000
	// uploadDirName 是 staging 根目录名（相对 data 根）。
	uploadDirName = "uploads"
)

// TaskUploadDTO is the upload view returned to the frontend (no server paths leak).
type TaskUploadDTO struct {
	ID         string   `json:"id"`
	Filename   string   `json:"filename"`
	FileCount  int64    `json:"file_count"`
	TotalBytes int64    `json:"total_bytes"`
	CreatedAt  string   `json:"created_at"`
	Entries    []string `json:"entries"` // 顶层目录/文件名（最多 20 个），供确认上传的是哪个包
}

// POST /api/tasks/upload — multipart/form-data，字段名 file，内容为 .zip 源码包。
// 返回 {upload_id, filename, file_count, total_bytes, entries}。
func (s *Server) uploadTaskSource(w http.ResponseWriter, r *http.Request) {
	me := currentUser(r)
	if me == nil {
		writeErr(w, 401, "未授权")
		return
	}
	if ok, err := s.canCreateTask(me); err != nil {
		writeErr(w, 500, err.Error())
		return
	} else if !ok {
		writeErr(w, 403, "当前账号没有创建任务的权限（需要是某个部门的所有者，或管理员）")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes+1<<20)
	mr, err := r.MultipartReader()
	if err != nil {
		writeErr(w, 400, "请求不是合法的文件上传")
		return
	}
	var (
		uploadID = newUploadID()
		dir      = filepath.Join(s.m.dir, uploadDirName, uploadID)
	)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeErr(w, 500, "创建上传目录失败: "+err.Error())
		return
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	var (
		savedName string
		zipPath   string
		bytes     int64
	)
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			cleanup()
			writeErr(w, 400, "读取上传内容失败: "+err.Error())
			return
		}
		if part.FormName() != "file" || part.FileName() == "" {
			_ = part.Close()
			continue
		}
		name := sanitizeUploadFilename(part.FileName())
		if !strings.HasSuffix(strings.ToLower(name), ".zip") {
			_ = part.Close()
			cleanup()
			writeErr(w, 400, "只支持 .zip 源码压缩包")
			return
		}
		savedName = name
		zipPath = filepath.Join(dir, name)
		f, err := os.Create(zipPath)
		if err != nil {
			_ = part.Close()
			cleanup()
			writeErr(w, 500, "保存上传文件失败: "+err.Error())
			return
		}
		bytes, err = io.Copy(f, part)
		closeErr := f.Close()
		_ = part.Close()
		if err != nil {
			cleanup()
			writeErr(w, 400, "保存上传文件失败: "+err.Error())
			return
		}
		if closeErr != nil {
			cleanup()
			writeErr(w, 500, "写入上传文件失败: "+closeErr.Error())
			return
		}
		break
	}
	if zipPath == "" {
		cleanup()
		writeErr(w, 400, "未收到文件（表单字段名应为 file）")
		return
	}

	sourceDir := filepath.Join(dir, "source")
	stats, err := extractZipArchive(zipPath, sourceDir)
	if err != nil {
		cleanup()
		writeErr(w, 400, "解压失败: "+err.Error())
		return
	}
	if stats.Files == 0 {
		cleanup()
		writeErr(w, 400, "压缩包内没有可解压的文件")
		return
	}
	createdBy := me.ID
	up, err := s.m.pg.TaskUploads().CreateTaskUpload(uploadID, savedName, zipPath, sourceDir, stats.Files, stats.Bytes, &createdBy)
	if err != nil {
		cleanup()
		writeErr(w, 500, "记录上传失败: "+err.Error())
		return
	}
	_ = bytes
	log.Printf("[upload] %s ← %s（%d 个文件 / %.1f MB）", uploadID, savedName, stats.Files, float64(stats.Bytes)/(1<<20))
	writeJSON(w, 201, map[string]any{
		"upload_id":   up.ID,
		"filename":    up.Filename,
		"file_count":  up.FileCount,
		"total_bytes": up.TotalBytes,
		"entries":     stats.Entries,
		"created_at":  up.CreatedAt,
	})
}

// GET /api/tasks/uploads — 当前账号尚未使用的上传（刷新页面后仍可继续建任务）。
func (s *Server) listTaskUploads(w http.ResponseWriter, r *http.Request) {
	me := currentUser(r)
	rows, err := s.m.pg.TaskUploads().ListOpenTaskUploads(50)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, up := range rows {
		if me != nil && !me.IsAdmin && up.CreatedBy != nil && *up.CreatedBy != me.ID {
			continue
		}
		out = append(out, map[string]any{
			"upload_id": up.ID, "filename": up.Filename,
			"file_count": up.FileCount, "total_bytes": up.TotalBytes, "created_at": up.CreatedAt,
		})
	}
	writeJSON(w, 200, map[string]any{"uploads": out})
}

// DELETE /api/tasks/uploads/{id} — 放弃一次上传（删除 staging 目录）。
func (s *Server) deleteTaskUpload(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, 400, "无效的上传 id")
		return
	}
	me := currentUser(r)
	up, err := s.m.pg.TaskUploads().GetTaskUpload(id)
	if err != nil {
		writeErr(w, 404, "上传不存在或已被使用")
		return
	}
	if me != nil && !me.IsAdmin && up.CreatedBy != nil && *up.CreatedBy != me.ID {
		writeErr(w, 403, "无权删除他人的上传")
		return
	}
	if up.ConsumedBy != nil {
		writeErr(w, 400, "该上传已被任务使用")
		return
	}
	if err := s.m.pg.TaskUploads().DeleteTaskUpload(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	_ = os.RemoveAll(filepath.Join(s.m.dir, uploadDirName, id))
	writeJSON(w, 200, map[string]any{"deleted": id})
}

// attachUploadToTask moves one staging upload into the task's own directory and
// records tasks.source_path. Called right after the task row is created.
func (s *Server) attachUploadToTask(t *Task, uploadID string) error {
	uploadID = strings.TrimSpace(uploadID)
	if uploadID == "" || t == nil {
		return nil
	}
	ups := s.m.pg.TaskUploads()
	up, err := ups.GetTaskUpload(uploadID)
	if err != nil {
		return fmt.Errorf("上传不存在或已过期，请重新上传")
	}
	if up.ConsumedBy != nil {
		return fmt.Errorf("该上传已被任务 #%d 使用", *up.ConsumedBy)
	}
	fi, err := os.Stat(up.SourcePath)
	if err != nil || !fi.IsDir() {
		return fmt.Errorf("上传的源码目录已丢失，请重新上传")
	}
	dest := filepath.Join(s.m.dir, "tasks", t.ID, "source")
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("创建任务目录失败: %w", err)
	}
	if err := os.Rename(up.SourcePath, dest); err != nil {
		// 跨盘/被占用时退化为复制。
		if cerr := copyDirTree(up.SourcePath, dest); cerr != nil {
			return fmt.Errorf("源码迁移失败: %w", cerr)
		}
		_ = os.RemoveAll(up.SourcePath)
	}
	rel := filepath.ToSlash(filepath.Join("tasks", t.ID, "source"))
	taskID, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		return fmt.Errorf("任务 id 异常: %w", err)
	}
	if err := s.m.pg.SetTaskSourcePath(taskID, rel); err != nil {
		return fmt.Errorf("记录源码目录失败: %w", err)
	}
	s.m.SetTaskSourcePathInMemory(t.ID, rel)
	claimed, err := ups.MarkTaskUploadConsumed(uploadID, taskID)
	if err != nil {
		return err
	}
	if !claimed {
		return fmt.Errorf("该上传已被其他任务使用")
	}
	log.Printf("[upload] %s → 任务 #%s 源码目录 %s", uploadID, t.ID, rel)
	return nil
}

// zipStats summarises one extraction.
type zipStats struct {
	Files   int64
	Bytes   int64
	Entries []string
}

// extractZipArchive unpacks src into dest, refusing path traversal, symlinks and
// over-large archives. Returns the file count/total size and the top-level entries.
func extractZipArchive(src, dest string) (zipStats, error) {
	var stats zipStats
	zr, err := zip.OpenReader(src)
	if err != nil {
		return stats, fmt.Errorf("不是合法的 zip 文件（%v）", err)
	}
	defer zr.Close()
	if len(zr.File) > maxExtractFiles {
		return stats, fmt.Errorf("压缩包内文件数超过 %d", maxExtractFiles)
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return stats, err
	}
	topLevel := map[string]bool{}
	for _, f := range zr.File {
		rel, ok := safeZipPath(f.Name)
		if !ok || rel == "" {
			continue
		}
		if i := strings.IndexByte(rel, '/'); i > 0 {
			topLevel[rel[:i]] = true
		} else if rel != "" {
			topLevel[rel] = true
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(filepath.Join(dest, filepath.FromSlash(rel)), 0o755); err != nil {
				return stats, err
			}
			continue
		}
		// 符号链接/设备文件一律跳过：源码审计不需要它们，解压出来只会有风险。
		if f.Mode()&os.ModeSymlink != 0 || f.Mode()&os.ModeDevice != 0 || f.Mode()&os.ModeNamedPipe != 0 {
			continue
		}
		target := filepath.Join(dest, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return stats, err
		}
		if stats.Bytes+int64(f.UncompressedSize64) > maxExtractBytes {
			return stats, fmt.Errorf("解压后总大小超过上限（%d GiB）", maxExtractBytes>>30)
		}
		rc, err := f.Open()
		if err != nil {
			return stats, err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			_ = rc.Close()
			return stats, err
		}
		n, err := io.Copy(out, io.LimitReader(rc, maxExtractBytes))
		_ = rc.Close()
		closeErr := out.Close()
		if err != nil {
			return stats, err
		}
		if closeErr != nil {
			return stats, closeErr
		}
		stats.Files++
		stats.Bytes += n
		if stats.Files > maxExtractFiles {
			return stats, fmt.Errorf("压缩包内文件数超过 %d", maxExtractFiles)
		}
	}
	if len(topLevel) > 0 {
		entries := make([]string, 0, len(topLevel))
		for name := range topLevel {
			entries = append(entries, name)
		}
		sort.Strings(entries)
		if len(entries) > 20 {
			entries = entries[:20]
		}
		stats.Entries = entries
	}
	return stats, nil
}

// safeZipPath normalises a zip entry name and reports whether it stays inside the
// destination directory. Absolute paths, drive letters, ".." and NUL are rejected.
func safeZipPath(name string) (string, bool) {
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

// sanitizeUploadFilename keeps only the base name and strips characters that are
// awkward or unsafe on disk (keeps CJK, digits, letters, dot, dash, underscore).
func sanitizeUploadFilename(name string) string {
	name = strings.TrimSpace(strings.ReplaceAll(name, "\\", "/"))
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_', r == ' ', r > 0x7f:
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := strings.TrimLeft(strings.TrimSpace(b.String()), ".")
	if out == "" {
		out = "source.zip"
	}
	if len(out) > 120 {
		out = out[len(out)-120:]
	}
	return out
}

// newUploadID returns a short random upload id (also used as the staging dir name).
func newUploadID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("up%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

// copyDirTree copies a directory tree (used when a rename crosses filesystems).
func copyDirTree(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !info.Mode().IsRegular() {
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
