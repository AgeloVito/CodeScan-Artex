package server

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/Autumn-27/artex/db"
	"golang.org/x/crypto/bcrypt"
)

// =====================================================================
// 账号与部门管理 API（仅管理员可写；普通用户只能读自己的部门）
// =====================================================================

const maxAdminMutationBodyBytes = 256 << 10

// departmentInput is one {department_id, role} pair sent by the admin UI.
type departmentInput struct {
	DepartmentID int64  `json:"department_id"`
	Role         string `json:"role"`
}

func toMemberships(in []departmentInput) []db.DepartmentMembership {
	out := make([]db.DepartmentMembership, 0, len(in))
	for _, m := range in {
		out = append(out, db.DepartmentMembership{DepartmentID: m.DepartmentID, Role: m.Role})
	}
	return out
}

// GET /api/users — 全部账号（含所属部门与角色）。仅管理员。
func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.m.pg.Users().ListUsers()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"users": users})
}

// POST /api/users — 新建账号。Body: {username, password, display_name?, is_admin?, departments?}.
func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminMutationBodyBytes)
	var req struct {
		Username    string            `json:"username"`
		Password    string            `json:"password"`
		DisplayName string            `json:"display_name"`
		IsAdmin     bool              `json:"is_admin"`
		Departments []departmentInput `json:"departments"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if msg := validateUsername(req.Username); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "密码加密失败")
		return
	}
	u, err := s.m.pg.Users().CreateUser(req.Username, req.DisplayName, string(hash), req.IsAdmin, toMemberships(req.Departments))
	if err != nil {
		writeErr(w, userWriteStatus(err), userWriteMessage(err))
		return
	}
	log.Printf("[users] 新建账号 %s (admin=%v, 部门 %d 个)", u.Username, u.IsAdmin, len(u.Departments))
	writeJSON(w, 201, u)
}

// PATCH /api/users/{id} — 改资料/角色/启用状态/密码。Body: {display_name?, is_admin?, enabled?, password?}.
func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminMutationBodyBytes)
	var req struct {
		DisplayName *string `json:"display_name"`
		IsAdmin     *bool   `json:"is_admin"`
		Enabled     *bool   `json:"enabled"`
		Password    string  `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	users := s.m.pg.Users()
	u, err := users.UpdateUser(id, db.UserPatch{DisplayName: req.DisplayName, IsAdmin: req.IsAdmin, Enabled: req.Enabled})
	if err != nil {
		writeErr(w, userWriteStatus(err), userWriteMessage(err))
		return
	}
	if strings.TrimSpace(req.Password) != "" {
		if msg := validatePassword(req.Password); msg != "" {
			writeErr(w, 400, msg)
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			writeErr(w, 500, "密码加密失败")
			return
		}
		if err := users.SetUserPassword(id, string(hash)); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	writeJSON(w, 200, u)
}

// DELETE /api/users/{id} — 删除账号（不能删掉最后一个管理员，也不能删自己）。
func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if me := currentUser(r); me != nil && me.ID == id {
		writeErr(w, 400, "不能删除当前登录账号")
		return
	}
	if err := s.m.pg.Users().DeleteUser(id); err != nil {
		writeErr(w, userWriteStatus(err), userWriteMessage(err))
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}

// PUT /api/users/{id}/departments — 分配账号所属部门（可多选，含 owner/visitor 角色）。
func (s *Server) setUserDepartments(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminMutationBodyBytes)
	var req struct {
		Departments []departmentInput `json:"departments"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	users := s.m.pg.Users()
	if err := users.SetUserDepartments(id, toMemberships(req.Departments)); err != nil {
		writeErr(w, userWriteStatus(err), userWriteMessage(err))
		return
	}
	u, err := users.GetUserByID(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, u)
}

// ---- departments ----

// GET /api/departments — 管理员看全部部门；普通用户只看自己所属的部门（带角色）。
func (s *Server) listDepartments(w http.ResponseWriter, r *http.Request) {
	me := currentUser(r)
	all, err := s.m.pg.Departments().ListDepartments()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if me != nil && !me.IsAdmin {
		roleOf := map[int64]string{}
		for _, m := range me.Departments {
			roleOf[m.DepartmentID] = m.Role
		}
		filtered := make([]*db.Department, 0, len(me.Departments))
		for _, dep := range all {
			if _, ok := roleOf[dep.ID]; ok {
				filtered = append(filtered, dep)
			}
		}
		all = filtered
	}
	writeJSON(w, 200, map[string]any{"departments": all})
}

// POST /api/departments — 新建部门。Body: {name, description?}.
func (s *Server) createDepartment(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminMutationBodyBytes)
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	dep, err := s.m.pg.Departments().CreateDepartment(req.Name, req.Description)
	if err != nil {
		writeErr(w, deptWriteStatus(err), deptWriteMessage(err))
		return
	}
	writeJSON(w, 201, dep)
}

// PATCH /api/departments/{id} — 改名/改描述。
func (s *Server) updateDepartment(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminMutationBodyBytes)
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	dep, err := s.m.pg.Departments().UpdateDepartment(id, req.Name, req.Description)
	if err != nil {
		writeErr(w, deptWriteStatus(err), deptWriteMessage(err))
		return
	}
	writeJSON(w, 200, dep)
}

// DELETE /api/departments/{id} — 删除部门（其成员关系级联删除，任务保留但变为无部门）。
func (s *Server) deleteDepartment(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if err := s.m.pg.Departments().DeleteDepartment(id); err != nil {
		writeErr(w, deptWriteStatus(err), deptWriteMessage(err))
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}

// GET /api/departments/{id}/members — 部门成员（管理员或该部门成员可读）。
func (s *Server) listDepartmentMembers(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	me := currentUser(r)
	if me != nil && !me.IsAdmin {
		role, err := s.m.pg.Users().DepartmentRole(me.ID, id)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if role == "" {
			writeErr(w, 403, "无权查看该部门")
			return
		}
	}
	members, err := s.m.pg.Departments().DepartmentMemberList(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"members": members})
}

// POST /api/tasks/{id}/department — 管理员调整任务归属部门。Body: {department_id|null}.
func (s *Server) setTaskDepartment(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t, ok := s.m.Task(id)
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	var req struct {
		DepartmentID *int64 `json:"department_id"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	updated, err := s.m.SetTaskDepartment(t.ID, req.DepartmentID)
	if err != nil {
		if errors.Is(err, db.ErrDepartmentNotFound) {
			writeErr(w, 400, "部门不存在")
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	if updated == nil {
		writeErr(w, 404, "task not found")
		return
	}
	writeJSON(w, 200, s.taskDTOWithAccess(r, updated))
}

// pathID parses a positive int64 path value, replying 400 on failure.
func pathID(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	var id int64
	if _, err := fmt.Sscanf(strings.TrimSpace(r.PathValue(name)), "%d", &id); err != nil || id <= 0 {
		writeErr(w, 400, "无效的 id")
		return 0, false
	}
	return id, true
}

func userWriteStatus(err error) int {
	switch {
	case errors.Is(err, db.ErrUserNotFound), errors.Is(err, db.ErrDepartmentNotFound):
		return 404
	case errors.Is(err, db.ErrUsernameTaken), errors.Is(err, db.ErrLastAdmin),
		errors.Is(err, db.ErrDepartmentRoleBad), errors.Is(err, db.ErrDepartmentMembersBad):
		return 400
	default:
		return 500
	}
}

func userWriteMessage(err error) string {
	switch {
	case errors.Is(err, db.ErrUserNotFound):
		return "账号不存在"
	case errors.Is(err, db.ErrUsernameTaken):
		return "用户名已存在"
	case errors.Is(err, db.ErrLastAdmin):
		return "不能移除最后一个管理员（请先指定其他管理员）"
	case errors.Is(err, db.ErrDepartmentNotFound):
		return "部门不存在"
	case errors.Is(err, db.ErrDepartmentRoleBad):
		return "部门角色必须是 owner 或 visitor"
	case errors.Is(err, db.ErrDepartmentMembersBad):
		return "所选部门不存在"
	default:
		return err.Error()
	}
}

func deptWriteStatus(err error) int {
	switch {
	case errors.Is(err, db.ErrDepartmentNotFound):
		return 404
	case errors.Is(err, db.ErrDepartmentNameTaken):
		return 400
	default:
		return 500
	}
}

func deptWriteMessage(err error) string {
	switch {
	case errors.Is(err, db.ErrDepartmentNotFound):
		return "部门不存在"
	case errors.Is(err, db.ErrDepartmentNameTaken):
		return "部门名称已存在"
	default:
		return err.Error()
	}
}
