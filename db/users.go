package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// =====================================================================
// 用户 / 部门 / 部门成员
//
// 权限模型：
//   - 管理员（users.is_admin=true）：管理用户与部门，可见并可操作全部任务。
//   - 普通用户：可见范围 = 自己所属部门下的任务；部门角色决定能否写。
//   - 部门角色 role：owner=部门所有者（可对话、建任务、暂停/删除任务），
//     visitor=部门访客（只读，不能对话、不能建任务、不能暂停或删除任务）。
// =====================================================================

// 部门角色取值。
const (
	DeptRoleOwner   = "owner"
	DeptRoleVisitor = "visitor"
)

var (
	ErrUserNotFound         = errors.New("user not found")
	ErrUsernameTaken        = errors.New("username already exists")
	ErrLastAdmin            = errors.New("cannot remove the last administrator")
	ErrUserDisabled         = errors.New("user disabled")
	ErrDepartmentNotFound   = errors.New("department not found")
	ErrDepartmentNameTaken  = errors.New("department name already exists")
	ErrDepartmentRoleBad    = errors.New("department role must be owner|visitor")
	ErrDepartmentMembersBad = errors.New("department membership references an unknown department")
)

// User is a row in the users table, optionally carrying its department memberships.
type User struct {
	ID          int64            `json:"id"`
	Username    string           `json:"username"`
	DisplayName string           `json:"display_name"`
	IsAdmin     bool             `json:"is_admin"`
	Enabled     bool             `json:"enabled"`
	LastLoginAt *time.Time       `json:"last_login_at,omitempty"`
	CreatedAt   time.Time        `json:"created_at"`
	Departments []UserDepartment `json:"departments"`
}

// UserDepartment is one membership row joined with the department name.
type UserDepartment struct {
	DepartmentID   int64  `json:"department_id"`
	DepartmentName string `json:"department_name"`
	Role           string `json:"role"`
}

// Department is a row in the departments table plus member counters.
type Department struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	MemberCount int       `json:"member_count"`
	OwnerCount  int       `json:"owner_count"`
	CreatedAt   time.Time `json:"created_at"`
}

// DepartmentMembership is a (department, role) pair used on user writes.
type DepartmentMembership struct {
	DepartmentID int64  `json:"department_id"`
	Role         string `json:"role"`
}

// UserStore operates on users + user_departments.
type UserStore struct{ db *DB }

// DepartmentStore operates on departments.
type DepartmentStore struct{ db *DB }

// Users returns the user store.
func (d *DB) Users() *UserStore { return &UserStore{db: d} }

// Departments returns the department store.
func (d *DB) Departments() *DepartmentStore { return &DepartmentStore{db: d} }

func normalizeDeptRole(role string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "", DeptRoleVisitor:
		return DeptRoleVisitor, nil
	case DeptRoleOwner:
		return DeptRoleOwner, nil
	default:
		return "", ErrDepartmentRoleBad
	}
}

func deptNKey(name string) string {
	return strings.Join(strings.Fields(strings.ToLower(name)), " ")
}

// ---- users ----

const userCols = `id, username, COALESCE(display_name,''), is_admin, COALESCE(enabled,true), last_login_at, created_at`

func scanUser(sc interface{ Scan(...any) error }) (*User, error) {
	var u User
	if err := sc.Scan(&u.ID, &u.Username, &u.DisplayName, &u.IsAdmin, &u.Enabled, &u.LastLoginAt, &u.CreatedAt); err != nil {
		return nil, err
	}
	u.Departments = []UserDepartment{}
	return &u, nil
}

// CountUsers reports how many accounts exist (0 = 平台尚未初始化)。
func (s *UserStore) CountUsers() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

// CountAdmins reports how many enabled administrator accounts exist.
func (s *UserStore) CountAdmins() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT count(*) FROM users WHERE is_admin AND enabled`).Scan(&n)
	return n, err
}

// CreateUser inserts an account with its department memberships in one transaction.
// The caller supplies the bcrypt hash. Empty username is rejected; duplicates are
// reported as ErrUsernameTaken (unique index on lower(username)).
func (s *UserStore) CreateUser(username, displayName, passwordHash string, isAdmin bool, memberships []DepartmentMembership) (*User, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, fmt.Errorf("username must not be empty")
	}
	if passwordHash == "" {
		return nil, fmt.Errorf("password hash must not be empty")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	u, err := scanUser(tx.QueryRow(`
INSERT INTO users(username, display_name, password_hash, is_admin)
VALUES ($1,$2,$3,$4)
RETURNING `+userCols, username, strings.TrimSpace(displayName), passwordHash, isAdmin))
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrUsernameTaken
		}
		return nil, err
	}
	if err := replaceUserDepartments(tx, u.ID, memberships); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetUserByID(u.ID)
}

// MigrateLegacyAdmin seeds the first administrator from the legacy single-password
// install (settings auth.password_hash). No-op when an account already exists, so
// it can run on every startup.
func (s *UserStore) MigrateLegacyAdmin(username, passwordHash string) (bool, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		username = "admin"
	}
	if strings.TrimSpace(passwordHash) == "" {
		return false, nil
	}
	var exists bool
	if err := s.db.QueryRow(`SELECT EXISTS (SELECT 1 FROM users)`).Scan(&exists); err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	_, err := s.CreateUser(username, "管理员", passwordHash, true, nil)
	if err != nil {
		if errors.Is(err, ErrUsernameTaken) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ListUsers returns every account ordered by id, each with its department memberships.
func (s *UserStore) ListUsers() ([]*User, error) {
	rows, err := s.db.Query(`SELECT ` + userCols + ` FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*User{}
	byID := map[int64]*User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
		byID[u.ID] = u
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return out, nil
	}
	mrows, err := s.db.Query(`
SELECT ud.user_id, ud.department_id, d.name, ud.role
FROM user_departments ud JOIN departments d ON d.id = ud.department_id
ORDER BY d.name, ud.department_id`)
	if err != nil {
		return nil, err
	}
	defer mrows.Close()
	for mrows.Next() {
		var uid int64
		var m UserDepartment
		if err := mrows.Scan(&uid, &m.DepartmentID, &m.DepartmentName, &m.Role); err != nil {
			return nil, err
		}
		if u := byID[uid]; u != nil {
			u.Departments = append(u.Departments, m)
		}
	}
	return out, mrows.Err()
}

// GetUserByID loads one account (memberships included) or ErrUserNotFound.
func (s *UserStore) GetUserByID(id int64) (*User, error) {
	u, err := scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE id=$1`, id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	memberships, err := s.UserMemberships(id)
	if err != nil {
		return nil, err
	}
	u.Departments = memberships
	return u, nil
}

// GetUserByUsername loads an account by case-insensitive username.
func (s *UserStore) GetUserByUsername(username string) (*User, error) {
	u, err := scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE lower(username)=lower($1)`, strings.TrimSpace(username)))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	memberships, err := s.UserMemberships(u.ID)
	if err != nil {
		return nil, err
	}
	u.Departments = memberships
	return u, nil
}

// UserAuth is the credential lookup result for login.
type UserAuth struct {
	ID           int64
	Username     string
	PasswordHash string
	IsAdmin      bool
	Enabled      bool
}

// GetUserAuth returns the stored hash + flags for a login attempt.
func (s *UserStore) GetUserAuth(username string) (*UserAuth, error) {
	var a UserAuth
	err := s.db.QueryRow(`
SELECT id, username, password_hash, is_admin, COALESCE(enabled,true)
FROM users WHERE lower(username)=lower($1)`, strings.TrimSpace(username)).
		Scan(&a.ID, &a.Username, &a.PasswordHash, &a.IsAdmin, &a.Enabled)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &a, nil
}

// TouchLastLogin stamps the login time (best effort).
func (s *UserStore) TouchLastLogin(id int64) error {
	_, err := s.db.Exec(`UPDATE users SET last_login_at=now() WHERE id=$1`, id)
	return err
}

// SetUserPassword replaces an account's password hash.
func (s *UserStore) SetUserPassword(id int64, passwordHash string) error {
	if strings.TrimSpace(passwordHash) == "" {
		return fmt.Errorf("password hash must not be empty")
	}
	res, err := s.db.Exec(`UPDATE users SET password_hash=$2 WHERE id=$1`, id, passwordHash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// UserPatch carries the mutable account fields (nil = leave unchanged).
type UserPatch struct {
	DisplayName *string
	IsAdmin     *bool
	Enabled     *bool
}

// UpdateUser applies an account patch. Demoting or disabling the last enabled
// administrator is refused so the platform can never lose its only admin.
func (s *UserStore) UpdateUser(id int64, patch UserPatch) (*User, error) {
	current, err := s.GetUserByID(id)
	if err != nil {
		return nil, err
	}
	displayName := current.DisplayName
	if patch.DisplayName != nil {
		displayName = strings.TrimSpace(*patch.DisplayName)
	}
	isAdmin := current.IsAdmin
	if patch.IsAdmin != nil {
		isAdmin = *patch.IsAdmin
	}
	enabled := current.Enabled
	if patch.Enabled != nil {
		enabled = *patch.Enabled
	}
	if current.IsAdmin && current.Enabled && (!isAdmin || !enabled) {
		admins, err := s.CountAdmins()
		if err != nil {
			return nil, err
		}
		if admins <= 1 {
			return nil, ErrLastAdmin
		}
	}
	if _, err := s.db.Exec(`UPDATE users SET display_name=$2, is_admin=$3, enabled=$4 WHERE id=$1`,
		id, displayName, isAdmin, enabled); err != nil {
		return nil, err
	}
	return s.GetUserByID(id)
}

// DeleteUser removes an account. The last enabled administrator cannot be deleted.
func (s *UserStore) DeleteUser(id int64) error {
	current, err := s.GetUserByID(id)
	if err != nil {
		return err
	}
	if current.IsAdmin && current.Enabled {
		admins, err := s.CountAdmins()
		if err != nil {
			return err
		}
		if admins <= 1 {
			return ErrLastAdmin
		}
	}
	res, err := s.db.Exec(`DELETE FROM users WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// UserMemberships lists a user's departments (with names) ordered by name.
func (s *UserStore) UserMemberships(userID int64) ([]UserDepartment, error) {
	rows, err := s.db.Query(`
SELECT ud.department_id, d.name, ud.role
FROM user_departments ud JOIN departments d ON d.id=ud.department_id
WHERE ud.user_id=$1
ORDER BY d.name, ud.department_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UserDepartment{}
	for rows.Next() {
		var m UserDepartment
		if err := rows.Scan(&m.DepartmentID, &m.DepartmentName, &m.Role); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// SetUserDepartments replaces a user's department memberships atomically.
func (s *UserStore) SetUserDepartments(userID int64, memberships []DepartmentMembership) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SELECT id FROM users WHERE id=$1 FOR UPDATE`, userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUserNotFound
		}
		return err
	}
	if err := replaceUserDepartments(tx, userID, memberships); err != nil {
		return err
	}
	return tx.Commit()
}

// replaceUserDepartments rewrites one user's membership rows inside tx.
func replaceUserDepartments(tx *sql.Tx, userID int64, memberships []DepartmentMembership) error {
	if _, err := tx.Exec(`DELETE FROM user_departments WHERE user_id=$1`, userID); err != nil {
		return err
	}
	seen := map[int64]bool{}
	for _, m := range memberships {
		if m.DepartmentID <= 0 {
			return ErrDepartmentMembersBad
		}
		if seen[m.DepartmentID] {
			continue
		}
		seen[m.DepartmentID] = true
		role, err := normalizeDeptRole(m.Role)
		if err != nil {
			return err
		}
		res, err := tx.Exec(`
INSERT INTO user_departments(user_id, department_id, role)
SELECT $1, id, $3 FROM departments WHERE id=$2`, userID, m.DepartmentID, role)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrDepartmentMembersBad
		}
	}
	return nil
}

// VisibleDepartmentIDs returns the ids of the departments a user belongs to.
// role="" returns every membership; role=owner returns only owned departments.
func (s *UserStore) VisibleDepartmentIDs(userID int64, role string) ([]int64, error) {
	q := `SELECT department_id FROM user_departments WHERE user_id=$1`
	args := []any{userID}
	if role != "" {
		q += ` AND role=$2`
		args = append(args, role)
	}
	q += ` ORDER BY department_id`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// DepartmentRole returns the user's role in one department ("" = not a member).
func (s *UserStore) DepartmentRole(userID, departmentID int64) (string, error) {
	var role string
	err := s.db.QueryRow(`SELECT role FROM user_departments WHERE user_id=$1 AND department_id=$2`,
		userID, departmentID).Scan(&role)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return role, nil
}

// IsDepartmentOwner reports whether the user owns (not merely visits) a department.
func (s *UserStore) IsDepartmentOwner(userID, departmentID int64) (bool, error) {
	role, err := s.DepartmentRole(userID, departmentID)
	return role == DeptRoleOwner, err
}

// OwnedDepartmentIDs lists the departments the user can act on (owner role).
func (s *UserStore) OwnedDepartmentIDs(userID int64) ([]int64, error) {
	return s.VisibleDepartmentIDs(userID, DeptRoleOwner)
}

// ---- departments ----

const deptCols = `d.id, d.name, COALESCE(d.description,''), d.created_at,
COALESCE((SELECT count(*) FROM user_departments ud WHERE ud.department_id=d.id),0),
COALESCE((SELECT count(*) FROM user_departments ud WHERE ud.department_id=d.id AND ud.role='owner'),0)`

func scanDepartment(sc interface{ Scan(...any) error }) (*Department, error) {
	var dep Department
	if err := sc.Scan(&dep.ID, &dep.Name, &dep.Description, &dep.CreatedAt, &dep.MemberCount, &dep.OwnerCount); err != nil {
		return nil, err
	}
	return &dep, nil
}

// ListDepartments returns all departments ordered by name.
func (s *DepartmentStore) ListDepartments() ([]*Department, error) {
	rows, err := s.db.Query(`SELECT ` + deptCols + ` FROM departments d ORDER BY d.name, d.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Department{}
	for rows.Next() {
		dep, err := scanDepartment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, dep)
	}
	return out, rows.Err()
}

// GetDepartment loads one department or ErrDepartmentNotFound.
func (s *DepartmentStore) GetDepartment(id int64) (*Department, error) {
	dep, err := scanDepartment(s.db.QueryRow(`SELECT `+deptCols+` FROM departments d WHERE d.id=$1`, id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrDepartmentNotFound
		}
		return nil, err
	}
	return dep, nil
}

// CreateDepartment inserts a department (name uniqueness is case-insensitive).
func (s *DepartmentStore) CreateDepartment(name, description string) (*Department, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("部门名称不能为空")
	}
	var id int64
	err := s.db.QueryRow(`
INSERT INTO departments(name, nkey, description) VALUES ($1,$2,$3) RETURNING id`,
		name, deptNKey(name), strings.TrimSpace(description)).Scan(&id)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrDepartmentNameTaken
		}
		return nil, err
	}
	return s.GetDepartment(id)
}

// UpdateDepartment renames/describes a department.
func (s *DepartmentStore) UpdateDepartment(id int64, name, description string) (*Department, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("部门名称不能为空")
	}
	res, err := s.db.Exec(`UPDATE departments SET name=$2, nkey=$3, description=$4 WHERE id=$1`,
		id, name, deptNKey(name), strings.TrimSpace(description))
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrDepartmentNameTaken
		}
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrDepartmentNotFound
	}
	return s.GetDepartment(id)
}

// DeleteDepartment removes a department; task rows referencing it keep their data
// (tasks.department_id is set to NULL by the FK) but become admin/creator-only.
func (s *DepartmentStore) DeleteDepartment(id int64) error {
	res, err := s.db.Exec(`DELETE FROM departments WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrDepartmentNotFound
	}
	return nil
}

// DepartmentMember 是部门成员列表的一行：账号信息 + 它在该部门的角色。
// 前端「部门管理 → 成员列表」要显示角色徽标（所有者/访客），所以角色必须随列表返回。
type DepartmentMember struct {
	UserID      int64  `json:"user_id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	IsAdmin     bool   `json:"is_admin"`
	Enabled     bool   `json:"enabled"`
	Role        string `json:"role"`
}

// DepartmentMemberList lists a department's members together with their role.
func (s *DepartmentStore) DepartmentMemberList(departmentID int64) ([]DepartmentMember, error) {
	rows, err := s.db.Query(`
SELECT u.id, u.username, COALESCE(u.display_name,''), u.is_admin, COALESCE(u.enabled,true), ud.role
FROM users u
JOIN user_departments ud ON ud.user_id=u.id
WHERE ud.department_id=$1
ORDER BY ud.role, u.username`, departmentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DepartmentMember{}
	for rows.Next() {
		var m DepartmentMember
		if err := rows.Scan(&m.UserID, &m.Username, &m.DisplayName, &m.IsAdmin, &m.Enabled, &m.Role); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// DepartmentMembers lists the users belonging to a department.
// userCols 里的列名没有表前缀，join user_departments（它自己也有 created_at）时会
// 触发 "column reference is ambiguous"，所以这里显式按 u. 限定。
func (s *DepartmentStore) DepartmentMembers(departmentID int64) ([]*User, error) {
	rows, err := s.db.Query(`
SELECT u.id, u.username, COALESCE(u.display_name,''), u.is_admin, COALESCE(u.enabled,true),
       u.last_login_at, u.created_at
FROM users u
JOIN user_departments ud ON ud.user_id=u.id
WHERE ud.department_id=$1
ORDER BY u.username`, departmentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// isUniqueViolation reports whether err is a PostgreSQL unique-constraint error.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "23505") || strings.Contains(strings.ToLower(err.Error()), "duplicate key")
}
