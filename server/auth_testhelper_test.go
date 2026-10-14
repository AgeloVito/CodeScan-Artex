package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/Autumn-27/artex/db"
	"golang.org/x/crypto/bcrypt"
)

// testAdminUsername is the administrator account the HTTP tests authenticate as.
// It is created on demand in the shared test database.
const testAdminUsername = "test-admin"

// withTestAdmin puts a synthetic administrator into the request context, for tests
// that call a handler directly (bypassing requireAuth, which normally resolves the
// account from the JWT). Use it only where the test is not about authentication:
// handlers that enforce per-task write permission would otherwise answer 401/403.
func withTestAdmin(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), authCtxKey{}, &db.User{
		ID: 1, Username: testAdminUsername, DisplayName: "测试管理员", IsAdmin: true, Enabled: true,
	}))
}

// testAdminToken returns a JWT for a real administrator account, creating the
// account when the test database has none. Tests therefore exercise the real auth
// chain (JWT → account lookup → task permission guard) instead of a synthetic
// identity that bypasses it.
func testAdminToken(t *testing.T, s *Server) string {
	t.Helper()
	users := s.m.pg.Users()
	u, err := users.GetUserByUsername(testAdminUsername)
	if err != nil {
		hash, herr := bcrypt.GenerateFromPassword([]byte("test-admin-password"), bcrypt.MinCost)
		if herr != nil {
			t.Fatalf("hash test password: %v", herr)
		}
		u, err = users.CreateUser(testAdminUsername, "测试管理员", string(hash), true, nil)
		if err != nil {
			t.Fatalf("create test admin: %v", err)
		}
	}
	tok, err := signJWT(s.jwtKey, u)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return tok
}
