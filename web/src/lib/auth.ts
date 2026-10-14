import type { Permissions, UserAccount } from "@/lib/types";

// 客户端会话：token + 当前账号 + 权限集合。
//
// token 仍是唯一凭据（localStorage + cookie 各写一份，cookie 供 Next 路由守卫读取）；
// 账号与权限是 /api/auth/me 的结果缓存，用于「刷新页面后立刻按角色渲染」，避免先闪出
// 管理员入口再隐藏。缓存只是 UI 优化：后端每个请求都会重新校验账号与权限。
const TOKEN_KEY = "artex_token";
const SESSION_KEY = "sca_audit_session";
const COOKIE_MAX_AGE = 7 * 24 * 60 * 60; // 7 天（秒）

/** 展示用的当前用户（兼容既有组件：name/avatar/role 等）。 */
export interface CurrentUser {
  id: string;
  name: string;
  username: string;
  email: string;
  avatar: string;
  role: string;
  isAdmin: boolean;
  departments: { id: number; name: string; role: "owner" | "visitor" }[];
}

/** 无权限时的安全默认值：什么都不能做。 */
export const NO_PERMISSIONS: Permissions = {
  can_manage_users: false,
  can_manage_departments: false,
  can_create_task: false,
  can_chat: false,
  is_visitor_only: false,
};

interface Session {
  user: UserAccount;
  permissions: Permissions;
}

function toCurrentUser(u: UserAccount): CurrentUser {
  return {
    id: String(u.id),
    name: u.display_name?.trim() || u.username,
    username: u.username,
    email: "",
    avatar: "",
    role: u.is_admin ? "admin" : "user",
    isAdmin: !!u.is_admin,
    departments: (u.departments ?? []).map((d) => ({
      id: d.department_id,
      name: d.department_name,
      role: d.role,
    })),
  };
}

function cookieSuffix(token: string): string {
  return `${TOKEN_KEY}=${encodeURIComponent(token)}; path=/; max-age=${COOKIE_MAX_AGE}; SameSite=Lax`;
}

export const auth = {
  getToken(): string | null {
    if (typeof window === "undefined") return null;
    // Mock demo：无真实登录，返回一个假 token 让路由守卫放行、直接进主界面。
    return localStorage.getItem(TOKEN_KEY) ?? (process.env.NEXT_PUBLIC_MOCK === "1" ? "mock-demo" : null);
  },

  setToken(token: string): void {
    localStorage.setItem(TOKEN_KEY, token);
    // 同步写 cookie，供 Next.js middleware 服务端读取
    document.cookie = cookieSuffix(token);
  },

  clearToken(): void {
    localStorage.removeItem(TOKEN_KEY);
    document.cookie = `${TOKEN_KEY}=; path=/; max-age=0`;
  },

  /** 登录/初始化成功后写入完整会话（token + 账号 + 权限）。 */
  setSession(token: string, user: UserAccount, permissions?: Permissions): void {
    this.setToken(token);
    const session: Session = { user, permissions: permissions ?? NO_PERMISSIONS };
    try {
      localStorage.setItem(SESSION_KEY, JSON.stringify(session));
    } catch {
      // 隐私模式下 localStorage 可能不可写：会话缓存失效不影响鉴权（token 仍有效）。
    }
  },

  getSession(): Session | null {
    if (typeof window === "undefined") return null;
    try {
      const raw = localStorage.getItem(SESSION_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw) as Session;
      if (!parsed?.user?.username) return null;
      return { user: parsed.user, permissions: { ...NO_PERMISSIONS, ...(parsed.permissions ?? {}) } };
    } catch {
      return null;
    }
  },

  /** 刷新 /api/auth/me 的结果：账号被删除/停用时清空会话并返回 null。 */
  updateSession(user: UserAccount, permissions: Permissions): void {
    const session: Session = { user, permissions };
    try {
      localStorage.setItem(SESSION_KEY, JSON.stringify(session));
    } catch {
      /* 见 setSession */
    }
  },

  clearSession(): void {
    this.clearToken();
    try {
      localStorage.removeItem(SESSION_KEY);
    } catch {
      /* ignore */
    }
  },

  getPermissions(): Permissions {
    return this.getSession()?.permissions ?? NO_PERMISSIONS;
  },

  /** 展示用当前用户；没有会话缓存时回退到 JWT 的 sub（老 token 场景）。 */
  getCurrentUser(): CurrentUser | null {
    const session = this.getSession();
    if (session) return toCurrentUser(session.user);
    const token = this.getToken();
    if (!token) return null;
    try {
      const parts = token.split(".");
      if (parts.length !== 3) return null;
      const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
      const username: string = payload.usr ?? payload.sub ?? "user";
      const isAdmin: boolean = !!payload.adm;
      return {
        id: String(payload.uid ?? ""),
        name: username,
        username,
        email: "",
        avatar: "",
        role: isAdmin ? "admin" : "user",
        isAdmin,
        departments: [],
      };
    } catch {
      return null;
    }
  },
};
