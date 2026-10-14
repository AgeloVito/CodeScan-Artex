"use client";

import * as React from "react";

import { auth, NO_PERMISSIONS } from "@/lib/auth";
import { api } from "@/lib/api";
import type { Permissions, UserAccount } from "@/lib/types";

// AuthContext 把「当前账号 + 权限集合」提升为全局状态：
// - 首次挂载时用 /api/auth/me 拉一次（后端会重新校验 token 是否仍然有效）；
// - 侧边栏/按钮据此隐藏无权入口（后端仍然独立强制校验，前端隐藏只是体验）；
// - 登录页/初始化页登录成功后调用 refresh() 立刻拿到权限，避免刷新前闪空。

interface AuthContextValue {
  user: UserAccount | null;
  permissions: Permissions;
  loading: boolean;
  /** 重新拉取 /api/auth/me；401 时清空会话并返回 null。 */
  refresh: () => Promise<{ user: UserAccount; permissions: Permissions } | null>;
  /** 登录/初始化成功后写入会话并同步 context。 */
  adopt: (token: string, user: UserAccount, permissions?: Permissions) => void;
  signOut: () => void;
}

const AuthContext = React.createContext<AuthContextValue>({
  user: null,
  permissions: NO_PERMISSIONS,
  loading: true,
  refresh: async () => null,
  adopt: () => {},
  signOut: () => {},
});

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = React.useState<UserAccount | null>(null);
  const [permissions, setPermissions] = React.useState<Permissions>(NO_PERMISSIONS);
  const [loading, setLoading] = React.useState(true);

  const refresh = React.useCallback(async () => {
    if (!auth.getToken()) {
      setUser(null);
      setPermissions(NO_PERMISSIONS);
      setLoading(false);
      return null;
    }
    try {
      const res = await api.me();
      setUser(res.user);
      setPermissions(res.permissions);
      auth.updateSession(res.user, res.permissions);
      return res;
    } catch {
      // 401 已由 http() 统一处理（清 token + 跳登录）；其它错误保持上次状态。
      setLoading(false);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    // 先用本地缓存立刻渲染（避免首屏按「无权限」渲染后跳变），再向后端核对。
    const cached = auth.getSession();
    if (cached) {
      setUser(cached.user);
      setPermissions(cached.permissions);
      setLoading(false);
    }
    void refresh();
  }, [refresh]);

  const adopt = React.useCallback((token: string, u: UserAccount, p?: Permissions) => {
    auth.setSession(token, u, p);
    setUser(u);
    setPermissions(p ?? NO_PERMISSIONS);
    setLoading(false);
  }, []);

  const signOut = React.useCallback(() => {
    void api.logout().catch(() => {
      /* 登出失败也要清本地会话 */
    });
    auth.clearSession();
    setUser(null);
    setPermissions(NO_PERMISSIONS);
  }, []);

  const value = React.useMemo(
    () => ({ user, permissions, loading, refresh, adopt, signOut }),
    [user, permissions, loading, refresh, adopt, signOut],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  return React.useContext(AuthContext);
}
