"use client";

import * as React from "react";

import { auth, type CurrentUser } from "@/lib/auth";
import { useAuth } from "@/lib/auth-context";
import type { UserAccount } from "@/lib/types";

// 没有会话时的占位账号：主界面校验 token 期间或 mock demo 下，头部/侧边栏
// 仍要有东西可渲染，但不能伪装成某个真实用户名。
const FALLBACK: CurrentUser = {
  id: "",
  name: "SCA Audit",
  username: "",
  email: "",
  avatar: "",
  role: "user",
  isAdmin: false,
  departments: [],
};

// 与 lib/auth.ts 的 toCurrentUser 同规则：显示名优先 display_name，回退 username。
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

/**
 * 当前登录账号（展示用）。这次改为基于 AuthProvider 的 context：
 * /api/auth/me 返回后头部与用户菜单会自动换成真实账号；无会话时给安全占位值。
 */
export function useCurrentUser(): CurrentUser {
  const { user } = useAuth();

  return React.useMemo(() => {
    if (user) return toCurrentUser(user);
    // context 尚无可用的账号（首屏 / 未登录）时退回本地会话缓存，再退到占位账号。
    return auth.getCurrentUser() ?? FALLBACK;
  }, [user]);
}
