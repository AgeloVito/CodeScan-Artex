"use client";

import { useEffect, useState } from "react";

import { useRouter } from "next/navigation";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import { auth } from "@/lib/auth";
import type { Permissions } from "@/lib/types";

// 第一个账号必然是管理员（后端 /api/auth/init 保证），先按「全权限」写本地会话缓存，
// 免得 /api/auth/me 回来之前侧边栏把管理入口藏起来；后端稍后会覆盖成真实权限。
const ADMIN_PERMISSIONS: Permissions = {
  can_manage_users: true,
  can_manage_departments: true,
  can_create_task: true,
  can_chat: true,
  is_visitor_only: false,
};

export default function SetupPage() {
  const router = useRouter();
  const [username, setUsername] = useState("admin");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [checking, setChecking] = useState(true);
  // 查不到初始化状态时不能默认当成"未初始化"——那样会把创建管理员表单摆给一个
  // 其实已经有账号的实例，用户照着填就会以为在建第一个账号。此时关闭入口。
  const [unavailable, setUnavailable] = useState(false);

  useEffect(() => {
    api
      .authStatus()
      .then(({ initialized }) => {
        // 已有账号（含老单账号实例迁移出的 admin）就不再提供初始化入口。
        if (initialized) router.replace("/login");
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : "无法连接到后端服务");
        setUnavailable(true);
      })
      .finally(() => setChecking(false));
  }, [router]);

  // 校验规则与后端一致：用户名 2–64 字符且不含空格，密码至少 8 位。
  function validationError(): string {
    const name = username.trim();
    if (name.length < 2 || name.length > 64) return "用户名长度需为 2–64 个字符";
    if (/\s/.test(name)) return "用户名不能包含空格";
    if (password.length < 8) return "密码长度至少 8 位";
    if (password !== confirm) return "两次输入的密码不一致";
    return "";
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const invalid = validationError();
    if (invalid) {
      setError(invalid);
      return;
    }
    setLoading(true);
    setError("");
    try {
      const res = await api.initAdmin(username.trim(), password, displayName.trim());
      if (res.user) auth.setSession(res.token, res.user, res.user.is_admin ? ADMIN_PERMISSIONS : undefined);
      else auth.setToken(res.token); // NEXT_PUBLIC_MOCK 的 demo 只回 token
      router.replace("/function/tasks");
    } catch (err) {
      setError(err instanceof Error ? err.message : "创建管理员失败");
    } finally {
      setLoading(false);
    }
  }

  if (checking) return null;

  return (
    <div className="flex h-dvh">
      {/* Left panel */}
      <div className="hidden flex-col items-center justify-center bg-primary p-12 text-center lg:flex lg:w-1/3">
        <div className="relative flex items-center justify-center">
          <div className="absolute size-80 rounded-full border border-primary-foreground/10" />
          <div className="absolute size-60 rounded-full border border-primary-foreground/15" />
          <div className="absolute size-40 rounded-full border border-primary-foreground/20" />
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/logo.png" alt="SCA Audit" width={160} height={160} className="relative brightness-0 invert" />
        </div>
      </div>

      {/* Right panel */}
      <div className="flex w-full items-center justify-center bg-background p-8 lg:w-2/3">
        <div className="w-full max-w-md space-y-10 py-24 lg:py-32">
          <div className="space-y-4 text-center">
            <h2 className="text-2xl font-medium tracking-tight">
              {unavailable ? "无法确认初始化状态" : "创建管理员账号"}
            </h2>
            <p className="mx-auto max-w-xl text-muted-foreground">
              {unavailable
                ? "后端或数据库暂时不可用。为避免覆盖实例上已有的账号，初始化入口已临时关闭——请恢复服务后重试。"
                : "SCA Audit 是代码审计平台。首次使用，请创建第一个管理员账号（拥有全部管理权限）"}
            </p>
          </div>
          {unavailable ? (
            <div className="flex flex-col gap-4">
              {error && <p className="text-center text-sm text-destructive">{error}</p>}
              <Button type="button" className="w-full" onClick={() => window.location.reload()}>
                重试
              </Button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="flex flex-col gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="username">用户名</Label>
                <Input
                  id="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="2–64 个字符，不能包含空格"
                  autoFocus
                  autoComplete="username"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="display-name">显示名称</Label>
                <Input
                  id="display-name"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder="选填，用于界面展示"
                  autoComplete="nickname"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="password">密码</Label>
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="至少 8 位"
                  autoComplete="new-password"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="confirm">确认密码</Label>
                <Input
                  id="confirm"
                  type="password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  placeholder="再次输入密码"
                  autoComplete="new-password"
                />
              </div>
              {error && <p className="text-sm text-destructive">{error}</p>}
              <Button type="submit" className="w-full" disabled={loading || !username.trim() || !password || !confirm}>
                {loading ? "创建中..." : "创建管理员并登录"}
              </Button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
