"use client";

import * as React from "react";

import {
  AlertCircleIcon,
  Building2Icon,
  KeyRoundIcon,
  PencilIcon,
  PlusIcon,
  RefreshCwIcon,
  Trash2Icon,
  UsersIcon,
} from "lucide-react";
import { toast } from "sonner";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import { auth } from "@/lib/auth";
import type {
  Department,
  DepartmentMembership,
  DepartmentMembershipInput,
  DepartmentRole,
  UserAccount,
} from "@/lib/types";
import { cn } from "@/lib/utils";

const ROLE_LABEL: Record<DepartmentRole, string> = { owner: "所有者", visitor: "访客" };
const ROLE_HINT: Record<DepartmentRole, string> = {
  owner: "可对话 / 建任务 / 暂停删除任务",
  visitor: "只读，不能对话、不能建任务",
};

function fmtTime(ts?: string | null): string {
  if (!ts) return "从未登录";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// 就地报错：所有失败都写在对话框内部，不用 window.alert。
function FormError({ message }: { message: string }) {
  if (!message) return null;
  return (
    <div
      role="alert"
      className="border-destructive/40 bg-destructive/5 text-destructive flex items-start gap-1.5 rounded-md border px-2.5 py-1.5 text-xs"
    >
      <AlertCircleIcon className="mt-px size-3.5 shrink-0" />
      <span className="min-w-0 break-words">{message}</span>
    </div>
  );
}

// 所属部门：每个成员关系一个 chip，形如「研发中心（所有者）」。
function DepartmentChips({ memberships }: { memberships?: DepartmentMembership[] }) {
  const list = memberships ?? [];
  if (list.length === 0) {
    return <span className="text-muted-foreground text-xs">未分配部门</span>;
  }
  return (
    // max-w 放在内层 div 上：td 的 max-width 在表格自动布局下不总是生效，
    // 内层限宽 + flex-wrap 才能保证部门多时换行而不是把表格撑宽。
    <div className="flex max-w-[22rem] flex-wrap items-center gap-1">
      {list.map((m) => (
        <Badge
          key={m.department_id}
          variant="outline"
          className={cn(
            "font-normal",
            m.role === "owner"
              ? "border-sky-400 text-sky-600 dark:text-sky-400"
              : "text-muted-foreground",
          )}
          title={ROLE_HINT[m.role] ?? undefined}
        >
          {m.department_name}
          <span className="ml-0.5">（{ROLE_LABEL[m.role] ?? m.role}）</span>
        </Badge>
      ))}
    </div>
  );
}

function RoleBadge({ isAdmin }: { isAdmin: boolean }) {
  return isAdmin ? <Badge>管理员</Badge> : <Badge variant="secondary">普通用户</Badge>;
}

export default function UsersPage() {
  const [users, setUsers] = React.useState<UserAccount[]>([]);
  const [departments, setDepartments] = React.useState<Department[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [loadError, setLoadError] = React.useState("");
  // 当前登录账号 id（后端拒绝删除自己，这里先把按钮标出来）。
  const [meId, setMeId] = React.useState("");

  // 新建账号
  const [createOpen, setCreateOpen] = React.useState(false);
  const [cUsername, setCUsername] = React.useState("");
  const [cDisplayName, setCDisplayName] = React.useState("");
  const [cPassword, setCPassword] = React.useState("");
  const [cAdmin, setCAdmin] = React.useState(false);
  const [createBusy, setCreateBusy] = React.useState(false);
  const [createError, setCreateError] = React.useState("");

  // 编辑账号
  const [editing, setEditing] = React.useState<UserAccount | null>(null);
  const [eDisplayName, setEDisplayName] = React.useState("");
  const [eAdmin, setEAdmin] = React.useState(false);
  const [eEnabled, setEEnabled] = React.useState(true);
  const [ePassword, setEPassword] = React.useState("");
  const [editBusy, setEditBusy] = React.useState(false);
  const [editError, setEditError] = React.useState("");

  // 分配部门
  const [assigning, setAssigning] = React.useState<UserAccount | null>(null);
  const [assignMap, setAssignMap] = React.useState<Record<number, DepartmentRole>>({});
  const [assignBusy, setAssignBusy] = React.useState(false);
  const [assignError, setAssignError] = React.useState("");

  // 删除账号
  const [pendingDelete, setPendingDelete] = React.useState<UserAccount | null>(null);
  const [deleteBusy, setDeleteBusy] = React.useState(false);
  const [deleteError, setDeleteError] = React.useState("");

  React.useEffect(() => {
    setMeId(auth.getCurrentUser()?.id ?? "");
  }, []);

  const load = React.useCallback(async () => {
    setLoading(true);
    setLoadError("");
    const problems: string[] = [];
    // 两个接口分开 try：部门拉不到只该影响「分配部门」，不该把账号表一起标成失败。
    try {
      setUsers(await api.users());
    } catch (e) {
      problems.push("账号列表：" + (e as Error).message);
    }
    try {
      setDepartments(await api.departments());
    } catch (e) {
      problems.push("部门列表：" + (e as Error).message);
    }
    setLoadError(problems.length > 0 ? "读取数据失败（" + problems.join("；") + "）" : "");
    setLoading(false);
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  // ── 新建 ────────────────────────────────────────────────────────────────
  function openCreate() {
    setCUsername("");
    setCDisplayName("");
    setCPassword("");
    setCAdmin(false);
    setCreateError("");
    setCreateOpen(true);
  }

  async function submitCreate() {
    const username = cUsername.trim();
    if (!username) {
      setCreateError("请填写用户名。");
      return;
    }
    if (!cPassword) {
      setCreateError("请填写初始密码。");
      return;
    }
    setCreateBusy(true);
    setCreateError("");
    try {
      await api.createUser({
        username,
        password: cPassword,
        displayName: cDisplayName.trim() || undefined,
        isAdmin: cAdmin,
      });
      toast.success(`已创建账号：${username}`);
      setCreateOpen(false);
      await load();
    } catch (e) {
      setCreateError("创建失败：" + (e as Error).message);
    } finally {
      setCreateBusy(false);
    }
  }

  // ── 编辑 ────────────────────────────────────────────────────────────────
  function openEdit(u: UserAccount) {
    setEditing(u);
    setEDisplayName(u.display_name ?? "");
    setEAdmin(!!u.is_admin);
    setEEnabled(!!u.enabled);
    setEPassword("");
    setEditError("");
  }

  async function submitEdit() {
    const u = editing;
    if (!u) return;
    // 只提交真正改动过的字段：undefined 表示「后端不改这一项」。
    const patch: { displayName?: string; isAdmin?: boolean; enabled?: boolean; password?: string } = {};
    const displayName = eDisplayName.trim();
    if (displayName !== (u.display_name ?? "")) patch.displayName = displayName;
    if (eAdmin !== !!u.is_admin) patch.isAdmin = eAdmin;
    if (eEnabled !== !!u.enabled) patch.enabled = eEnabled;
    if (ePassword) patch.password = ePassword;
    if (Object.keys(patch).length === 0) {
      setEditError("没有任何改动。");
      return;
    }
    setEditBusy(true);
    setEditError("");
    try {
      await api.updateUser(u.id, patch);
      toast.success(`已保存账号：${u.username}`);
      setEditing(null);
      await load();
    } catch (e) {
      setEditError("保存失败：" + (e as Error).message);
    } finally {
      setEditBusy(false);
    }
  }

  // ── 分配部门 ────────────────────────────────────────────────────────────
  function openAssign(u: UserAccount) {
    const map: Record<number, DepartmentRole> = {};
    for (const m of u.departments ?? []) map[m.department_id] = m.role;
    setAssignMap(map);
    setAssignError("");
    setAssigning(u);
  }

  function toggleAssignDept(id: number, on: boolean) {
    setAssignMap((prev) => {
      const next = { ...prev };
      if (on) next[id] = next[id] ?? "visitor";
      else delete next[id];
      return next;
    });
  }

  async function submitAssign() {
    const u = assigning;
    if (!u) return;
    const payload: DepartmentMembershipInput[] = Object.entries(assignMap).map(([id, role]) => ({
      department_id: Number(id),
      role,
    }));
    setAssignBusy(true);
    setAssignError("");
    try {
      await api.setUserDepartments(u.id, payload);
      toast.success(`已更新「${u.username}」的所属部门（${payload.length} 个）`);
      setAssigning(null);
      await load();
    } catch (e) {
      setAssignError("保存失败：" + (e as Error).message);
    } finally {
      setAssignBusy(false);
    }
  }

  // ── 删除 ────────────────────────────────────────────────────────────────
  function openDelete(u: UserAccount) {
    setDeleteError("");
    setPendingDelete(u);
  }

  async function submitDelete() {
    const u = pendingDelete;
    if (!u) return;
    setDeleteBusy(true);
    setDeleteError("");
    try {
      await api.deleteUser(u.id);
      toast.success(`已删除账号：${u.username}`);
      setPendingDelete(null);
      await load();
    } catch (e) {
      // 后端会拒绝「删除最后一个管理员」和「删除自己」，把它的原话显示在确认框里。
      setDeleteError((e as Error).message);
    } finally {
      setDeleteBusy(false);
    }
  }

  const assignCount = Object.keys(assignMap).length;

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">账号管理</h1>
          <p className="text-muted-foreground text-sm">
            管理员可管理账号与部门、可见全部任务；普通用户只看本部门任务 · 部门所有者可对话、建任务、暂停删除任务，部门访客只读
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
            <RefreshCwIcon className={cn("size-3.5", loading && "animate-spin")} />
            刷新
          </Button>
          <Button size="sm" onClick={openCreate}>
            <PlusIcon className="size-3.5" />
            新建账号
          </Button>
        </div>
      </div>

      <FormError message={loadError} />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">账号清单</CardTitle>
          <CardDescription>
            共 {users.length} 个账号 · 密码只在新建账号或编辑时重置，不在此处回显
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <p className="text-muted-foreground p-6 text-sm">加载中…</p>
          ) : users.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-2 py-16 text-center">
              <UsersIcon className="text-muted-foreground/40 size-8" />
              <p className="text-muted-foreground text-sm">
                {loadError ? "账号列表读取失败，请查看上方错误信息" : "暂无账号"}
              </p>
              {!loadError && (
                <Button size="sm" variant="outline" onClick={openCreate}>
                  <PlusIcon className="size-3.5" />
                  新建第一个账号
                </Button>
              )}
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>用户名</TableHead>
                  <TableHead>显示名称</TableHead>
                  <TableHead className="w-[100px]">角色</TableHead>
                  <TableHead>所属部门</TableHead>
                  <TableHead className="w-[80px]">状态</TableHead>
                  <TableHead className="w-[170px]">最近登录</TableHead>
                  <TableHead className="w-[130px] text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((u) => {
                  const isSelf = meId !== "" && String(u.id) === meId;
                  return (
                    <TableRow key={u.id} className={u.enabled ? undefined : "opacity-60"}>
                      <TableCell>
                        <div className="flex items-center gap-1.5">
                          <span className="font-medium">{u.username}</span>
                          {isSelf && (
                            <Badge variant="secondary" className="px-1.5 py-0 text-[10px]">
                              当前账号
                            </Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="text-muted-foreground max-w-[180px] truncate">
                        {u.display_name?.trim() || "—"}
                      </TableCell>
                      <TableCell>
                        <RoleBadge isAdmin={!!u.is_admin} />
                      </TableCell>
                      <TableCell className="max-w-[320px] whitespace-normal">
                        <DepartmentChips memberships={u.departments} />
                      </TableCell>
                      <TableCell>
                        {u.enabled ? (
                          <Badge
                            variant="outline"
                            className="border-emerald-400 text-emerald-600 dark:text-emerald-400"
                          >
                            启用
                          </Badge>
                        ) : (
                          <Badge variant="destructive">停用</Badge>
                        )}
                      </TableCell>
                      <TableCell className="text-muted-foreground text-xs">{fmtTime(u.last_login_at)}</TableCell>
                      <TableCell>
                        <div className="flex items-center justify-end gap-0.5">
                          <Button
                            size="icon-sm"
                            variant="ghost"
                            onClick={() => openEdit(u)}
                            title="编辑账号"
                            aria-label={`编辑账号「${u.username}」`}
                          >
                            <PencilIcon className="size-3.5" />
                          </Button>
                          <Button
                            size="icon-sm"
                            variant="ghost"
                            onClick={() => openAssign(u)}
                            title="分配部门"
                            aria-label={`分配账号「${u.username}」的所属部门`}
                          >
                            <Building2Icon className="size-3.5" />
                          </Button>
                          <Button
                            size="icon-sm"
                            variant="ghost"
                            className="text-destructive hover:text-destructive"
                            onClick={() => openDelete(u)}
                            title={isSelf ? "不能删除当前登录账号" : "删除账号"}
                            aria-label={`删除账号「${u.username}」`}
                          >
                            <Trash2Icon className="size-3.5" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* ── 新建账号 ───────────────────────────────────────────────────── */}
      <Dialog
        open={createOpen}
        onOpenChange={(o) => {
          if (!createBusy) setCreateOpen(o);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>新建账号</DialogTitle>
            <DialogDescription>
              创建后用该账号登录 SCA Audit。部门归属可在创建后通过「分配部门」设置。
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-2">
            <div className="grid gap-1.5">
              <Label htmlFor="u-new-name">用户名</Label>
              <Input
                id="u-new-name"
                placeholder="如 zhangsan"
                value={cUsername}
                onChange={(e) => setCUsername(e.target.value)}
                className="font-mono"
                autoComplete="off"
              />
              <p className="text-muted-foreground text-xs">登录用，创建后不可修改。</p>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="u-new-display">显示名称</Label>
              <Input
                id="u-new-display"
                placeholder="如 张三"
                value={cDisplayName}
                onChange={(e) => setCDisplayName(e.target.value)}
                autoComplete="off"
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="u-new-password">初始密码</Label>
              <Input
                id="u-new-password"
                type="password"
                placeholder="登录密码"
                value={cPassword}
                onChange={(e) => setCPassword(e.target.value)}
                autoComplete="new-password"
              />
            </div>
            <div className="flex items-center gap-2 text-sm">
              <Switch
                id="u-new-admin"
                checked={cAdmin}
                onCheckedChange={setCAdmin}
                aria-label="设为管理员"
              />
              <Label htmlFor="u-new-admin" className="cursor-pointer">
                管理员（可管理账号与部门、可见全部任务）
              </Label>
            </div>
            <FormError message={createError} />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)} disabled={createBusy}>
              取消
            </Button>
            <Button onClick={() => void submitCreate()} disabled={createBusy}>
              {createBusy ? "创建中…" : "创建"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── 编辑账号 ───────────────────────────────────────────────────── */}
      <Dialog
        open={!!editing}
        onOpenChange={(o) => {
          if (!o && !editBusy) setEditing(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>编辑账号{editing ? `「${editing.username}」` : ""}</DialogTitle>
            <DialogDescription>只提交改动过的项；密码留空表示不修改。</DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-2">
            <div className="grid gap-1.5">
              <Label htmlFor="u-edit-display">显示名称</Label>
              <Input
                id="u-edit-display"
                value={eDisplayName}
                onChange={(e) => setEDisplayName(e.target.value)}
                autoComplete="off"
              />
            </div>
            <div className="flex items-center gap-2 text-sm">
              <Switch id="u-edit-admin" checked={eAdmin} onCheckedChange={setEAdmin} aria-label="管理员" />
              <Label htmlFor="u-edit-admin" className="cursor-pointer">
                管理员（可管理账号与部门、可见全部任务）
              </Label>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <Switch id="u-edit-enabled" checked={eEnabled} onCheckedChange={setEEnabled} aria-label="启用账号" />
              <Label htmlFor="u-edit-enabled" className="cursor-pointer">
                启用（停用后该账号无法登录）
              </Label>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="u-edit-password">重置密码</Label>
              <Input
                id="u-edit-password"
                type="password"
                placeholder="留空则不修改"
                value={ePassword}
                onChange={(e) => setEPassword(e.target.value)}
                autoComplete="new-password"
              />
              <p className="text-muted-foreground flex items-center gap-1 text-xs">
                <KeyRoundIcon className="size-3" />
                填写后立即生效，旧密码失效。
              </p>
            </div>
            <FormError message={editError} />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditing(null)} disabled={editBusy}>
              取消
            </Button>
            <Button onClick={() => void submitEdit()} disabled={editBusy}>
              {editBusy ? "保存中…" : "保存"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── 分配部门（可多选，每个部门单独选角色）────────────────────────── */}
      <Dialog
        open={!!assigning}
        onOpenChange={(o) => {
          if (!o && !assignBusy) setAssigning(null);
        }}
      >
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>分配部门{assigning ? `：${assigning.username}` : ""}</DialogTitle>
            <DialogDescription>
              可多选。所有者可对话 / 建任务 / 暂停删除任务；访客只读。不选任何部门则该账号看不到任务。
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-2 py-2">
            {departments.length === 0 ? (
              <p className="text-muted-foreground rounded-md border border-dashed p-4 text-center text-xs">
                暂无部门，请先在「部门管理」中创建。
              </p>
            ) : (
              <div className="grid max-h-[50vh] gap-2 overflow-y-auto">
                {departments.map((d) => {
                  const role = assignMap[d.id];
                  const checked = role !== undefined;
                  return (
                    <div
                      key={d.id}
                      className="flex flex-wrap items-center gap-2 rounded-md border px-2.5 py-2"
                    >
                      <label className="flex min-w-0 flex-1 cursor-pointer items-center gap-2 text-sm">
                        <Checkbox
                          checked={checked}
                          onCheckedChange={(on) => toggleAssignDept(d.id, !!on)}
                          aria-label={`选择部门「${d.name}」`}
                        />
                        <span className="min-w-0 flex-1 truncate" title={d.name}>
                          {d.name}
                        </span>
                      </label>
                      {checked && (
                        <Select
                          value={role}
                          onValueChange={(v) => setAssignMap((prev) => ({ ...prev, [d.id]: v as DepartmentRole }))}
                        >
                          <SelectTrigger className="h-7 w-28 shrink-0" aria-label={`「${d.name}」中的角色`}>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="owner">所有者</SelectItem>
                            <SelectItem value="visitor">访客</SelectItem>
                          </SelectContent>
                        </Select>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
            <p className="text-muted-foreground text-xs">已选 {assignCount} 个部门。</p>
            <FormError message={assignError} />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAssigning(null)} disabled={assignBusy}>
              取消
            </Button>
            <Button onClick={() => void submitAssign()} disabled={assignBusy || departments.length === 0}>
              {assignBusy ? "保存中…" : "保存"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── 删除确认 ───────────────────────────────────────────────────── */}
      <AlertDialog
        open={!!pendingDelete}
        onOpenChange={(o) => {
          if (!o && !deleteBusy) setPendingDelete(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>删除账号{pendingDelete ? `「${pendingDelete.username}」` : ""}？</AlertDialogTitle>
            <AlertDialogDescription>
              删除后该账号立即失效，其部门归属一并移除。此操作不可撤销。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <FormError message={deleteError} />
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteBusy}>取消</AlertDialogCancel>
            <AlertDialogAction
              disabled={deleteBusy}
              onClick={(e) => {
                // 交给 submitDelete 处理：失败时保持确认框打开，好让后端原话留在屏幕上。
                e.preventDefault();
                void submitDelete();
              }}
            >
              {deleteBusy ? "删除中…" : "删除"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
