"use client";

import * as React from "react";

import {
  AlertCircleIcon,
  Building2Icon,
  PencilIcon,
  PlusIcon,
  RefreshCwIcon,
  ShieldCheckIcon,
  Trash2Icon,
  UserIcon,
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
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { Department, DepartmentMember, DepartmentRole } from "@/lib/types";
import { cn } from "@/lib/utils";

const ROLE_LABEL: Record<DepartmentRole, string> = { owner: "所有者", visitor: "访客" };

function fmtDate(ts?: string | null): string {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleDateString("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit" });
}

// 就地报错：不用 window.alert，失败信息留在触发它的对话框里。
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

function RoleBadge({ role }: { role: DepartmentRole }) {
  const owner = role === "owner";
  return (
    <Badge
      variant="outline"
      className={cn("font-normal", owner ? "border-sky-400 text-sky-600 dark:text-sky-400" : "text-muted-foreground")}
    >
      {ROLE_LABEL[role] ?? role}
    </Badge>
  );
}

export default function DepartmentsPage() {
  const [departments, setDepartments] = React.useState<Department[]>([]);
  // 后端没给 member_count 时，用 api.departmentMembers(id).length 补齐。
  const [memberCounts, setMemberCounts] = React.useState<Record<number, number>>({});
  const [loading, setLoading] = React.useState(true);
  const [loadError, setLoadError] = React.useState("");

  // 新建 / 重命名 + 改描述
  const [formOpen, setFormOpen] = React.useState(false);
  const [editing, setEditing] = React.useState<Department | null>(null);
  const [name, setName] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [formBusy, setFormBusy] = React.useState(false);
  const [formError, setFormError] = React.useState("");

  // 删除
  const [pendingDelete, setPendingDelete] = React.useState<Department | null>(null);
  const [deleteBusy, setDeleteBusy] = React.useState(false);
  const [deleteError, setDeleteError] = React.useState("");

  // 成员列表（侧边面板）
  const [viewing, setViewing] = React.useState<Department | null>(null);
  const [members, setMembers] = React.useState<DepartmentMember[]>([]);
  const [membersLoading, setMembersLoading] = React.useState(false);
  const [membersError, setMembersError] = React.useState("");

  const load = React.useCallback(async () => {
    setLoading(true);
    setLoadError("");
    try {
      const ds = await api.departments();
      setDepartments(ds);
      // member_count 缺失的部门逐个补数（读接口失败只让该卡片显示「—」，不影响整页）。
      const missing = ds.filter((d) => typeof d.member_count !== "number");
      if (missing.length > 0) {
        const pairs = await Promise.all(
          missing.map(async (d) => {
            try {
              return [d.id, (await api.departmentMembers(d.id)).length] as const;
            } catch {
              return [d.id, -1] as const;
            }
          }),
        );
        setMemberCounts((prev) => {
          const next = { ...prev };
          for (const [id, n] of pairs) {
            if (n >= 0) next[id] = n;
            else delete next[id];
          }
          return next;
        });
      }
    } catch (e) {
      setLoadError("读取部门列表失败：" + (e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  // 打开某个部门 → 拉它的成员列表（关闭时清空，避免下次打开先闪旧数据）。
  React.useEffect(() => {
    if (!viewing) {
      setMembers([]);
      setMembersError("");
      return;
    }
    const id = viewing.id;
    // cancelled 防止「关掉面板 / 换部门」后旧请求的结果再写回状态。
    let cancelled = false;
    setMembers([]);
    setMembersError("");
    setMembersLoading(true);
    api
      .departmentMembers(id)
      .then((ms) => {
        if (!cancelled) setMembers(ms);
      })
      .catch((e) => {
        if (!cancelled) setMembersError("读取成员列表失败：" + (e as Error).message);
      })
      .finally(() => {
        if (!cancelled) setMembersLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [viewing]);

  function memberCountOf(d: Department): string {
    if (typeof d.member_count === "number") return String(d.member_count);
    const n = memberCounts[d.id];
    return typeof n === "number" ? String(n) : "—";
  }

  // ── 新建 ────────────────────────────────────────────────────────────────
  function openCreate() {
    setEditing(null);
    setName("");
    setDescription("");
    setFormError("");
    setFormOpen(true);
  }

  // ── 重命名 / 改描述 ─────────────────────────────────────────────────────
  function openEdit(d: Department) {
    setEditing(d);
    setName(d.name);
    setDescription(d.description ?? "");
    setFormError("");
    setFormOpen(true);
  }

  async function submitForm() {
    const n = name.trim();
    if (!n) {
      setFormError("请填写部门名称。");
      return;
    }
    setFormBusy(true);
    setFormError("");
    try {
      if (editing) {
        await api.updateDepartment(editing.id, n, description.trim());
        toast.success(`已保存部门：${n}`);
      } else {
        await api.createDepartment(n, description.trim());
        toast.success(`已创建部门：${n}`);
      }
      setFormOpen(false);
      await load();
    } catch (e) {
      setFormError((editing ? "保存失败：" : "创建失败：") + (e as Error).message);
    } finally {
      setFormBusy(false);
    }
  }

  // ── 删除 ────────────────────────────────────────────────────────────────
  function openDelete(d: Department) {
    setDeleteError("");
    setPendingDelete(d);
  }

  async function submitDelete() {
    const d = pendingDelete;
    if (!d) return;
    setDeleteBusy(true);
    setDeleteError("");
    try {
      await api.deleteDepartment(d.id);
      toast.success(`已删除部门：${d.name}`);
      setPendingDelete(null);
      if (viewing?.id === d.id) setViewing(null);
      await load();
    } catch (e) {
      setDeleteError("删除失败：" + (e as Error).message);
    } finally {
      setDeleteBusy(false);
    }
  }

  // 面板标题里的成员数：列表读出来之后以列表长度为准，否则回落到清单里已知的数字。
  const viewingCount = viewing
    ? membersLoading || membersError
      ? memberCountOf(viewing)
      : String(members.length)
    : "—";

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">部门管理</h1>
          <p className="text-muted-foreground text-sm">
            部门是任务可见性与写权限的边界 · 管理员可见全部任务，普通用户只看本部门任务；部门所有者可对话、建任务、暂停删除任务，部门访客只读
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
            <RefreshCwIcon className={cn("size-3.5", loading && "animate-spin")} />
            刷新
          </Button>
          <Button size="sm" onClick={openCreate}>
            <PlusIcon className="size-3.5" />
            新建部门
          </Button>
        </div>
      </div>

      <FormError message={loadError} />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">部门清单</CardTitle>
          <CardDescription>共 {departments.length} 个部门 · 点击卡片查看成员列表与角色</CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <p className="text-muted-foreground py-6 text-center text-sm">加载中…</p>
          ) : departments.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-2 py-16 text-center">
              <Building2Icon className="text-muted-foreground/40 size-8" />
              <p className="text-muted-foreground text-sm">
                {loadError ? "部门列表读取失败，请查看上方错误信息" : "暂无部门"}
              </p>
              {!loadError && (
                <Button size="sm" variant="outline" onClick={openCreate}>
                  <PlusIcon className="size-3.5" />
                  新建第一个部门
                </Button>
              )}
            </div>
          ) : (
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {departments.map((d) => (
                <div
                  key={d.id}
                  className="hover:border-primary/50 flex flex-col gap-3 rounded-lg border p-4 transition-colors"
                >
                  {/* 卡片主体是可点的按钮：点部门名即看成员；操作按钮放在它外面，避免按钮嵌套。 */}
                  <button
                    type="button"
                    onClick={() => setViewing(d)}
                    aria-label={`查看部门「${d.name}」的成员列表`}
                    className="flex w-full flex-col gap-2 text-left"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <Building2Icon className="text-muted-foreground size-4 shrink-0" />
                      <span className="min-w-0 truncate font-medium" title={d.name}>
                        {d.name}
                      </span>
                      <Badge variant="secondary" className="px-1.5 py-0 text-[10px]">
                        成员 {memberCountOf(d)}
                      </Badge>
                    </div>
                    <p className="text-muted-foreground line-clamp-2 min-h-8 text-xs">
                      {d.description?.trim() || "（无描述）"}
                    </p>
                    <div className="text-muted-foreground flex flex-wrap gap-1.5 text-[10px]">
                      {typeof d.task_count === "number" && (
                        <span className="rounded border px-1.5 py-0.5">任务 {d.task_count}</span>
                      )}
                      <span className="rounded border px-1.5 py-0.5">创建 {fmtDate(d.created_at)}</span>
                    </div>
                  </button>

                  <div className="flex items-center gap-1.5">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => setViewing(d)}
                      aria-label={`查看部门「${d.name}」的成员`}
                    >
                      <UsersIcon className="size-3.5" />
                      成员
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => openEdit(d)}
                      aria-label={`重命名部门「${d.name}」或修改描述`}
                    >
                      <PencilIcon className="size-3.5" />
                      重命名
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="text-destructive hover:text-destructive ml-auto"
                      onClick={() => openDelete(d)}
                      aria-label={`删除部门「${d.name}」`}
                      title="删除部门"
                    >
                      <Trash2Icon className="size-3.5" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── 新建 / 重命名 + 改描述 ─────────────────────────────────────── */}
      <Dialog
        open={formOpen}
        onOpenChange={(o) => {
          if (!formBusy) setFormOpen(o);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{editing ? `编辑部门：${editing.name}` : "新建部门"}</DialogTitle>
            <DialogDescription>
              部门决定任务可见范围：普通用户只能看到本部门的任务，管理员可见全部任务。
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-2">
            <div className="grid gap-1.5">
              <Label htmlFor="d-name">部门名称</Label>
              <Input
                id="d-name"
                placeholder="如 研发中心"
                value={name}
                onChange={(e) => setName(e.target.value)}
                autoComplete="off"
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="d-desc">描述</Label>
              <Textarea
                id="d-desc"
                rows={2}
                className="resize-none"
                placeholder="这个部门负责什么"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>
            <FormError message={formError} />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setFormOpen(false)} disabled={formBusy}>
              取消
            </Button>
            <Button onClick={() => void submitForm()} disabled={formBusy}>
              {formBusy ? "保存中…" : editing ? "保存" : "创建"}
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
        <AlertDialogContent className="max-w-[min(28rem,calc(100vw-2rem))]">
          <AlertDialogHeader>
            <AlertDialogTitle>删除部门{pendingDelete ? `「${pendingDelete.name}」` : ""}？</AlertDialogTitle>
            <AlertDialogDescription>
              删除部门会同时移除该部门的全部成员关系，并把该部门从相关任务上清除（任务本身保留）。
              此操作不可撤销。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <FormError message={deleteError} />
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteBusy}>取消</AlertDialogCancel>
            <AlertDialogAction
              disabled={deleteBusy}
              onClick={(e) => {
                // 交给 submitDelete：失败时保持确认框打开，好让后端原话留在屏幕上。
                e.preventDefault();
                void submitDelete();
              }}
            >
              {deleteBusy ? "删除中…" : "删除"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* ── 成员列表侧边面板 ───────────────────────────────────────────── */}
      <Sheet
        open={!!viewing}
        onOpenChange={(o) => {
          if (!o) setViewing(null);
        }}
      >
        <SheetContent side="right" className="flex w-full flex-col gap-0 data-[side=right]:sm:max-w-md">
          <SheetHeader className="border-b px-4 pt-4 pb-3">
            <SheetTitle className="flex flex-wrap items-center gap-2">
              {viewing?.name ?? "部门成员"}
              <Badge variant="secondary" className="px-1.5 py-0 text-[10px]">
                成员 {viewingCount}
              </Badge>
            </SheetTitle>
            <SheetDescription className="text-xs">
              {viewing?.description?.trim() || "该部门暂无描述"} · 所有者可对话 / 建任务 / 暂停删除任务，访客只读
            </SheetDescription>
          </SheetHeader>

          <div className="min-h-0 flex-1 overflow-y-auto px-4 py-4">
            <FormError message={membersError} />
            {membersLoading ? (
              <p className="text-muted-foreground text-sm">加载中…</p>
            ) : members.length === 0 ? (
              <div className="flex flex-col items-center justify-center gap-2 py-16 text-center">
                <UsersIcon className="text-muted-foreground/40 size-8" />
                <p className="text-muted-foreground text-sm">该部门暂无成员</p>
                <p className="text-muted-foreground text-xs">可在「账号管理」的「分配部门」中把账号加入本部门。</p>
              </div>
            ) : (
              <ul className="grid gap-2">
                {members.map((m) => (
                  <li
                    key={m.user_id}
                    className={cn(
                      "flex flex-wrap items-center gap-2 rounded-md border px-2.5 py-2",
                      !m.enabled && "opacity-60",
                    )}
                  >
                    <UserIcon className="text-muted-foreground size-3.5 shrink-0" />
                    <span className="font-mono text-xs font-medium" title={m.username}>
                      {m.username}
                    </span>
                    <span className="text-muted-foreground min-w-0 flex-1 truncate text-xs" title={m.display_name}>
                      {m.display_name?.trim() || "—"}
                    </span>
                    <RoleBadge role={m.role} />
                    {m.is_admin && (
                      <Badge className="px-1.5 py-0 text-[10px]">
                        <ShieldCheckIcon className="size-3" />
                        管理员
                      </Badge>
                    )}
                    {!m.enabled && (
                      <Badge variant="destructive" className="px-1.5 py-0 text-[10px]">
                        停用
                      </Badge>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}
