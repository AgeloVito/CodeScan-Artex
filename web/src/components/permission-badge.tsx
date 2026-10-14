import { cn } from "@/lib/utils";

// 接口所需权限的色调映射。与「测试资产 → 接口」页保持同一套配色，保证同一个权限
// 在发现列表、漏洞详情、任务总览里看起来完全一致。
const PERMISSION_TONE: { match: RegExp; className: string }[] = [
  { match: /内部/, className: "bg-red-100 text-red-700" },
  { match: /管理员|超级|root|admin/i, className: "bg-orange-100 text-orange-700" },
  { match: /登录用户|注册用户|用户/, className: "bg-amber-100 text-amber-700" },
  { match: /公开|匿名|无需/, className: "bg-emerald-100 text-emerald-700" },
  { match: /其他/, className: "bg-slate-100 text-slate-600" },
];

export const PERMISSION_OPTIONS = ["公开", "注册用户", "登录用户", "管理员权限", "内部接口", "其他"] as const;

// PermissionBadge 展示复现漏洞所需的权限。空值按「未标注」处理，不猜成「公开」——
// 未判定权限的接口不等于公开接口。
export function PermissionBadge({
  permission,
  className,
  emptyText = "未标注权限",
}: {
  permission?: string;
  className?: string;
  emptyText?: string;
}) {
  const value = (permission ?? "").trim();
  if (!value) {
    return <span className={cn("text-xs text-muted-foreground", className)}>{emptyText}</span>;
  }
  const tone = PERMISSION_TONE.find((t) => t.match.test(value));
  return (
    <span
      className={cn(
        "inline-block max-w-[10rem] truncate rounded px-1.5 py-0.5 text-[11px] font-medium leading-none",
        tone?.className ?? "bg-muted text-muted-foreground",
        className,
      )}
      title={value}
    >
      {value}
    </span>
  );
}
