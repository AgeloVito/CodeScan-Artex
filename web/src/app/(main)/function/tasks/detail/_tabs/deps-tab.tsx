"use client";

import * as React from "react";
import { BoxIcon, FileCodeIcon, PackageIcon, RefreshCwIcon, SparklesIcon, TriangleAlertIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { api } from "@/lib/api";
import type { TaskDependency, TaskDependencyList, TaskDepsImportEntry, TaskDepsImportResult } from "@/lib/types";
import { cn } from "@/lib/utils";

import { writeTitle } from "./read-only";

// 第三方依赖面板——见 docs/java-m2依赖读取与反编译方案.md。
//
// 这一页的核心是让「按需反编译」看得见：
//   - 上传只建清单与类名索引，**一个 jar 都不反编译**（所以初始全是「未反编译」）；
//   - 每个依赖单独一个「反编译」按钮，点了才跑，且只跑那一个 jar；
//   - 已经可读的显示文件数与来源（原始源码 / 反编译产物）。
// 不做批量反编译入口——那正是这个功能要避免的。
//
// 依赖的来源有两个：上传内含 jar 的 zip，或从服务器已配置的本地 Maven 仓库
// （~/.m2/repository）按坐标直接拉——后者同样只建清单与索引，不反编译。

function humanSize(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

/** 导入结果里「没进来」的条目：本地仓库没有 / 坐标不合法 / 版本无法解析 / 其它失败。 */
const IMPORT_PROBLEM_STATUSES: TaskDepsImportEntry["status"][] = [
  "not_found",
  "invalid",
  "unresolved_version",
  "error",
];

/** 逐条结果的短说明：后端给了 error 就用它，否则回落到状态本身的中文含义。 */
const IMPORT_STATUS_TEXT: Record<TaskDepsImportEntry["status"], string> = {
  imported: "已导入",
  already: "任务里已有",
  not_found: "本地仓库没有该坐标",
  invalid: "坐标不合法",
  unresolved_version: "版本无法解析（pom 里是属性占位符）",
  error: "导入失败",
};

/** 汇总一行，面板与 toast 共用同一份文案，避免两处说法不一致。 */
function importSummary(r: TaskDepsImportResult): string {
  return `导入 ${r.imported} 个 · 已存在 ${r.already_present} 个 · 未找到 ${r.not_found} 个 · 跳过 ${r.skipped} 个`;
}

function importProblems(r: TaskDepsImportResult): TaskDepsImportEntry[] {
  return r.results.filter((entry) => IMPORT_PROBLEM_STATUSES.includes(entry.status));
}

/** 源码状态徽标：未反编译是常态（中性色），可读才是「已完成」（绿色系）。 */
function SourceStateBadge({ dep }: { dep: TaskDependency }) {
  if (dep.corrupt) {
    return (
      <Badge variant="outline" className="border-destructive/40 text-destructive">
        非法 jar
      </Badge>
    );
  }
  if (dep.native_heavy) {
    return (
      <Badge variant="outline" className="text-muted-foreground">
        无 class
      </Badge>
    );
  }
  if (dep.source_state === "original") {
    return (
      <Badge variant="outline" className="border-emerald-500/40 text-emerald-600 dark:text-emerald-400">
        原始源码 · {dep.source_files}
      </Badge>
    );
  }
  if (dep.source_state === "decompiled") {
    return (
      <Badge variant="outline" className="border-sky-500/40 text-sky-600 dark:text-sky-400">
        反编译产物 · {dep.source_files}
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className="text-muted-foreground">
      未反编译
    </Badge>
  );
}

export function DepsTab({ taskId, canWrite }: { taskId: string; canWrite: boolean }) {
  const [data, setData] = React.useState<TaskDependencyList | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [uploading, setUploading] = React.useState(false);
  const [progress, setProgress] = React.useState(0);
  const [rescanning, setRescanning] = React.useState(false);
  // 正在反编译的依赖 id 集合（允许同时点几个，但每个都是独立的一次反编译）。
  const [busy, setBusy] = React.useState<Record<number, boolean>>({});
  // 本地 Maven 仓库导入：面板开关、坐标文本、是否连带扫 pom、进行中、上一次结果。
  const [importOpen, setImportOpen] = React.useState(false);
  const [gavText, setGavText] = React.useState("");
  const [scanSource, setScanSource] = React.useState(false);
  const [importing, setImporting] = React.useState(false);
  const [importResult, setImportResult] = React.useState<TaskDepsImportResult | null>(null);
  const fileRef = React.useRef<HTMLInputElement>(null);

  const load = React.useCallback(
    async (silent = false) => {
      if (!silent) setLoading(true);
      try {
        setData(await api.taskDeps(taskId));
        setError(null);
      } catch (e) {
        setError(e instanceof Error ? e.message : "读取依赖清单失败");
      } finally {
        if (!silent) setLoading(false);
      }
    },
    [taskId],
  );

  React.useEffect(() => {
    void load();
  }, [load]);

  // 一行一个坐标；trim + 丢空行（从 pom 或聊天里粘过来常带缩进与空行）。
  const gavs = gavText
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);

  async function onPickFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = ""; // 允许重复选同一个文件
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".zip")) {
      toast.error("依赖包需要是 .zip（里面放要审计的 jar）");
      return;
    }
    setUploading(true);
    setProgress(0);
    try {
      const r = await api.uploadTaskDeps(taskId, file, setProgress);
      toast.success(`已入库 ${r.jars} 个 jar，索引 ${r.indexed_class} 个类（未反编译任何 jar）`);
      await load(true);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "上传失败");
    } finally {
      setUploading(false);
      setProgress(0);
    }
  }

  async function onRescan() {
    setRescanning(true);
    try {
      const r = await api.rescanTaskDeps(taskId);
      toast.success(`已重新扫描 ${r.jars} 个 jar（未反编译）`);
      await load(true);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "重新扫描失败");
    } finally {
      setRescanning(false);
    }
  }

  // 从本地仓库导入：坐标文本与「扫 pom」至少有一个才有意义（按钮同样据此禁用）。
  async function onImport() {
    if (!gavs.length && !scanSource) return;
    setImporting(true);
    try {
      const r = await api.importTaskDeps(taskId, { gavs, scan_source: scanSource });
      // 结果留在面板里（坐标也保留），方便照着「未找到」改坐标重试。
      setImportResult(r);
      const line = importSummary(r);
      // 一个都没进来且确有失败条目时才用错误色，避免「全部已存在」被误报成失败。
      if (r.imported > 0 || importProblems(r).length === 0) toast.success(line);
      else toast.error(line);
      await load(true); // 清单变了：静默刷新，不把整页打回骨架屏
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "从本地仓库导入失败");
    } finally {
      setImporting(false);
    }
  }

  async function onMaterialize(dep: TaskDependency) {
    setBusy((b) => ({ ...b, [dep.id]: true }));
    const t = toast.loading(`正在反编译 ${dep.gav}…（只处理这一个 jar）`);
    try {
      const r = await api.materializeTaskDep(taskId, dep.id);
      const secs = (r.duration_ms / 1000).toFixed(1);
      toast.success(
        r.from_cache
          ? `${dep.gav} 源码已就绪（命中缓存，${r.files} 个文件）`
          : `${dep.gav} 反编译完成：${r.files} 个 .java / ${secs}s`,
        { id: t },
      );
      await load(true);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "反编译失败", { id: t });
    } finally {
      setBusy((b) => {
        const next = { ...b };
        delete next[dep.id];
        return next;
      });
    }
  }

  // ---- 加载中 ----
  if (loading) {
    return (
      <div className="flex flex-col gap-4">
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  // ---- 读取失败 ----
  if (error) {
    return (
      <Card>
        <CardContent className="flex items-center justify-between gap-4 py-6">
          <p className="text-destructive text-sm">{error}</p>
          <Button variant="outline" size="sm" onClick={() => void load()}>
            重试
          </Button>
        </CardContent>
      </Card>
    );
  }

  const deps = data?.deps ?? [];
  const decompileOk = data?.decompile_available ?? false;
  const problems = importResult ? importProblems(importResult) : [];
  const notes = importResult?.notes ?? [];

  return (
    <div className="flex flex-col gap-4">
      {/* 概览 + 上传 */}
      <Card className="gap-2">
        <CardHeader className="gap-1">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <div className="bg-primary/10 flex size-8 shrink-0 items-center justify-center rounded-lg">
                <PackageIcon className="text-primary size-4" />
              </div>
              <div className="flex flex-col">
                <CardTitle className="text-sm">第三方依赖</CardTitle>
                <CardDescription className="text-xs">
                  上传的 jar 只建清单与类名索引；源码按需单独反编译，默认一个都不反编译。
                </CardDescription>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <input
                ref={fileRef}
                type="file"
                accept=".zip"
                className="hidden"
                onChange={(e) => void onPickFile(e)}
              />
              <Tooltip>
                <TooltipTrigger asChild>
                  <span>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={!canWrite || uploading || rescanning}
                      title={writeTitle(canWrite, "重新扫描已上传的 jar（只重建清单与索引）")}
                      onClick={() => void onRescan()}
                    >
                      <RefreshCwIcon className={cn("size-4", rescanning && "animate-spin")} />
                      重新扫描
                    </Button>
                  </span>
                </TooltipTrigger>
                <TooltipContent>只重建清单与类名索引，不反编译</TooltipContent>
              </Tooltip>
              <Button
                variant="outline"
                size="sm"
                disabled={!canWrite || importing || !data?.local_repo_available}
                title={writeTitle(
                  canWrite,
                  data?.local_repo_available
                    ? "从服务器本地 Maven 仓库按坐标导入 jar（不用上传依赖包）"
                    : "未配置本地仓库（config.json 的 java.local_repo 或环境变量 ARTEX_JAVA_LOCAL_REPO）",
                )}
                onClick={() => setImportOpen(true)}
              >
                {importing ? <Spinner className="size-4" /> : <PackageIcon className="size-4" />}
                从本地仓库导入
              </Button>
              <Button
                size="sm"
                disabled={!canWrite || uploading}
                title={writeTitle(canWrite, "上传内含 jar 的 zip 依赖包")}
                onClick={() => fileRef.current?.click()}
              >
                {uploading ? <Spinner className="size-4" /> : <BoxIcon className="size-4" />}
                {uploading ? `上传中 ${progress}%` : "上传依赖包"}
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="pt-1">
          <div className="text-muted-foreground flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
            <span>
              依赖 <span className="text-foreground font-medium">{deps.length}</span> 个
            </span>
            <span>
              类索引 <span className="text-foreground font-medium">{data?.total_classes ?? 0}</span> 个类
            </span>
            <span>
              已可读源码 <span className="text-foreground font-medium">{data?.materialized ?? 0}</span> 个
            </span>
            <span className="inline-flex items-center gap-1">
              <SparklesIcon className="size-3" />
              反编译引擎：
              <span className={cn("font-medium", decompileOk ? "text-foreground" : "text-amber-600 dark:text-amber-400")}>
                {data?.engine || "unknown"}
              </span>
            </span>
            {/* 本地仓库：路径直接摆出来，排查「导入按钮为什么点不动」时不用去翻配置。 */}
            {data?.local_repo_available ? (
              <span className="inline-flex min-w-0 max-w-[320px] items-center gap-1">
                本地仓库
                <span className="truncate font-mono text-foreground" title={data.local_repo}>
                  {data.local_repo}
                </span>
              </span>
            ) : (
              <span className="text-muted-foreground">本地仓库 未配置</span>
            )}
          </div>
          {/* 本地仓库导入：内联展开而不是弹窗——坐标要跟下面的清单对着看，弹窗会挡住它。 */}
          {importOpen && (
            <div className="mt-3 flex flex-col gap-2.5 rounded-lg border bg-muted/30 p-3">
              <Textarea
                className="min-h-20 bg-background font-mono text-xs"
                rows={5}
                value={gavText}
                disabled={importing}
                onChange={(e) => setGavText(e.target.value)}
                placeholder="一行一个 Maven 坐标，例如 org.apache.logging.log4j:log4j-core:2.17.0"
              />
              <label htmlFor="deps-import-scan-source" className="flex items-center gap-2 text-xs">
                <Checkbox
                  id="deps-import-scan-source"
                  checked={scanSource}
                  disabled={importing}
                  onCheckedChange={(v) => setScanSource(!!v)}
                />
                同时扫描本任务源码里的 pom.xml，自动补全直接依赖
              </label>
              <div className="flex items-center gap-2">
                <Button
                  size="sm"
                  disabled={importing || (!gavs.length && !scanSource)}
                  title={
                    !gavs.length && !scanSource
                      ? "填一个坐标，或勾选扫描 pom.xml"
                      : "从本地仓库拉取 jar（只建清单与索引，不反编译）"
                  }
                  onClick={() => void onImport()}
                >
                  {importing ? <Spinner className="size-4" /> : <PackageIcon className="size-4" />}
                  {importing ? "导入中…" : "开始导入"}
                </Button>
                <Button variant="ghost" size="sm" disabled={importing} onClick={() => setImportOpen(false)}>
                  取消
                </Button>
              </div>
              {importResult && (
                <div className="flex flex-col gap-1 border-t pt-2">
                  <span className="text-muted-foreground text-xs">{importSummary(importResult)}</span>
                  <span className="text-[11px] text-muted-foreground">
                    任务现有 {importResult.dependencies} 个依赖 · 索引 {importResult.indexed_class} 个类
                    {importResult.scanned_poms > 0 && ` · 扫描 ${importResult.scanned_poms} 个 pom.xml`}
                  </span>
                  {/* 失败条目最多列 8 条：够改坐标重试，又不会把卡片撑成一屏。 */}
                  {problems.length > 0 && (
                    <ul className="flex flex-col gap-0.5">
                      {problems.slice(0, 8).map((entry) => (
                        <li
                          key={`${entry.gav}:${entry.status}`}
                          className={cn(
                            "flex items-baseline gap-1.5 text-[11px]",
                            entry.status === "error" ? "text-destructive" : "text-amber-600 dark:text-amber-400",
                          )}
                        >
                          <span className="max-w-[45%] shrink-0 truncate font-mono" title={entry.gav}>
                            {entry.gav}
                          </span>
                          <span className="min-w-0 flex-1">{entry.error || IMPORT_STATUS_TEXT[entry.status]}</span>
                        </li>
                      ))}
                      {problems.length > 8 && (
                        <li className="text-[11px] text-muted-foreground">等 {problems.length - 8} 条</li>
                      )}
                    </ul>
                  )}
                  {notes.length > 0 && (
                    <ul className="flex flex-col gap-0.5 text-[11px] text-muted-foreground">
                      {notes.map((note) => (
                        <li key={note}>{note}</li>
                      ))}
                    </ul>
                  )}
                </div>
              )}
            </div>
          )}
          {!decompileOk && deps.length > 0 && (
            <div className="border-amber-500/30 bg-amber-500/5 text-amber-700 dark:text-amber-400 mt-3 flex items-start gap-2 rounded-lg border px-3 py-2 text-xs">
              <TriangleAlertIcon className="mt-0.5 size-3.5 shrink-0" />
              <span>
                当前环境没有可用的反编译器（需要 JRE 17+ 与 Vineflower，或 JRE 6+ 与 CFR）。
                依赖清单与类名索引仍然可用；如需反编译，请把 <code className="font-mono">cfr-*.jar</code> 放到{" "}
                <code className="font-mono">data/tools/</code>，或在 config.json 里配置{" "}
                <code className="font-mono">java.cfr_jar</code>。
              </span>
            </div>
          )}
        </CardContent>
      </Card>

      {/* 清单 */}
      {deps.length === 0 ? (
        <Card>
          <CardContent className="py-2">
            <Empty className="border-0">
              <EmptyHeader>
                <EmptyMedia variant="icon">
                  <PackageIcon />
                </EmptyMedia>
                <EmptyTitle>还没有上传依赖</EmptyTitle>
                <EmptyDescription>
                  要审计 Java 项目的第三方依赖，先上传一个内含 jar 的 zip。可以在项目里执行{" "}
                  <code className="font-mono text-xs">mvn dependency:copy-dependencies -DoutputDirectory=deps-jars</code>
                  ，把 <code className="font-mono text-xs">deps-jars</code> 打包上传；如果有{" "}
                  <code className="font-mono text-xs">-sources.jar</code> 一并放进去，就能免反编译直接读原始源码。
                </EmptyDescription>
              </EmptyHeader>
            </Empty>
          </CardContent>
        </Card>
      ) : (
        <Card className="gap-0 overflow-hidden py-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="min-w-[260px]">坐标</TableHead>
                <TableHead className="w-[90px]">类数</TableHead>
                <TableHead className="w-[90px]">大小</TableHead>
                <TableHead className="w-[150px]">源码状态</TableHead>
                <TableHead className="w-[110px] text-right">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {deps.map((dep) => {
                const canDo = canWrite && dep.can_materialize && decompileOk;
                const isBusy = !!busy[dep.id];
                const readable = dep.source_state !== "none";
                return (
                  <TableRow key={dep.id}>
                    <TableCell>
                      <div className="flex min-w-0 flex-col gap-0.5">
                        <span className="truncate font-mono text-xs" title={dep.gav}>
                          {dep.gav}
                        </span>
                        <span className="text-muted-foreground flex flex-wrap items-center gap-x-2 text-[11px]">
                          {dep.scope && <span>{dep.scope}</span>}
                          {dep.direct && <span>直接依赖</span>}
                          {/* 坐标是猜出来的（文件名解析）时明确标注，避免被当成权威坐标。 */}
                          {dep.gav_source === "filename" && <span className="text-amber-600 dark:text-amber-400">坐标来自文件名</span>}
                          {dep.source_path && (
                            <span className="truncate font-mono" title={dep.source_path}>
                              {dep.source_path}
                            </span>
                          )}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell className="text-muted-foreground text-xs tabular-nums">
                      {dep.class_count > 0 ? dep.class_count : "—"}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-xs tabular-nums">{humanSize(dep.size_bytes)}</TableCell>
                    <TableCell>
                      <SourceStateBadge dep={dep} />
                    </TableCell>
                    <TableCell className="text-right">
                      {readable ? (
                        <span className="text-muted-foreground inline-flex items-center gap-1 text-xs">
                          <FileCodeIcon className="size-3.5" />
                          可读
                        </span>
                      ) : (
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span>
                              <Button
                                variant="outline"
                                size="sm"
                                className="h-7 px-2 text-xs"
                                disabled={!canDo || isBusy}
                                title={writeTitle(
                                  canWrite,
                                  dep.native_heavy
                                    ? "该 jar 没有 class 文件，无需反编译"
                                    : dep.corrupt
                                      ? "该 jar 不是合法 zip，无法反编译"
                                      : !decompileOk
                                        ? "当前环境没有可用的反编译器"
                                        : "只反编译这一个 jar",
                                )}
                                onClick={() => void onMaterialize(dep)}
                              >
                                {isBusy ? <Spinner className="size-3.5" /> : <SparklesIcon className="size-3.5" />}
                                {isBusy ? "反编译中" : "反编译"}
                              </Button>
                            </span>
                          </TooltipTrigger>
                          <TooltipContent>
                            {dep.native_heavy
                              ? "没有 class 文件（本地库/平台包）"
                              : dep.corrupt
                                ? "不是合法 zip"
                                : "只反编译这一个 jar，产物写到 deps/src/"}
                          </TooltipContent>
                        </Tooltip>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* 说明：把「为什么默认不反编译」讲清楚，避免用户以为功能坏了 */}
      {deps.length > 0 && (
        <p className="text-muted-foreground px-1 text-xs">
          反编译一个 jar 通常要几十秒（实测 1.7&nbsp;MB 的 log4j-core 约 40~60 秒），所以这里不提供「全部反编译」。
          审计 agent 也是同一个约束：它会先查 <code className="font-mono">deps/index/classes.txt</code> 定位类名，
          再只对确有必要的那一个依赖按需反编译。
        </p>
      )}
    </div>
  );
}
