"use client";

import * as React from "react";

import { ChevronDownIcon, ChevronRightIcon, DownloadIcon, InfoIcon, PackageOpenIcon } from "lucide-react";
import { toast } from "sonner";

import { LlmRetestPacketView } from "@/components/finding-llm-packet";
import { HttpCodeBlock } from "@/components/http-code-block";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import type {
  Finding,
  FindingPacket,
  FindingPacketInterface,
  FindingPackets,
  FindingRawPacket,
  FindingTraffic,
} from "@/lib/types";

const SIDES = ["request", "response"] as const;
type Side = (typeof SIDES)[number];

// 与「关联流量」卡片同一套用途措辞，避免同一个绑定在两处叫法不同。
const ROLE_LABELS: Record<string, string> = {
  baseline: "正常对照",
  proof: "漏洞证明",
  verification: "补充验证",
  supporting: "辅助证据",
};

function roleLabel(role: string) {
  return ROLE_LABELS[role] ?? role;
}

function fmtBytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

// 接口模板：漏洞没有绑定真实流量、也还没有任何推演报文时（纯代码审计结论很常见），
// 用锚定接口拼一份可直接粘贴的最小请求报文，至少把方法、路径、Host 和权限前提交代清楚。
function interfaceTemplate(finding: Finding): string | null {
  const label = (finding.interface ?? "").trim();
  if (!label) return null;
  const space = label.indexOf(" ");
  if (space <= 0) return null;
  const method = label.slice(0, space).toUpperCase();
  const url = label.slice(space + 1).trim();
  let path = url;
  let host = "";
  try {
    const parsed = new URL(url);
    host = parsed.host;
    path = `${parsed.pathname}${parsed.search}` || "/";
  } catch {
    // 非标准 URL：原样当作路径，Host 留空让使用者自己补。
  }
  const lines = [`${method} ${path} HTTP/1.1`];
  if (host) lines.push(`Host: ${host}`);
  lines.push("User-Agent: Mozilla/5.0 (artex-retest)");
  lines.push("Accept: */*");
  if (finding.permission) lines.push(`X-Required-Permission: ${finding.permission}`);
  lines.push("Cookie: <按所需权限准备会话 Cookie>");
  if (method !== "GET" && method !== "HEAD") {
    lines.push("Content-Type: application/json");
    lines.push("");
    lines.push("{}");
  } else {
    lines.push("");
  }
  return lines.join("\n");
}

// FindingRawPacketPanel 展示漏洞绑定的完整原始报文（起始行 + 头部 + 空行 + 正文），
// 用 HttpCodeBlock 渲染，自带「复制报文」按钮，可直接粘贴到 Repeater/curl 复测。
//
// 一个漏洞常常锚定多个接口（同一个漏洞方法被多个入口调用）。报文里写死了 Host、路径与
// 请求参数，**一份报文只可能对应一个接口**，所以这里按接口列槽位：每个接口各占一行，
// 没有报文的接口照样列出来并标注「未生成」。否则一份报文会被读成覆盖了全部涉及资产，
// 复测时就会漏测——这正是改造前的问题。
export function FindingRawPacketPanel({ finding, contextTask }: { finding: Finding; contextTask?: string }) {
  const findingId = finding.finding_id ?? "";
  const [traffic, setTraffic] = React.useState<FindingTraffic | null>(null);
  const [bindingId, setBindingId] = React.useState<string | null>(null);
  const [side, setSide] = React.useState<Side>("request");
  const [packet, setPacket] = React.useState<FindingRawPacket | null>(null);
  const [packets, setPackets] = React.useState<FindingPacket[]>([]);
  const [interfaces, setInterfaces] = React.useState<FindingPacketInterface[]>([]);
  const [packetsLoaded, setPacketsLoaded] = React.useState(false);
  const [openAsset, setOpenAsset] = React.useState<string | null>(null);
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [downloading, setDownloading] = React.useState(false);

  React.useEffect(() => {
    if (!findingId) return;
    let active = true;
    setTraffic(null);
    setError("");
    api
      .findingTraffic(findingId, contextTask)
      .then((value) => {
        if (!active) return;
        setTraffic(value);
        setBindingId(value.bindings[0]?.id ?? null);
      })
      .catch((e: Error) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [findingId, contextTask]);

  // 推演报文与真实流量并行读取：两者互不阻塞，
  // 展示时再按「真实抓包 > 推演报文 > 接口模板」的优先级取舍。
  // 一次读回全部报文与接口槽位，页面才能算出「还差几个接口」。
  React.useEffect(() => {
    if (!findingId) return;
    let active = true;
    setPackets([]);
    setInterfaces([]);
    setPacketsLoaded(false);
    setOpenAsset(null);
    api
      .findingPackets(findingId, contextTask)
      .then((value) => {
        if (!active) return;
        applyPackets(value);
        setPacketsLoaded(true);
      })
      .catch(() => {
        // 推演报文只是兜底展示：读不到时静默回退到接口模板，不打扰使用者。
        if (active) setPacketsLoaded(true);
      });
    return () => {
      active = false;
    };
    // applyPackets 是稳定的 setState 包装，无需进依赖。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [findingId, contextTask]);

  React.useEffect(() => {
    if (!findingId || !bindingId) {
      setPacket(null);
      return;
    }
    let active = true;
    setLoading(true);
    setError("");
    api
      .findingTrafficRaw(findingId, bindingId, side, contextTask)
      .then((value) => {
        if (active) setPacket(value);
      })
      .catch((e: Error) => {
        if (active) {
          setPacket(null);
          setError(e.message);
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [findingId, bindingId, side, contextTask]);

  function applyPackets(next: FindingPackets) {
    setPackets(next.packets);
    setInterfaces(next.interfaces);
  }

  const template = interfaceTemplate(finding);
  const binding = traffic?.bindings.find((b) => b.id === bindingId) ?? traffic?.bindings[0] ?? null;

  // 没有绑定流量时的兜底：有锚定接口就给出复测模板，否则说明无法生成。
  function renderWithoutTraffic() {
    if (!template) {
      return (
        <div className="flex flex-col items-center gap-1 py-6 text-center">
          <PackageOpenIcon className="size-6 text-muted-foreground" />
          <p className="text-sm text-muted-foreground">该漏洞没有绑定流量证据，也没有锚定接口，无法生成原始数据包。</p>
        </div>
      );
    }
    return (
      <>
        <Alert>
          <InfoIcon />
          <AlertDescription>
            该漏洞没有绑定真实流量，下面是按锚定接口生成的复测模板
            {finding.permission ? `（所需权限：${finding.permission}）` : ""}；请补齐 Cookie / 请求体后再发送。
          </AlertDescription>
        </Alert>
        <HttpCodeBlock raw={template} />
      </>
    );
  }

  // 当前方向的报文：加载中显示骨架，取不到时给出说明。
  function renderPacket() {
    if (loading && !packet) return <Skeleton className="h-40 w-full" />;
    if (packet) return <HttpCodeBlock raw={packet.raw} />;
    return <p className="text-sm text-muted-foreground">（未取到该方向的报文）</p>;
  }

  async function download() {
    if (!findingId || !bindingId) return;
    setDownloading(true);
    try {
      await api.downloadFindingTrafficRaw(findingId, bindingId, side, contextTask);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setDownloading(false);
    }
  }

  // 有绑定流量时：证据切换 + 请求/响应切换 + 完整报文。
  function renderTraffic() {
    if (!traffic) return null;
    return (
      <>
        {packets.length > 0 ? (
          <p className="text-xs text-muted-foreground">
            该漏洞另有 {packets.length} 份 AI 推演报文（非抓包证据，按接口各一份），此处优先展示真实抓包；
            清除绑定后才会回退到推演报文。
          </p>
        ) : null}
        {traffic.bindings.length > 1 ? (
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-xs text-muted-foreground">证据</span>
            {traffic.bindings.map((b, index) => (
              <Button
                key={b.id}
                variant={b.id === bindingId ? "secondary" : "ghost"}
                size="xs"
                onClick={() => setBindingId(b.id)}
              >
                #{index + 1} {b.snapshot.method} · {roleLabel(b.role)}
              </Button>
            ))}
          </div>
        ) : null}

        <Tabs value={side} onValueChange={(value) => setSide(value as Side)}>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <TabsList>
              <TabsTrigger value="request">请求 Request</TabsTrigger>
              <TabsTrigger value="response">响应 Response</TabsTrigger>
            </TabsList>
            {packet ? (
              <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <Badge variant="outline">{fmtBytes(packet.bytes)}</Badge>
                {packet.truncated ? <Badge variant="outline">正文超 1 MB，已截断</Badge> : null}
                {packet.binary ? <Badge variant="outline">二进制正文</Badge> : null}
              </div>
            ) : null}
          </div>
          {SIDES.map((value) => (
            <TabsContent key={value} value={value} className="mt-2">
              {value === side ? renderPacket() : null}
            </TabsContent>
          ))}
        </Tabs>
        {binding ? (
          <p className="text-xs text-muted-foreground">
            {binding.snapshot.method} {binding.snapshot.url} · HTTP {binding.snapshot.status}
            {packet?.truncated ? " · 正文超过 1 MB，请用「下载 .http」获取完整报文" : ""}
          </p>
        ) : null}
      </>
    );
  }

  // 一个接口槽位：有报文就展开看/改，没报文就明说「未生成」。
  function renderSlot(it: FindingPacketInterface, p: FindingPacket | null, single: boolean) {
    const open = single || openAsset === it.asset_id;
    const label = (
      <span className="flex min-w-0 items-center gap-1.5">
        {single ? null : open ? (
          <ChevronDownIcon className="size-3.5 shrink-0 text-muted-foreground" />
        ) : (
          <ChevronRightIcon className="size-3.5 shrink-0 text-muted-foreground" />
        )}
        <span className="truncate font-mono text-xs">{it.label}</span>
      </span>
    );
    return (
      <div key={it.asset_id} className={p ? "rounded-md border" : "rounded-md border border-dashed"}>
        <div className="flex flex-wrap items-center justify-between gap-2 px-3 py-2">
          {single ? (
            <div className="flex min-w-0 flex-1 items-center">{label}</div>
          ) : (
            <button
              type="button"
              className="flex min-w-0 flex-1 items-center text-left"
              onClick={() => setOpenAsset(open ? null : it.asset_id)}
            >
              {label}
            </button>
          )}
          <div className="flex shrink-0 items-center gap-1.5">
            {p ? (
              <>
                {p.valid ? null : <Badge variant="destructive">未通过校验</Badge>}
                <Badge variant="secondary">{p.source === "manual" ? "人工修订" : "AI 推演"}</Badge>
              </>
            ) : (
              <Badge variant="outline">未生成</Badge>
            )}
          </div>
        </div>
        {open ? (
          p ? (
            <div className="px-3 pb-3">
              <LlmRetestPacketView
                findingId={findingId}
                packet={p}
                contextTask={contextTask}
                onChanged={applyPackets}
              />
            </div>
          ) : (
            <p className="px-3 pb-3 text-xs text-muted-foreground">
              还没有这个接口的复测报文。可让复核 Agent 依据源码补一份，或在此人工补写——不要直接套用别的接口的报文，
              各接口的路径与传参并不相同。
            </p>
          )
        ) : null}
      </div>
    );
  }

  // 推演报文区：逐接口列槽位 + 覆盖度汇总。没有声明接口的那一份单独摆出来，
  // 它无法对应到任何一个涉及接口，不能混进接口列表里冒充「已覆盖」。
  function renderLlmPackets() {
    const byAsset = new Map(packets.filter((p) => p.asset_id !== "0").map((p) => [p.asset_id, p]));
    const unassigned = packets.find((p) => p.asset_id === "0") ?? null;
    const covered = interfaces.filter((it) => byAsset.has(it.asset_id)).length;
    const missing = interfaces.length - covered;
    const single = interfaces.length === 1;

    return (
      <>
        {interfaces.length > 0 ? (
          <>
            <Alert>
              <InfoIcon />
              <AlertDescription>
                报文里写死了 Host、路径与请求参数，<strong>一份报文只对应一个接口</strong>。请按接口逐个复测：
                某个接口有报文，不代表其它涉及接口也验证过了。
              </AlertDescription>
            </Alert>
            <div className="flex flex-wrap items-center gap-1.5">
              <Badge variant="outline">涉及接口 {interfaces.length}</Badge>
              <Badge variant="secondary">已生成 {covered}</Badge>
              {missing > 0 ? <Badge variant="destructive">未生成 {missing}</Badge> : null}
            </div>
          </>
        ) : null}

        {interfaces.map((it) => renderSlot(it, byAsset.get(it.asset_id) ?? null, single))}

        {unassigned ? (
          <div className="flex flex-col gap-2.5 rounded-md border border-dashed px-3 py-2.5">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-xs font-medium">未指定接口的报文</span>
              <Badge variant="destructive">未指定接口</Badge>
            </div>
            <p className="text-xs text-muted-foreground">
              这份报文没有声明它属于哪个接口，无法确认它对应哪一个涉及接口；请核对 Host 与路径后归位，不要当作已覆盖全部接口。
            </p>
            <LlmRetestPacketView
              findingId={findingId}
              packet={unassigned}
              contextTask={contextTask}
              onChanged={applyPackets}
            />
          </div>
        ) : null}
      </>
    );
  }

  // 主内容：没有独立记录 id / 还在加载 / 有真实抓包 / 有推演报文或接口槽位 / 退回复测模板。
  function renderBody() {
    if (!findingId) {
      return <p className="text-sm text-muted-foreground">该漏洞没有独立记录 ID，无法读取报文。</p>;
    }
    if (traffic === null || !packetsLoaded) return <Skeleton className="h-40 w-full" />;
    if (traffic.bindings.length > 0) return renderTraffic();
    if (interfaces.length > 0 || packets.length > 0) return renderLlmPackets();
    return renderWithoutTraffic();
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div className="flex flex-col gap-1">
            <CardTitle className="text-sm">原始数据包</CardTitle>
            <CardDescription className="text-xs">
              完整 HTTP 报文（起始行 + 头部 + 空行 + 正文），点右上角复制即可直接粘贴复测。优先展示真实抓包；
              没有抓包时按接口展示 AI 依据源码推演的报文（非证据），未生成的接口会明确标出。
            </CardDescription>
          </div>
          {traffic && traffic.bindings.length > 0 ? (
            <Button variant="outline" size="sm" onClick={() => void download()} disabled={downloading || !packet}>
              <DownloadIcon data-icon="inline-start" />
              下载 .http
            </Button>
          ) : null}
        </div>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {error ? <p className="text-sm text-destructive">{error}</p> : null}
        {renderBody()}
      </CardContent>
    </Card>
  );
}
