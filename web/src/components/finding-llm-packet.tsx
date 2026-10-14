"use client";

import * as React from "react";

import { DownloadIcon, PencilIcon, SparklesIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { HttpCodeBlock } from "@/components/http-code-block";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { FindingPacket, FindingPackets } from "@/lib/types";

// LlmRetestPacketView 展示「由模型依据源码推演」的复测报文。
//
// 它必须一眼就能和真实抓包区分开：报文从未真正发送过，取值来自源码推演与假设，
// 只能当复测用例用。所以这里固定展示「AI 推演 / 非证据」标识、校验结论、
// 源码依据与假设，并把人工修订入口放在同一张卡片里。
//
// 一份报文只对应一个接口（packet.asset_id）：修订/清除都按接口下发，
// 不会连带改掉同一个漏洞其它接口的报文。
export function LlmRetestPacketView({
  findingId,
  packet,
  contextTask,
  onChanged,
}: {
  findingId: string;
  packet: FindingPacket;
  contextTask?: string;
  onChanged: (next: FindingPackets) => void;
}) {
  const [editing, setEditing] = React.useState(false);
  const [draft, setDraft] = React.useState(packet.raw_request);
  const [draftResponse, setDraftResponse] = React.useState(packet.raw_response ?? "");
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    setDraft(packet.raw_request);
    setDraftResponse(packet.raw_response ?? "");
  }, [packet]);

  const errors = packet.validation.errors ?? [];
  const warnings = packet.validation.warnings ?? [];

  async function save() {
    setBusy(true);
    try {
      const next = await api.saveFindingPacket(
        findingId,
        packet.asset_id,
        { raw_request: draft, raw_response: draftResponse },
        contextTask,
      );
      onChanged(next);
      setEditing(false);
      toast.success("报文已保存并重新校验");
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    setBusy(true);
    try {
      await api.deleteFindingPacket(findingId, packet.asset_id, contextTask);
      // 删除只影响这一份；重新拉一次列表，让接口槽位回到「未生成」。
      const next = await api.findingPackets(findingId, contextTask);
      onChanged(next);
      toast.success("已清除该接口的推演报文");
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <Alert>
        <SparklesIcon />
        <AlertTitle className="flex flex-wrap items-center gap-1.5">
          AI 推演报文（未实际发送）
          <Badge variant="outline">非抓包证据</Badge>
          {packet.source === "manual" ? (
            <Badge variant="secondary">人工修订</Badge>
          ) : (
            <Badge variant="secondary">LLM 生成</Badge>
          )}
          {packet.valid ? <Badge variant="outline">校验通过</Badge> : <Badge variant="destructive">未通过校验</Badge>}
        </AlertTitle>
        <AlertDescription>
          平台不抓包：这份报文由模型依据源码与已登记接口推演，取值可能包含假设，<strong>不能作为漏洞证据</strong>
          ，请人工核对后再用于复测。
          {packet.generator ? ` 生成者：${packet.generator}` : ""}
          {packet.revision > 1 ? ` · 第 ${packet.revision} 版` : ""}
        </AlertDescription>
      </Alert>

      {errors.length > 0 ? (
        <Alert variant="destructive">
          <AlertDescription>
            <p className="font-medium">校验未通过（报文仍可用，但以下内容不可信）：</p>
            <ul className="mt-1 list-disc pl-4">
              {errors.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>
      ) : null}

      {warnings.length > 0 ? (
        <Alert>
          <AlertDescription>
            <p className="font-medium">需要人工确认：</p>
            <ul className="mt-1 list-disc pl-4">
              {warnings.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>
      ) : null}

      <div className="flex flex-wrap items-center justify-end gap-1.5">
        <Button
          variant="outline"
          size="sm"
          onClick={() => api.downloadFindingPacket(findingId, "request", packet.raw_request)}
        >
          <DownloadIcon data-icon="inline-start" />
          下载 .http
        </Button>
        <Button variant="outline" size="sm" disabled={busy} onClick={() => setEditing((value) => !value)}>
          <PencilIcon data-icon="inline-start" />
          {editing ? "取消修订" : "人工修订"}
        </Button>
        <Button variant="ghost" size="sm" disabled={busy} onClick={() => void remove()}>
          <Trash2Icon data-icon="inline-start" />
          清除
        </Button>
      </div>

      {editing ? (
        <div className="flex flex-col gap-2">
          <Textarea
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            spellCheck={false}
            className="min-h-56 font-mono text-xs"
            aria-label="请求报文"
          />
          <Textarea
            value={draftResponse}
            onChange={(event) => setDraftResponse(event.target.value)}
            spellCheck={false}
            placeholder="可选：响应报文"
            className="min-h-32 font-mono text-xs"
            aria-label="响应报文"
          />
          <div className="flex items-center justify-end gap-1.5">
            <Button variant="ghost" size="sm" disabled={busy} onClick={() => setEditing(false)}>
              取消
            </Button>
            <Button size="sm" disabled={busy || !draft.trim()} onClick={() => void save()}>
              保存并重新校验
            </Button>
          </div>
        </div>
      ) : (
        <HttpCodeBlock raw={packet.raw_request} />
      )}

      {packet.raw_response && !editing ? (
        <details className="rounded-md border">
          <summary className="cursor-pointer px-3 py-2 text-xs text-muted-foreground">
            预期响应（同为推演产物，仅供参考）
          </summary>
          <div className="px-3 pb-3">
            <HttpCodeBlock raw={packet.raw_response} />
          </div>
        </details>
      ) : null}

      {packet.grounded_refs.length > 0 ? (
        <div className="text-xs text-muted-foreground">
          <p className="font-medium text-foreground">源码依据</p>
          <ul className="mt-1 list-disc pl-4">
            {packet.grounded_refs.map((item) => (
              <li key={item} className="break-all font-mono">
                {item}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {packet.assumptions.length > 0 ? (
        <div className="text-xs text-muted-foreground">
          <p className="font-medium text-foreground">假设</p>
          <ul className="mt-1 list-disc pl-4">
            {packet.assumptions.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </>
  );
}
