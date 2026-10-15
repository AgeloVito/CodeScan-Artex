"use client";

import * as React from "react";

import { PencilIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { FindingPackets } from "@/lib/types";

// FindingPacketComposer 是「还没有报文的接口」的人工补写入口。
//
// 空槽位此前只有一句「或在此人工补写」，却没有任何编辑器——而 PATCH
// /api/exploration/findings/{id}/packets/{assetID} 本来就是 upsert，创建是支持的。
// 这里把它补上：按接口写入，保存后用后端返回的覆盖度整体刷新，页面不自己维护两份状态。
//
// 写入的仍然是非证据的复测用例（服务端会重新校验并回传逐条结论），
// 所以这里不做任何本地校验之外的判断——格式问题交给服务端暴露，人再决定用不用。
export function FindingPacketComposer({
  findingId,
  assetId,
  assetLabel,
  contextTask,
  onChanged,
}: {
  findingId: string;
  assetId: string;
  assetLabel: string;
  contextTask?: string;
  onChanged: (next: FindingPackets) => void;
}) {
  const [open, setOpen] = React.useState(false);
  const [raw, setRaw] = React.useState("");
  const [rawResponse, setRawResponse] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  async function save() {
    if (!raw.trim()) {
      toast.error("请求报文不能为空");
      return;
    }
    setBusy(true);
    try {
      const next = await api.saveFindingPacket(
        findingId,
        assetId,
        { raw_request: raw, raw_response: rawResponse },
        contextTask,
      );
      onChanged(next);
      setOpen(false);
      setRaw("");
      setRawResponse("");
      toast.success("已保存该接口的报文并重新校验");
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (!open) {
    return (
      <Button variant="outline" size="sm" onClick={() => setOpen(true)}>
        <PencilIcon data-icon="inline-start" />
        人工补写
      </Button>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <p className="text-xs text-muted-foreground">
        为 <span className="font-mono">{assetLabel || `接口 ${assetId}`}</span> 补写报文：路径与参数必须与这个接口一致，
        不要套用别的接口的正文；凭证写 <code className="font-mono">&lt;占位符&gt;</code>。
      </p>
      <Textarea
        value={raw}
        onChange={(event) => setRaw(event.target.value)}
        spellCheck={false}
        placeholder={"GET /api/user HTTP/1.1\nHost: app.example.com\nCookie: <会话 Cookie>\n\n"}
        className="min-h-56 font-mono text-xs"
        aria-label="请求报文"
      />
      <Textarea
        value={rawResponse}
        onChange={(event) => setRawResponse(event.target.value)}
        spellCheck={false}
        placeholder="可选：响应报文"
        className="min-h-32 font-mono text-xs"
        aria-label="响应报文"
      />
      <div className="flex items-center justify-end gap-1.5">
        <Button variant="ghost" size="sm" disabled={busy} onClick={() => setOpen(false)}>
          取消
        </Button>
        <Button size="sm" disabled={busy || !raw.trim()} onClick={() => void save()}>
          保存并重新校验
        </Button>
      </div>
    </div>
  );
}
