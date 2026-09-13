"use client";

import { Badge } from "@/components/ui/badge";
import { useHoldfast } from "@/components/holdfast-provider";
import { formatCommand, sessionCounts } from "@/lib/format";

export function SessionStrip() {
  const { session, reachable } = useHoldfast();
  if (!reachable && !session) {
    return (
      <div className="border-b border-border/70 bg-zinc-950/40 px-4 py-1.5 text-[12px] text-zinc-500 lg:px-6">
        No wrap session.
      </div>
    );
  }
  if (!session) {
    return (
      <div className="border-b border-border/70 bg-zinc-950/40 px-4 py-1.5 text-[12px] text-zinc-500 lg:px-6">
        No wrap session. Agents outside <span className="font-mono text-zinc-400">holdfast wrap</span> are not gated here.
      </div>
    );
  }

  const { allowed, denied, asked } = sessionCounts(session);

  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-border/70 bg-zinc-950/50 px-4 py-1.5 text-[12px] lg:px-6">
      <Badge variant="outline" className="h-5 rounded-sm font-mono text-[10px] uppercase tracking-wider text-zinc-400">
        wrap
      </Badge>
      {session.pid != null ? (
        <span className="font-mono text-zinc-300">
          pid {session.pid}
        </span>
      ) : null}
      <span className="min-w-0 truncate font-mono text-zinc-200">
        {formatCommand(session.command)}
      </span>
      <span className="ml-auto flex items-center gap-3 font-mono tabular-nums text-zinc-500">
        <span>
          allowed <span className="text-zinc-200">{allowed}</span>
        </span>
        <span>
          denied <span className="text-zinc-200">{denied}</span>
        </span>
        <span>
          asked <span className="text-zinc-200">{asked}</span>
        </span>
      </span>
    </div>
  );
}
