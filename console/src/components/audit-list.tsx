"use client";

import { useState } from "react";
import Link from "next/link";
import { DecisionBadge, KindBadge } from "@/components/status-badges";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { chainOf, formatAction, relativeTime, shortHash } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { AuditEvent } from "@/lib/types";

export function AuditRow({
  event,
  now,
  compact = false,
}: {
  event: AuditEvent;
  now: number;
  compact?: boolean;
}) {
  const chain = chainOf(event);
  const action = formatAction(event.kind, event.detail);
  const [open, setOpen] = useState(false);

  return (
    <div className={cn("border-b border-border/60 py-2.5 last:border-0", compact && "py-2")}>
      <button type="button" className="w-full text-left" onClick={() => setOpen(true)}>
        <div className="flex items-start justify-between gap-3">
          <div className="flex min-w-0 flex-wrap items-center gap-1.5">
            <KindBadge kind={event.kind} />
            <DecisionBadge decision={event.decision} />
            {event.op ? (
              <span className="font-mono text-[11px] uppercase text-zinc-500">{event.op}</span>
            ) : null}
          </div>
          <span className="shrink-0 font-mono text-[11px] text-zinc-500">
            {relativeTime(event.ts, now)}
          </span>
        </div>
        <p className="mt-1 truncate font-mono text-[12px] text-zinc-200">{action}</p>
        <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px] text-zinc-500">
          {event.actor ? <span>{event.actor}</span> : null}
          {event.pid != null ? <span className="font-mono">pid {event.pid}</span> : null}
          {chain.hash ? (
            <span className="font-mono text-zinc-600" title={chain.hash}>
              {shortHash(chain.hash)}
              {chain.prev ? ` ← ${shortHash(chain.prev)}` : ""}
            </span>
          ) : null}
        </div>
      </button>
      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent side="right" className="bg-zinc-950">
          <SheetHeader>
            <SheetTitle className="font-mono text-sm">{event.op || event.kind}</SheetTitle>
            <SheetDescription>
              {event.actor || "unknown actor"} · {event.decision || "—"}
            </SheetDescription>
          </SheetHeader>
          <div className="space-y-3 px-4 pb-4 font-mono text-[12px] text-zinc-300">
            <p className="whitespace-pre-wrap">{action}</p>
            {chain.hash ? (
              <p className="text-zinc-500 whitespace-pre-wrap">
                {`hash ${chain.hash}${chain.prev ? `\nprev ${chain.prev}` : ""}`}
              </p>
            ) : null}
            <pre className="overflow-x-auto rounded-md bg-zinc-900 p-3 text-[11px] text-zinc-400">
              {JSON.stringify(event.detail ?? {}, null, 2)}
            </pre>
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}

export function AuditPeek({ events, now }: { events: AuditEvent[]; now: number }) {
  return (
    <section className="flex h-full min-h-0 flex-col rounded-lg border border-border/80 bg-zinc-950/40">
      <div className="flex items-center justify-between border-b border-border/70 px-3 py-2">
        <h2 className="text-[13px] font-medium text-zinc-200">Recent decisions</h2>
        <Link href="/audit" className="text-[12px] text-zinc-500 hover:text-zinc-200">
          Full log
        </Link>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto px-3">
        {events.length === 0 ? (
          <p className="py-8 text-center text-[12px] text-zinc-500">No audit events yet.</p>
        ) : (
          events.slice(0, 20).map((event) => (
            <AuditRow key={`${event.id}-${event.ts}`} event={event} now={now} compact />
          ))
        )}
      </div>
    </section>
  );
}
