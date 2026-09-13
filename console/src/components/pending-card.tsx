"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardFooter, CardHeader } from "@/components/ui/card";
import { KindBadge } from "@/components/status-badges";
import { basename, formatAction, relativeTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { Decision, HoldfastRequest } from "@/lib/types";

type PendingCardProps = {
  item: HoldfastRequest;
  selected: boolean;
  now: number;
  busy?: boolean;
  flash?: Decision;
  stickyActions?: boolean;
  onSelect: () => void;
  onDecide: (decision: Decision, options: { remember_session: boolean; note: string }) => void;
};

export function PendingCard({
  item,
  selected,
  now,
  busy,
  flash,
  stickyActions,
  onSelect,
  onDecide,
}: PendingCardProps) {
  const [remember, setRemember] = useState(false);
  const [note, setNote] = useState("");

  const action = formatAction(item.kind, item.detail);
  const exe = basename(item.exe);

  const decide = (decision: Decision) => {
    onDecide(decision, { remember_session: remember, note });
  };

  return (
    <Card
      tabIndex={0}
      size="sm"
      onClick={onSelect}
      onFocus={onSelect}
      onKeyDown={(event) => {
        const target = event.target as HTMLElement;
        if (target.tagName === "INPUT" || target.tagName === "TEXTAREA") return;
        if (event.metaKey || event.ctrlKey || event.altKey) return;
        if (event.key === "a" || event.key === "A") {
          event.preventDefault();
          decide("allow");
        }
        if (event.key === "d" || event.key === "D") {
          event.preventDefault();
          decide("deny");
        }
      }}
      className={cn(
        "cursor-pointer gap-3 rounded-lg py-3 ring-1 ring-foreground/10 outline-none transition-colors focus-visible:ring-2 focus-visible:ring-zinc-400/60",
        selected && "ring-zinc-400/45 bg-zinc-900/80",
        flash === "allow" && "flash-allow",
        flash === "deny" && "flash-deny"
      )}
    >
      <CardHeader className="flex flex-row items-start justify-between gap-3">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <KindBadge kind={item.kind} />
          <span className="truncate font-medium text-zinc-100">{exe}</span>
          {item.pid != null ? (
            <span className="font-mono text-[11px] text-zinc-500">pid {item.pid}</span>
          ) : null}
          {item.op ? (
            <span className="font-mono text-[11px] uppercase tracking-wide text-zinc-500">
              {item.op}
            </span>
          ) : null}
        </div>
        <span className="shrink-0 font-mono text-[11px] text-zinc-500">
          {relativeTime(item.ts || item.parked_at, now)}
        </span>
      </CardHeader>
      <CardContent className="space-y-2">
        <pre className="overflow-x-auto rounded-md bg-zinc-950/80 px-2.5 py-2 font-mono text-[12.5px] leading-relaxed text-zinc-100 whitespace-pre-wrap">
          {action}
        </pre>
        {item.cwd ? (
          <p className="truncate font-mono text-[11px] text-zinc-500">
            cwd {item.cwd}
          </p>
        ) : null}
        <label className="flex items-center gap-2 text-[12px] text-zinc-400">
          <input
            type="checkbox"
            className="size-3.5 rounded-sm border-zinc-600 bg-zinc-950 accent-zinc-200"
            checked={remember}
            onChange={(event) => setRemember(event.target.checked)}
            onClick={(event) => event.stopPropagation()}
          />
          Remember for this session
        </label>
        <input
          value={note}
          onChange={(event) => setNote(event.target.value)}
          onClick={(event) => event.stopPropagation()}
          placeholder="Note (optional)"
          className="h-8 w-full rounded-md border border-input bg-zinc-950/50 px-2 font-mono text-xs text-zinc-200 placeholder:text-zinc-600"
        />
      </CardContent>
      <CardFooter
        className={cn(
          "gap-2 border-t bg-zinc-950/40 p-3",
          stickyActions &&
            "max-md:sticky max-md:bottom-0 max-md:z-20 max-md:border-border max-md:bg-zinc-950/95 max-md:backdrop-blur"
        )}
      >
        <Button
          size="lg"
          className="h-10 flex-1 text-sm font-semibold"
          disabled={busy}
          onClick={(event) => {
            event.stopPropagation();
            decide("allow");
          }}
        >
          Allow
        </Button>
        <Button
          size="lg"
          variant="destructive"
          className="h-10 flex-1 text-sm font-semibold"
          disabled={busy}
          onClick={(event) => {
            event.stopPropagation();
            decide("deny");
          }}
        >
          Deny
        </Button>
      </CardFooter>
    </Card>
  );
}
