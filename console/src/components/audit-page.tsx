"use client";

import { useMemo, useState } from "react";
import { useHoldfast } from "@/components/holdfast-provider";
import { AuditRow } from "@/components/audit-list";
import { DaemonError } from "@/components/queue-states";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useNow } from "@/hooks/use-now";
import type { Decision, Kind } from "@/lib/types";
import { cn } from "@/lib/utils";

const KINDS: Array<Kind | "all"> = ["all", "file", "shell", "net"];
const DECISIONS: Array<Decision | "all"> = ["all", "allow", "deny"];

export function AuditPage() {
  const { audit, loading, reachable } = useHoldfast();
  const now = useNow();
  const [kind, setKind] = useState<Kind | "all">("all");
  const [decision, setDecision] = useState<Decision | "all">("all");

  const items = useMemo(() => {
    return audit.filter((event) => {
      if (kind !== "all" && event.kind !== kind) return false;
      if (decision !== "all" && event.decision !== decision) return false;
      return true;
    });
  }, [audit, kind, decision]);

  return (
    <div className="flex min-h-0 flex-1 flex-col p-4 lg:p-6">
      <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-sm font-medium text-zinc-100">Audit log</h1>
          <p className="mt-1 text-[12px] text-zinc-500">
            Reverse chronological. Hashes are the append-only chain, not a ceremony.
          </p>
        </div>
        <div className="flex flex-wrap gap-3">
          <ChipGroup
            label="Kind"
            value={kind}
            options={KINDS}
            onChange={setKind}
          />
          <ChipGroup
            label="Decision"
            value={decision}
            options={DECISIONS}
            onChange={setDecision}
          />
        </div>
      </div>
      {!reachable && !loading ? (
        <DaemonError />
      ) : (
        <ScrollArea className="min-h-0 flex-1 rounded-lg border border-border/80 bg-zinc-950/40 px-3">
          {items.length === 0 ? (
            <p className="py-12 text-center text-[13px] text-zinc-500">
              {loading ? "Loading audit log." : "No events match these filters."}
            </p>
          ) : (
            items.map((event) => (
              <AuditRow key={`${event.id}-${event.ts}-${event.hash ?? ""}`} event={event} now={now} />
            ))
          )}
        </ScrollArea>
      )}
    </div>
  );
}

function ChipGroup<T extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: T;
  options: readonly T[];
  onChange: (value: T) => void;
}) {
  return (
    <div className="flex items-center gap-1.5">
      <span className="mr-1 text-[11px] uppercase tracking-wide text-zinc-500">{label}</span>
      {options.map((option) => (
        <Button
          key={option}
          type="button"
          size="xs"
          variant={value === option ? "secondary" : "ghost"}
          className={cn(
            "rounded-full px-2.5 font-mono text-[11px]",
            value === option ? "text-zinc-100" : "text-zinc-500"
          )}
          onClick={() => onChange(option)}
        >
          {option}
        </Button>
      ))}
    </div>
  );
}
