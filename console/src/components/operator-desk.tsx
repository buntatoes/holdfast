"use client";

import { useMemo, useState } from "react";
import { useHoldfast } from "@/components/holdfast-provider";
import { AuditPeek } from "@/components/audit-list";
import { PendingCard } from "@/components/pending-card";
import { DaemonError, EmptyQueue, QueueSkeletons } from "@/components/queue-states";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useNow } from "@/hooks/use-now";
import type { Decision } from "@/lib/types";
import { cn } from "@/lib/utils";

export function OperatorDesk() {
  const { pending, audit, loading, reachable, flashes, deciding, decide } = useHoldfast();
  const now = useNow();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [mobilePane, setMobilePane] = useState("queue");

  const selected = useMemo(
    () => pending.find((item) => item.id === selectedId) ?? pending[0] ?? null,
    [pending, selectedId]
  );

  return (
    <div className="grid min-h-0 flex-1 gap-4 overflow-hidden p-4 lg:grid-cols-[minmax(0,1.35fr)_minmax(18rem,0.8fr)] lg:p-6">
      <div className="lg:hidden">
        <Tabs value={mobilePane} onValueChange={setMobilePane}>
          <TabsList variant="line" className="w-full">
            <TabsTrigger value="queue">Pending</TabsTrigger>
            <TabsTrigger value="audit">Audit</TabsTrigger>
          </TabsList>
        </Tabs>
      </div>
      <section className={cn("min-h-0 overflow-y-auto", mobilePane === "audit" && "max-lg:hidden")}>
        <div className="mb-3 flex items-baseline justify-between">
          <h1 className="text-[13px] font-medium tracking-wide text-zinc-300 uppercase">
            Pending
          </h1>
          <span className="font-mono text-[12px] tabular-nums text-zinc-500">
            {pending.length}
          </span>
        </div>
        {!reachable && !loading ? (
          <DaemonError />
        ) : loading ? (
          <QueueSkeletons />
        ) : pending.length === 0 ? (
          <EmptyQueue />
        ) : (
          <div className="space-y-3 pb-4">
            {pending.map((item) => (
              <PendingCard
                key={item.id}
                item={item}
                selected={selected?.id === item.id}
                now={now}
                busy={Boolean(deciding[item.id])}
                flash={flashes[item.id]}
                stickyActions={selected?.id === item.id}
                onSelect={() => setSelectedId(item.id)}
                onDecide={(decision: Decision, options) => {
                  void decide(item.id, decision, options);
                }}
              />
            ))}
          </div>
        )}
      </section>
      <div className={cn("min-h-0 lg:h-full", mobilePane === "queue" && "max-lg:hidden")}>
        <AuditPeek events={audit} now={now} />
      </div>
    </div>
  );
}
