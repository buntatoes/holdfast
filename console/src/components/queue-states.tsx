import { Card } from "@/components/ui/card";

export function QueueSkeletons() {
  return (
    <div className="space-y-3">
      {Array.from({ length: 3 }).map((_, index) => (
        <Card key={index} size="sm" className="gap-3 rounded-lg py-3">
          <div className="flex items-center justify-between px-3">
            <div className="flex gap-2">
              <div className="h-5 w-12 animate-pulse rounded-sm bg-zinc-800" />
              <div className="h-5 w-28 animate-pulse rounded-sm bg-zinc-800" />
            </div>
            <div className="h-4 w-12 animate-pulse rounded-sm bg-zinc-800" />
          </div>
          <div className="mx-3 h-10 animate-pulse rounded-md bg-zinc-800/80" />
          <div className="mx-3 h-3 w-40 animate-pulse rounded-sm bg-zinc-800" />
          <div className="flex gap-2 border-t px-3 py-3">
            <div className="h-10 flex-1 animate-pulse rounded-md bg-zinc-800" />
            <div className="h-10 flex-1 animate-pulse rounded-md bg-zinc-800" />
          </div>
        </Card>
      ))}
    </div>
  );
}

export function DaemonError() {
  return (
    <div className="rounded-lg border border-red-500/25 bg-red-950/30 px-4 py-8 text-center">
      <p className="text-sm text-red-200">Holdfast daemon is not running. Start `holdfastd`.</p>
      <p className="mt-2 text-[12px] text-zinc-500">
        The console expects HTTP at the configured API, defaulting to 127.0.0.1:47821.
      </p>
    </div>
  );
}

export function EmptyQueue() {
  return (
    <div className="rounded-lg border border-dashed border-zinc-700/80 bg-zinc-950/30 px-4 py-12 text-center">
      <p className="text-sm text-zinc-300">
        Nothing waiting. Agents can work, but they cannot act until you say so.
      </p>
    </div>
  );
}
