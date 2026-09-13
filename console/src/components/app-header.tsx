"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { useHoldfast } from "@/components/holdfast-provider";
import { cn } from "@/lib/utils";

const NAV = [
  { href: "/", label: "Desk" },
  { href: "/audit", label: "Audit" },
];

export function AppHeader() {
  const pathname = usePathname();
  const { reachable, health, stream, pending } = useHoldfast();

  return (
    <header className="border-b border-border/80 bg-background/95">
      <div className="flex items-center justify-between gap-4 px-4 py-3 lg:px-6">
        <div className="min-w-0">
          <div className="flex items-baseline gap-3">
            <Link href="/" className="font-semibold tracking-tight text-zinc-100">
              Holdfast
            </Link>
            <p className="truncate text-[13px] text-zinc-400">
              Agents propose. You decide.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <nav className="hidden items-center gap-1 text-[13px] sm:flex">
            {NAV.map((item) => {
              const active = pathname === item.href;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={cn(
                    "rounded-md px-2.5 py-1 text-zinc-400 transition-colors hover:text-zinc-100",
                    active && "bg-zinc-800/80 text-zinc-100"
                  )}
                >
                  {item.label}
                  {item.href === "/" && pending.length > 0 ? (
                    <span className="ml-1.5 tabular-nums text-zinc-500">
                      {pending.length}
                    </span>
                  ) : null}
                </Link>
              );
            })}
          </nav>
          <Separator orientation="vertical" className="hidden h-5 sm:block" />
          <HealthPill reachable={reachable} version={health?.version} stream={stream} />
        </div>
      </div>
      <div className="flex gap-1 border-t border-border/60 px-4 py-1.5 sm:hidden">
        {NAV.map((item) => {
          const active = pathname === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "rounded-md px-2 py-1 text-xs text-zinc-400",
                active && "bg-zinc-800 text-zinc-100"
              )}
            >
              {item.label}
            </Link>
          );
        })}
      </div>
    </header>
  );
}

function HealthPill({
  reachable,
  version,
  stream,
}: {
  reachable: boolean;
  version?: string;
  stream: string;
}) {
  const label = reachable ? "ok" : "unreachable";
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button type="button" className="rounded-full outline-none">
          <Badge
            variant="outline"
            className={cn(
              "h-6 rounded-full border px-2 font-mono text-[11px] tracking-wide",
              reachable
                ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                : "border-red-500/30 bg-red-500/10 text-red-300"
            )}
          >
            <span
              className={cn(
                "mr-1.5 size-1.5 rounded-full",
                reachable ? "bg-emerald-400" : "bg-red-400"
              )}
            />
            {label}
          </Badge>
        </button>
      </TooltipTrigger>
      <TooltipContent>
        {reachable
          ? `Daemon ${version ? `v${version}` : "reachable"} · ${stream === "ws" ? "live stream" : "polling"}`
          : "Cannot reach holdfastd on the configured API"}
      </TooltipContent>
    </Tooltip>
  );
}
