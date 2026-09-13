import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export function KindBadge({ kind }: { kind?: string }) {
  const value = (kind || "file").toLowerCase();
  return (
    <Badge
      variant="outline"
      className={cn(
        "h-5 rounded-sm px-1.5 font-mono text-[10px] uppercase tracking-wider",
        value === "file" && "border-zinc-500/40 text-zinc-300",
        value === "shell" && "border-amber-500/35 text-amber-200/90",
        value === "net" && "border-sky-500/35 text-sky-200/90"
      )}
    >
      {value}
    </Badge>
  );
}

export function DecisionBadge({ decision }: { decision?: string }) {
  const value = (decision || "").toLowerCase();
  return (
    <Badge
      variant="outline"
      className={cn(
        "h-5 rounded-sm px-1.5 font-mono text-[10px] uppercase tracking-wider",
        value === "allow" && "border-emerald-500/35 text-emerald-300",
        value === "deny" && "border-red-500/35 text-red-300",
        value !== "allow" && value !== "deny" && "text-zinc-400"
      )}
    >
      {value || "—"}
    </Badge>
  );
}
