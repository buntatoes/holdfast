import type { AuditEvent, RequestDetail, WrapSession } from "@/lib/types";

export function basename(path: string | undefined): string {
  if (!path) return "process";
  const parts = path.split("/").filter(Boolean);
  return parts.at(-1) || path;
}

function shellQuote(arg: string): string {
  if (arg === "") return '""';
  if (/^[A-Za-z0-9_./:=+-]+$/.test(arg)) return arg;
  return JSON.stringify(arg);
}

export function formatAction(kind: string | undefined, detail: RequestDetail | undefined): string {
  const d = detail ?? {};
  if (kind === "file") {
    return String(d.path ?? "—");
  }
  if (kind === "shell") {
    if (Array.isArray(d.argv) && d.argv.length > 0) {
      return d.argv.map((a) => shellQuote(String(a))).join(" ");
    }
    return String(d.resolved ?? "—");
  }
  if (kind === "net") {
    const host = d.host ?? "—";
    const port = d.port ?? "—";
    return `${host}:${port}`;
  }
  if (d.path) return String(d.path);
  if (Array.isArray(d.argv)) return d.argv.map((a) => shellQuote(String(a))).join(" ");
  if (d.host) return `${d.host}:${d.port ?? ""}`;
  return "—";
}

export function formatCommand(command: string | string[] | undefined): string {
  if (!command) return "—";
  if (Array.isArray(command)) return command.map((c) => shellQuote(String(c))).join(" ");
  return command;
}

export function relativeTime(iso: string | undefined, now = Date.now()): string {
  if (!iso) return "";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return iso;
  const seconds = Math.round((now - t) / 1000);
  if (seconds < 0) return "just now";
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return new Date(iso).toLocaleString();
}

export function shortHash(value: string | undefined, head = 8, tail = 4): string {
  if (!value) return "";
  const hash = value.replace(/^sha256:/i, "");
  if (hash.length <= head + tail + 1) return hash;
  return `${hash.slice(0, head)}…${hash.slice(-tail)}`;
}

export function chainOf(event: AuditEvent): { hash?: string; prev?: string } {
  const hash = event.hash || event.event_hash || event.sha256 || event.chain?.hash;
  const prev = event.prev_hash || event.chain?.prev_hash || event.chain?.prev;
  return { hash, prev };
}

export function sessionCounts(session: WrapSession): {
  allowed: number;
  denied: number;
  asked: number;
} {
  const stats = session.stats ?? {};
  return {
    allowed: Number(stats.allow ?? stats.allowed ?? session.allowed ?? 0),
    denied: Number(stats.deny ?? stats.denied ?? session.denied ?? 0),
    asked: Number(stats.ask ?? stats.asked ?? session.asked ?? 0),
  };
}
