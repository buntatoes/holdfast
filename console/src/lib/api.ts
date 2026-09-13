import { apiBase } from "@/lib/config";
import type {
  AuditEvent,
  Decision,
  Health,
  HoldfastRequest,
  WrapSession,
} from "@/lib/types";

async function getJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${apiBase()}${path}`, {
    ...init,
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error(`${path} ${res.status}`);
  }
  return (await res.json()) as T;
}

function asItems<T>(payload: unknown, keys: string[] = ["items"]): T[] {
  if (Array.isArray(payload)) return payload as T[];
  if (payload && typeof payload === "object") {
    const rec = payload as Record<string, unknown>;
    for (const key of keys) {
      if (Array.isArray(rec[key])) return rec[key] as T[];
    }
  }
  return [];
}

export async function fetchHealth(): Promise<Health> {
  return getJson<Health>("/health");
}

export async function fetchPending(): Promise<HoldfastRequest[]> {
  const payload = await getJson<unknown>("/api/pending");
  return asItems<HoldfastRequest>(payload, ["items", "pending", "requests"]);
}

export async function fetchAudit(limit = 100): Promise<AuditEvent[]> {
  const payload = await getJson<unknown>(`/api/audit?limit=${limit}`);
  return asItems<AuditEvent>(payload, ["items", "events", "audit"]).slice().reverse();
}

export async function fetchSession(): Promise<WrapSession | null> {
  try {
    const payload = await getJson<unknown>("/api/session");
    if (!payload || typeof payload !== "object") return null;
    const rec = payload as Record<string, unknown>;
    if (rec.session && typeof rec.session === "object") {
      return rec.session as WrapSession;
    }
    if (rec.id || rec.pid != null || rec.command) {
      return payload as WrapSession;
    }
    return null;
  } catch {
    return null;
  }
}

export async function postDecide(input: {
  id: string;
  decision: Decision;
  actor?: string;
  note?: string;
  remember_session?: boolean;
}): Promise<void> {
  const body: Record<string, unknown> = {
    id: input.id,
    decision: input.decision,
    actor: input.actor ?? "operator",
  };
  if (input.note?.trim()) body.note = input.note.trim();
  if (input.remember_session) body.remember_session = true;

  const res = await fetch(`${apiBase()}/api/decide`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(text || `decide ${res.status}`);
  }
}
