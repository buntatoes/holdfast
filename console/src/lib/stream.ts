import type { AuditEvent, HoldfastRequest, WrapSession } from "@/lib/types";

export type StreamEvent =
  | { type: "pending"; item?: HoldfastRequest; items?: HoldfastRequest[] }
  | { type: "decided"; id?: string; decision?: string; item?: AuditEvent }
  | { type: "audit"; item?: AuditEvent; items?: AuditEvent[] }
  | { type: "session"; item?: WrapSession | null };

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function asRequest(value: unknown): HoldfastRequest | null {
  if (!isRecord(value) || typeof value.id !== "string") return null;
  if (typeof value.kind !== "string" && typeof value.op !== "string") return null;
  return value as unknown as HoldfastRequest;
}

function asAudit(value: unknown): AuditEvent | null {
  if (!isRecord(value) || typeof value.id !== "string") return null;
  return value as unknown as AuditEvent;
}

export function parseStreamPayload(raw: unknown): StreamEvent[] {
  if (Array.isArray(raw)) {
    return raw.flatMap((item) => parseStreamPayload(item));
  }
  if (!isRecord(raw)) return [];

  const type = String(raw.type ?? raw.event ?? "");
  if (type === "pending") {
    if (Array.isArray(raw.items)) {
      return [{ type: "pending", items: raw.items as HoldfastRequest[] }];
    }
    const item = asRequest(raw.item ?? raw.request ?? raw);
    return item ? [{ type: "pending", item }] : [];
  }
  if (type === "decided") {
    const item = asAudit(raw.item ?? raw.event ?? raw.audit);
    const id = String(raw.id ?? item?.id ?? "");
    return [
      {
        type: "decided",
        id: id || undefined,
        decision: String(raw.decision ?? item?.decision ?? ""),
        item: item ?? undefined,
      },
    ];
  }
  if (type === "audit") {
    if (Array.isArray(raw.items)) {
      return [{ type: "audit", items: raw.items as AuditEvent[] }];
    }
    const item = asAudit(raw.item ?? raw.event ?? raw.audit ?? raw);
    return item ? [{ type: "audit", item }] : [];
  }
  if (type === "session") {
    const candidate = raw.item ?? raw.session ?? raw;
    if (!isRecord(candidate) || (!candidate.id && candidate.pid == null && !candidate.command)) {
      return [{ type: "session", item: null }];
    }
    return [{ type: "session", item: candidate as unknown as WrapSession }];
  }

  const request = asRequest(raw);
  if (request && (raw.kind || raw.op) && !raw.decision) {
    return [{ type: "pending", item: request }];
  }
  if (typeof raw.decision === "string" && typeof raw.id === "string") {
    return [{ type: "audit", item: raw as unknown as AuditEvent }];
  }
  return [];
}

export function parseStreamFrame(data: string): StreamEvent[] {
  const chunks = data
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  const events: StreamEvent[] = [];
  for (const chunk of chunks) {
    try {
      events.push(...parseStreamPayload(JSON.parse(chunk)));
    } catch {
      // ignore malformed frames
    }
  }
  return events;
}
