"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { toast } from "sonner";
import {
  fetchAudit,
  fetchHealth,
  fetchPending,
  fetchSession,
  postDecide,
} from "@/lib/api";
import { streamUrl } from "@/lib/config";
import { formatAction } from "@/lib/format";
import { parseStreamFrame } from "@/lib/stream";
import type {
  AuditEvent,
  Decision,
  Health,
  HoldfastRequest,
  StreamMode,
  WrapSession,
} from "@/lib/types";

const POLL_MS = 1500;
const HEALTH_MS = 4000;
const WS_RETRY_MS = 4000;
const FLASH_MS = 650;

export type FlashMap = Record<string, Decision>;

type DecideOptions = {
  remember_session?: boolean;
  note?: string;
};

type HoldfastContextValue = {
  health: Health | null;
  reachable: boolean;
  pending: HoldfastRequest[];
  audit: AuditEvent[];
  session: WrapSession | null;
  stream: StreamMode;
  loading: boolean;
  error: string | null;
  flashes: FlashMap;
  deciding: Record<string, boolean>;
  decide: (id: string, decision: Decision, options?: DecideOptions) => Promise<void>;
};

const HoldfastContext = createContext<HoldfastContextValue | null>(null);

function upsertById<T extends { id: string }>(list: T[], item: T, prepend = true): T[] {
  const index = list.findIndex((row) => row.id === item.id);
  if (index >= 0) {
    const next = list.slice();
    next[index] = item;
    return next;
  }
  return prepend ? [item, ...list] : [...list, item];
}

function sessionStatsPatch(
  session: WrapSession | null,
  decision: string | undefined
): WrapSession | null {
  if (!session || (decision !== "allow" && decision !== "deny")) return session;
  const stats = session.stats ?? {};
  const allow = Number(stats.allow ?? stats.allowed ?? session.allowed ?? 0) + (decision === "allow" ? 1 : 0);
  const deny = Number(stats.deny ?? stats.denied ?? session.denied ?? 0) + (decision === "deny" ? 1 : 0);
  const ask = Math.max(0, Number(stats.ask ?? stats.asked ?? session.asked ?? 1) - 1);
  return {
    ...session,
    allowed: allow,
    denied: deny,
    asked: ask,
    stats: { ...stats, allow, deny, ask, allowed: allow, denied: deny, asked: ask },
  };
}

export function HoldfastProvider({ children }: { children: ReactNode }) {
  const [health, setHealth] = useState<Health | null>(null);
  const [reachable, setReachable] = useState(false);
  const [pending, setPending] = useState<HoldfastRequest[]>([]);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [session, setSession] = useState<WrapSession | null>(null);
  const [stream, setStream] = useState<StreamMode>("off");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [flashes, setFlashes] = useState<FlashMap>({});
  const [deciding, setDeciding] = useState<Record<string, boolean>>({});

  const streamRef = useRef<StreamMode>("off");
  const wsRef = useRef<WebSocket | null>(null);

  const markReachable = useCallback((ok: boolean, healthPayload?: Health | null) => {
    setReachable(ok);
    if (healthPayload !== undefined) setHealth(healthPayload);
    if (ok) {
      setError(null);
    } else {
      setHealth(null);
      setError("Holdfast daemon is not running. Start `holdfastd`.");
    }
  }, []);

  const applyDecision = useCallback((id: string, decision?: string, event?: AuditEvent) => {
    setFlashes((prev) =>
      decision === "allow" || decision === "deny" ? { ...prev, [id]: decision } : prev
    );
    window.setTimeout(() => {
      setPending((prev) => prev.filter((item) => item.id !== id));
      setFlashes((prev) => {
        const next = { ...prev };
        delete next[id];
        return next;
      });
    }, FLASH_MS);
    if (event) {
      setAudit((prev) => upsertById(prev, event));
    }
    if (decision === "allow" || decision === "deny") {
      setSession((prev) => sessionStatsPatch(prev, decision));
    }
  }, []);

  const refresh = useCallback(
    async (mode: "all" | "pending" = "all") => {
      try {
        if (mode === "all") {
          const [healthPayload, pendingItems, auditItems, sessionPayload] = await Promise.all([
            fetchHealth(),
            fetchPending(),
            fetchAudit(100),
            fetchSession(),
          ]);
          markReachable(healthPayload.ok !== false, healthPayload);
          setPending(pendingItems);
          setAudit(auditItems);
          setSession(sessionPayload);
        } else {
          const pendingItems = await fetchPending();
          setPending(pendingItems);
          markReachable(true);
        }
      } catch {
        markReachable(false);
      } finally {
        setLoading(false);
      }
    },
    [markReachable]
  );

  useEffect(() => {
    let cancelled = false;
    let pollTimer: number | null = null;
    let healthTimer: number | null = null;
    let retryTimer: number | null = null;

    const stopPoll = () => {
      if (pollTimer !== null) {
        window.clearInterval(pollTimer);
        pollTimer = null;
      }
    };

    const startPoll = () => {
      if (cancelled || pollTimer !== null) return;
      streamRef.current = "poll";
      setStream("poll");
      pollTimer = window.setInterval(() => {
        void refresh(streamRef.current === "ws" ? "pending" : "all");
      }, POLL_MS);
    };

    const handleEvents = (data: string) => {
      for (const event of parseStreamFrame(data)) {
        if (event.type === "pending") {
          if (event.items) {
            setPending(event.items);
          } else if (event.item) {
            setPending((prev) => upsertById(prev, event.item!, false));
          }
        } else if (event.type === "decided") {
          const id = event.id || event.item?.id;
          if (id) applyDecision(id, event.decision || event.item?.decision, event.item);
        } else if (event.type === "audit") {
          if (event.items) setAudit(event.items);
          else if (event.item) setAudit((prev) => upsertById(prev, event.item!));
        } else if (event.type === "session") {
          setSession(event.item ?? null);
        }
      }
    };

    const connectWs = () => {
      if (cancelled) return;
      try {
        const ws = new WebSocket(streamUrl());
        wsRef.current = ws;
        ws.onopen = () => {
          if (cancelled) return;
          streamRef.current = "ws";
          setStream("ws");
          startPoll();
          void refresh("all");
        };
        ws.onmessage = (message) => {
          handleEvents(String(message.data));
        };
        ws.onerror = () => {
          ws.close();
        };
        ws.onclose = () => {
          if (cancelled) return;
          if (wsRef.current === ws) wsRef.current = null;
          startPoll();
          retryTimer = window.setTimeout(connectWs, WS_RETRY_MS);
        };
      } catch {
        startPoll();
        retryTimer = window.setTimeout(connectWs, WS_RETRY_MS);
      }
    };

    healthTimer = window.setInterval(() => {
      void fetchHealth()
        .then((payload) => markReachable(payload.ok !== false, payload))
        .catch(() => markReachable(false));
    }, HEALTH_MS);

    const boot = window.setTimeout(() => {
      void refresh("all").then(() => {
        if (!cancelled) {
          startPoll();
          connectWs();
        }
      });
    }, 0);

    return () => {
      cancelled = true;
      stopPoll();
      window.clearTimeout(boot);
      if (healthTimer !== null) window.clearInterval(healthTimer);
      if (retryTimer !== null) window.clearTimeout(retryTimer);
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, [applyDecision, markReachable, refresh]);

  const decide = useCallback(
    async (id: string, decision: Decision, options?: DecideOptions) => {
      const item = pending.find((row) => row.id === id);
      setDeciding((prev) => ({ ...prev, [id]: true }));
      try {
        await postDecide({
          id,
          decision,
          actor: "operator",
          remember_session: options?.remember_session,
          note: options?.note,
        });
        applyDecision(id, decision);
        const action = item ? formatAction(item.kind, item.detail) : id;
        toast.success(decision === "allow" ? `Allowed ${action}` : `Denied ${action}`);
      } catch (err) {
        toast.error(err instanceof Error ? err.message : "Decision failed");
      } finally {
        setDeciding((prev) => {
          const next = { ...prev };
          delete next[id];
          return next;
        });
      }
    },
    [applyDecision, pending]
  );

  const value = useMemo<HoldfastContextValue>(
    () => ({
      health,
      reachable,
      pending,
      audit,
      session,
      stream,
      loading,
      error,
      flashes,
      deciding,
      decide,
    }),
    [health, reachable, pending, audit, session, stream, loading, error, flashes, deciding, decide]
  );

  return <HoldfastContext.Provider value={value}>{children}</HoldfastContext.Provider>;
}

export function useHoldfast(): HoldfastContextValue {
  const ctx = useContext(HoldfastContext);
  if (!ctx) {
    throw new Error("useHoldfast must be used within HoldfastProvider");
  }
  return ctx;
}
