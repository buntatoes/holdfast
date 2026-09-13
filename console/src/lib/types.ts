export type Kind = "file" | "shell" | "net";
export type Op = "open" | "creat" | "unlink" | "rename" | "exec" | "connect" | string;
export type Decision = "allow" | "deny";

export type FileDetail = {
  path?: string;
  flags?: string;
  mode?: number;
};

export type ShellDetail = {
  argv?: string[];
  resolved?: string;
};

export type NetDetail = {
  host?: string;
  port?: number | string;
  family?: string;
};

export type RequestDetail = FileDetail & ShellDetail & NetDetail & Record<string, unknown>;

export type HoldfastRequest = {
  id: string;
  session?: string;
  kind: Kind | string;
  op: Op;
  pid?: number;
  ppid?: number;
  exe?: string;
  cwd?: string;
  detail?: RequestDetail;
  ts?: string;
  parked_at?: string;
};

export type AuditEvent = {
  id: string;
  ts?: string;
  kind?: Kind | string;
  op?: Op;
  detail?: RequestDetail;
  decision?: Decision | string;
  actor?: string;
  session?: string;
  pid?: number;
  exe?: string;
  cwd?: string;
  hash?: string;
  prev_hash?: string;
  event_hash?: string;
  sha256?: string;
  chain?: {
    hash?: string;
    prev?: string;
    prev_hash?: string;
  };
};

export type SessionStats = {
  allow?: number;
  deny?: number;
  ask?: number;
  allowed?: number;
  denied?: number;
  asked?: number;
  pending?: number;
};

export type WrapSession = {
  id?: string;
  pid?: number;
  command?: string | string[];
  started_at?: string;
  stats?: SessionStats;
  allowed?: number;
  denied?: number;
  asked?: number;
};

export type Health = {
  ok?: boolean;
  linux?: boolean;
  version?: string;
};

export type StreamMode = "ws" | "poll" | "off";
