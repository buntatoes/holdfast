export const DEFAULT_API = "http://127.0.0.1:47821";

export function apiBase(): string {
  const raw = process.env.NEXT_PUBLIC_HOLDFAST_API || DEFAULT_API;
  return raw.replace(/\/$/, "");
}

export function streamUrl(): string {
  return `${apiBase().replace(/^http/i, "ws")}/api/stream`;
}
