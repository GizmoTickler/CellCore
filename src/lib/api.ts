import { useAuthStore } from "@/stores/auth-store";
import { useWsStore } from "@/stores/ws-store";
import type {
  AtCommandItem,
  FirmwareAbFlashRequest,
  FirmwareAbInspectReport,
  FirmwareAbScope,
  FirmwareAbStatus,
  FirmwareAbSwitchRequest,
} from "@/types/cellcore";

export class ApiError extends Error {
  status: number;
  /** Parsed JSON error body, when the server sent one (e.g. `confirm` on HTTP 428). */
  data?: Record<string, unknown>;
  constructor(status: number, message: string, data?: Record<string, unknown>) {
    super(message);
    this.status = status;
    this.data = data;
  }
}

export async function apiFetch<T = unknown>(
  path: string,
  options: RequestInit & { skipAuthRedirect?: boolean } = {}
): Promise<T> {
  const { skipAuthRedirect, headers: extraHeaders, ...rest } = options;
  const { token, csrfToken } = useAuthStore.getState();

  const headers = new Headers(extraHeaders);
  headers.set("X-QM-CSRF", csrfToken || "1");
  if (token && /^[0-9a-fA-F]{16,64}$/.test(token)) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  if (rest.body && typeof rest.body === "string" && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const res = await fetch(path, {
    credentials: "same-origin",
    cache: "no-store",
    ...rest,
    headers,
  });

  if (res.status === 401 && !skipAuthRedirect) {
    useWsStore.getState().disconnect();
    useAuthStore.getState().clearAuth();
    if (window.location.hash !== "#/login") {
      window.location.hash = "#/login";
    }
    throw new ApiError(401, "Session expired");
  }

  const text = await res.text();
  if (!res.ok) {
    let msg = text || `HTTP ${res.status}`;
    let data: Record<string, unknown> | undefined;
    try {
      const parsed = JSON.parse(text) as { error?: string; message?: string };
      if (parsed && typeof parsed === "object") data = parsed as Record<string, unknown>;
      if (parsed?.error) msg = parsed.error;
      else if (parsed?.message) msg = parsed.message;
    } catch {
      // Never dump raw HTML fallback pages (e.g. SPA 404 or proxy gateway pages) into UI toasts.
      const trimmed = text.trimStart();
      if (/^<!doctype\s+html|^<html\b/i.test(trimmed)) {
        msg = `HTTP ${res.status} (${path})`;
      } else if (trimmed.length > 240) {
        msg = `${trimmed.slice(0, 240)}…`;
      }
    }
    throw new ApiError(res.status, msg, data);
  }

  if (!text.trim()) return {} as T;
  try {
    return JSON.parse(text) as T;
  } catch {
    return { raw: text } as T;
  }
}

export type AtClass = "read" | "caution" | "dangerous";

/** The daemon's AT guard verdict for one console line (worst part wins). */
export interface AtClassification {
  class: AtClass;
  reason: string;
  parts: Array<{ text: string; name: string; class: AtClass; reason: string }>;
}

/** `confirm` is required by the daemon for commands it classifies as dangerous (HTTP 428 otherwise). */
export async function sendAtCommand(command: string, timeoutSecs = 12, confirm = false): Promise<AtCommandItem> {
  return apiFetch<AtCommandItem>("/api/v1/modem/at", {
    method: "POST",
    body: JSON.stringify(confirm ? { command, timeoutSecs, confirm: true } : { command, timeoutSecs }),
  });
}

export async function classifyAtCommand(command: string): Promise<AtClassification> {
  return apiFetch<AtClassification>(`/api/v1/modem/at/classify?command=${encodeURIComponent(command)}`);
}

export async function getFirmwareAbStatus(): Promise<FirmwareAbStatus> {
  return apiFetch<FirmwareAbStatus>("/api/v1/system/firmware-ab");
}

export async function inspectFirmwareAb(params: {
  path: string;
  scope?: FirmwareAbScope;
  allowProjectMismatch?: boolean;
  allowNoManifest?: boolean;
}): Promise<FirmwareAbInspectReport> {
  return apiFetch<FirmwareAbInspectReport>("/api/v1/system/firmware-ab/inspect", {
    method: "POST",
    body: JSON.stringify(params),
  });
}

export async function flashFirmwareAb(body: FirmwareAbFlashRequest): Promise<{
  ok: boolean;
  started: boolean;
  status: string;
  targetSlot: string;
  partitions: number;
}> {
  return apiFetch("/api/v1/system/firmware-ab/flash", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function switchFirmwareAbSlot(body: FirmwareAbSwitchRequest): Promise<{
  ok: boolean;
  rebooting: boolean;
}> {
  return apiFetch("/api/v1/system/firmware-ab/switch", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function confirmFirmwareAbSlot(): Promise<{ ok: boolean }> {
  return apiFetch("/api/v1/system/firmware-ab/confirm", {
    method: "POST",
    body: "{}",
  });
}
