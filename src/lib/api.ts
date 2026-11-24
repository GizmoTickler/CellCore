import { useAuthStore } from "@/stores/auth-store";
import { useWsStore } from "@/stores/ws-store";
import type {
  AtCommandItem,
  FirmwareAbFlashRequest,
  FirmwareAbInspectReport,
  FirmwareAbScope,
  FirmwareAbStatus,
  FirmwareAbSwitchRequest,
  FirmwareUploadResponse,
  StagedFirmwareFile,
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

export async function getFirmwareAbStaged(): Promise<{ files: StagedFirmwareFile[] }> {
  return apiFetch<{ files: StagedFirmwareFile[] }>("/api/v1/system/firmware-ab/staged");
}

function normalizeFirmwareUploadFilename(raw: string): string {
  const trimmed = raw.trim();
  if (/^[A-Za-z0-9][A-Za-z0-9._-]*\.zip$/.test(trimmed) && !trimmed.includes("..") && trimmed.length <= 128) {
    return trimmed;
  }
  const withoutZip = trimmed.replace(/\.zip$/i, "");
  let cleaned = withoutZip
    .replace(/[^A-Za-z0-9._-]+/g, "_")
    .replace(/\.{2,}/g, ".")
    .replace(/^[._-]+/, "");
  if (!cleaned) cleaned = "firmware-upload";
  if (cleaned.length > 124) cleaned = cleaned.slice(0, 124);
  return `${cleaned}.zip`;
}

export function uploadFirmwareAbZip(
  file: File,
  onProgress: (pct: number, loaded: number, total: number) => void
): Promise<FirmwareUploadResponse> {
  return new Promise<FirmwareUploadResponse>((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    const { token, csrfToken } = useAuthStore.getState();

    xhr.open("POST", "/api/v1/system/firmware-ab/upload", true);
    xhr.withCredentials = true;
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.setRequestHeader("X-Firmware-Filename", normalizeFirmwareUploadFilename(file.name));
    xhr.setRequestHeader("X-QM-CSRF", csrfToken || "1");
    if (token && /^[0-9a-fA-F]{16,64}$/.test(token)) {
      xhr.setRequestHeader("Authorization", `Bearer ${token}`);
    }

    xhr.upload.onprogress = (ev) => {
      const total = ev.lengthComputable && ev.total > 0 ? ev.total : file.size;
      const loaded = ev.loaded;
      const pct = total > 0 ? Math.min(100, Math.round((loaded / total) * 100)) : 0;
      onProgress(pct, loaded, total);
    };

    xhr.onload = () => {
      const text = xhr.responseText || "";
      if (xhr.status === 401) {
        useWsStore.getState().disconnect();
        useAuthStore.getState().clearAuth();
        if (window.location.hash !== "#/login") {
          window.location.hash = "#/login";
        }
        reject(new ApiError(401, "Session expired"));
        return;
      }
      let parsed: Record<string, unknown> | undefined;
      try {
        const raw = JSON.parse(text) as unknown;
        if (raw && typeof raw === "object") parsed = raw as Record<string, unknown>;
      } catch {
        // non-JSON response handled below
      }
      if (xhr.status >= 200 && xhr.status < 300) {
        onProgress(100, file.size, file.size);
        if (parsed) {
          resolve(parsed as unknown as FirmwareUploadResponse);
        } else {
          reject(new ApiError(xhr.status, "Invalid upload response from daemon"));
        }
        return;
      }
      let msg = text.trim() || `HTTP ${xhr.status}`;
      if (typeof parsed?.error === "string" && parsed.error) msg = parsed.error;
      else if (typeof parsed?.message === "string" && parsed.message) msg = parsed.message;
      else if (/^<!doctype\s+html|^<html\b/i.test(msg)) msg = `HTTP ${xhr.status} (/api/v1/system/firmware-ab/upload)`;
      else if (msg.length > 240) msg = `${msg.slice(0, 240)}…`;
      reject(new ApiError(xhr.status, msg, parsed));
    };

    xhr.onerror = () => {
      reject(new ApiError(0, "Network error while uploading firmware archive"));
    };

    xhr.onabort = () => {
      reject(new ApiError(0, "Firmware upload aborted"));
    };

    xhr.send(file);
  });
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

export async function switchFirmwareAb(body: FirmwareAbSwitchRequest): Promise<{
  ok: boolean;
  rebooting: boolean;
}> {
  return apiFetch("/api/v1/system/firmware-ab/switch", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export const switchFirmwareAbSlot = switchFirmwareAb;

export async function confirmFirmwareAbSlot(): Promise<{ ok: boolean }> {
  return apiFetch("/api/v1/system/firmware-ab/confirm", {
    method: "POST",
    body: "{}",
  });
}
