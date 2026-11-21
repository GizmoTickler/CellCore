import { ApiError, apiFetch } from "./api";
import { useObsStore } from "../stores/obs-store";
import type { FailoverStatus } from "../types/obs";

/** Thrown when the user declines a disruptive action during failover. */
export class ActionCancelled extends Error {
  constructor() {
    super("Cancelled");
    this.name = "ActionCancelled";
  }
}

export function isCancelled(e: unknown): boolean {
  return e instanceof ActionCancelled;
}

function withForce(path: string): string {
  return path.includes("?") ? `${path}&force=true` : `${path}?force=true`;
}

/**
 * Call an endpoint that can interrupt traffic (QSCAN, OTA upgrade, speedtest,
 * band / mode / cell lock, MBN, reboot). While the modem carries failover
 * traffic the daemon answers 409 unless `force=true` is sent, so:
 *
 * - `confirmed: true` — the caller's own dialog already showed
 *   `<FailoverWarning />`; send with force when active.
 * - otherwise a global confirm dialog asks first (only while active).
 *
 * If the state flipped to active after the page loaded, the daemon's 409 opens
 * the same dialog and the call is retried with force once the user agrees.
 */
export async function disruptiveFetch<T = unknown>(
  label: string,
  path: string,
  options: RequestInit = {},
  opts: { confirmed?: boolean } = {}
): Promise<T> {
  const store = useObsStore.getState();
  let force = false;
  if (store.failover?.active) {
    if (!opts.confirmed && !(await store.requestConfirm(label))) throw new ActionCancelled();
    force = true;
  }
  try {
    return await apiFetch<T>(force ? withForce(path) : path, options);
  } catch (e) {
    if (!force && e instanceof ApiError && e.status === 409 && e.data?.code === "failover_active") {
      const f = e.data.failover as FailoverStatus | undefined;
      if (f) useObsStore.getState().setFailover(f);
      if (!(await useObsStore.getState().requestConfirm(label))) throw new ActionCancelled();
      return apiFetch<T>(withForce(path), options);
    }
    throw e;
  }
}
