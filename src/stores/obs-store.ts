import { create } from "zustand";
import { apiFetch } from "../lib/api";
import type { EventsResponse, FailoverStatus, ObsEvent } from "../types/obs";

/** Recent events kept client-side for the Now card and live pushes. */
const RECENT_CAP = 50;
const LOAD_DEDUP_MS = 1_500;

let loadInFlight: Promise<void> | null = null;
let lastLoadedAt = 0;

interface PendingConfirm {
  label: string;
  resolve: (ok: boolean) => void;
}

interface ObsState {
  failover: FailoverStatus | null;
  recent: ObsEvent[];
  /** Bumped on every pushed event so open views can refetch. */
  eventSeq: number;
  pendingConfirm: PendingConfirm | null;
  setFailover: (f: FailoverStatus | null) => void;
  pushEvent: (e: ObsEvent) => void;
  load: () => Promise<void>;
  /** Ask the user to confirm a disruptive action while carrying failover traffic. */
  requestConfirm: (label: string) => Promise<boolean>;
  resolveConfirm: (ok: boolean) => void;
}

export const useObsStore = create<ObsState>((set, get) => ({
  failover: null,
  recent: [],
  eventSeq: 0,
  pendingConfirm: null,

  setFailover: (failover) => set({ failover }),

  pushEvent: (e) =>
    set((s) => {
      if (s.recent.some((x) => x.id === e.id)) return s;
      return { recent: [e, ...s.recent].slice(0, RECENT_CAP), eventSeq: s.eventSeq + 1 };
    }),

  load: () => {
    if (loadInFlight) return loadInFlight;
    if (lastLoadedAt > 0 && Date.now() - lastLoadedAt < LOAD_DEDUP_MS) {
      return Promise.resolve();
    }
    loadInFlight = (async () => {
      try {
        const [f, ev] = await Promise.all([
          apiFetch<FailoverStatus>("/api/v1/failover"),
          apiFetch<EventsResponse>(`/api/v1/events?limit=${RECENT_CAP}`),
        ]);
        lastLoadedAt = Date.now();
        set({ failover: f, recent: Array.isArray(ev.events) ? ev.events : [] });
      } catch {
        // older daemon or transient error: badges simply stay hidden
      } finally {
        loadInFlight = null;
      }
    })();
    return loadInFlight;
  },

  requestConfirm: (label) => {
    const prev = get().pendingConfirm;
    if (prev) prev.resolve(false);
    return new Promise<boolean>((resolve) => set({ pendingConfirm: { label, resolve } }));
  },

  resolveConfirm: (ok) => {
    const p = get().pendingConfirm;
    set({ pendingConfirm: null });
    p?.resolve(ok);
  },
}));
