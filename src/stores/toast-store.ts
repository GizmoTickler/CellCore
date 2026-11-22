import { create } from "zustand";

export interface ToastItem {
  id: string;
  title: string;
  description?: string;
  tone: "success" | "error" | "info";
}

interface ToastTimer {
  handle: number | null;
  startedAt: number;
  remainingMs: number;
}

const timers = new Map<string, ToastTimer>();

function clearTimer(id: string) {
  const t = timers.get(id);
  if (t?.handle != null) {
    window.clearTimeout(t.handle);
  }
  timers.delete(id);
}

interface ToastState {
  toasts: ToastItem[];
  push: (title: string, tone?: ToastItem["tone"], description?: string) => void;
  dismiss: (id: string) => void;
  pause: (id: string) => void;
  resume: (id: string) => void;
}

export const useToastStore = create<ToastState>((set, get) => {
  const schedule = (id: string, ms: number) => {
    const prev = timers.get(id);
    if (prev?.handle != null) window.clearTimeout(prev.handle);
    const handle = window.setTimeout(() => {
      timers.delete(id);
      set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }));
    }, ms);
    timers.set(id, { handle, startedAt: Date.now(), remainingMs: ms });
  };

  return {
    toasts: [],
    push: (title, tone = "info", description) => {
      const id = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
      const durationMs = tone === "error" ? 8000 : 4200;
      set((s) => {
        const kept = s.toasts.slice(-3);
        const dropped = s.toasts.slice(0, Math.max(0, s.toasts.length - 3));
        for (const d of dropped) clearTimer(d.id);
        return { toasts: [...kept, { id, title, tone, description }] };
      });
      schedule(id, durationMs);
    },
    dismiss: (id) => {
      clearTimer(id);
      set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }));
    },
    pause: (id) => {
      const t = timers.get(id);
      if (!t || t.handle == null) return;
      window.clearTimeout(t.handle);
      const elapsed = Date.now() - t.startedAt;
      t.remainingMs = Math.max(800, t.remainingMs - elapsed);
      t.handle = null;
    },
    resume: (id) => {
      const t = timers.get(id);
      if (!t || t.handle != null) return;
      if (!get().toasts.some((x) => x.id === id)) {
        timers.delete(id);
        return;
      }
      schedule(id, t.remainingMs);
    },
  };
});
