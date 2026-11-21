import { create } from "zustand";

export interface ToastItem {
  id: string;
  title: string;
  description?: string;
  tone: "success" | "error" | "info";
}

interface ToastState {
  toasts: ToastItem[];
  push: (title: string, tone?: ToastItem["tone"], description?: string) => void;
  dismiss: (id: string) => void;
}

export const useToastStore = create<ToastState>((set) => ({
  toasts: [],
  push: (title, tone = "info", description) => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    set((s) => ({ toasts: [...s.toasts.slice(-3), { id, title, tone, description }] }));
    window.setTimeout(() => {
      set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }));
    }, 4200);
  },
  dismiss: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
}));
