import React, { useCallback, useState } from "react";
import { useQuery, type UseQueryOptions } from "@tanstack/react-query";
import { AlertTriangle, Info, ShieldAlert } from "lucide-react";
import { ApiError, apiFetch } from "../../lib/api";
import { isCancelled } from "../../lib/disruptive";
import { cn } from "../../lib/utils";
import { Button, Input, Modal } from "../../components/ui";
import { useToastStore } from "../../stores/toast-store";

export const ADMIN = "/api/v1/admin";

export function errText(e: unknown, fallback = "Request failed"): string {
  if (e instanceof Error && e.message) return e.message;
  return fallback;
}

/** GET an admin endpoint through react-query. */
export function useAdmin<T>(path: string, opts: Partial<UseQueryOptions<T>> = {}) {
  return useQuery<T>({
    queryKey: ["admin", path],
    queryFn: () => apiFetch<T>(`${ADMIN}${path}`),
    staleTime: 15_000,
    ...opts,
  });
}

export function adminSend<T = Record<string, unknown>>(method: "POST" | "PUT" | "DELETE", path: string, body?: unknown): Promise<T> {
  return apiFetch<T>(`${ADMIN}${path}`, { method, body: body === undefined ? undefined : JSON.stringify(body) });
}

/* ───────────────────────── Guarded actions ───────────────────────── */

interface GuardSpec<T> {
  title: string;
  /** What happens, in plain words. Shown before anything runs. */
  body: React.ReactNode;
  confirmLabel?: string;
  tone?: "danger" | "primary";
  /** Runs the action. `confirm` is the typed phrase once the server asked for one (HTTP 428). */
  action: (confirm?: string) => Promise<T>;
  onDone?: (res: T) => void;
  success?: string;
}

interface GuardState {
  spec: GuardSpec<unknown>;
  phrase: string | null;
  serverMsg: string | null;
}

/**
 * Confirm-then-run flow shared by every risky admin action: a modal states what
 * will happen; if the daemon answers 428 it switches to "type X to continue".
 */
export function useGuarded() {
  const toast = useToastStore((s) => s.push);
  const [state, setState] = useState<GuardState | null>(null);
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);

  const run = useCallback(<T,>(spec: GuardSpec<T>) => {
    setTyped("");
    setState({ spec: spec as GuardSpec<unknown>, phrase: null, serverMsg: null });
  }, []);

  const close = useCallback(() => {
    if (!busy) setState(null);
  }, [busy]);

  const go = useCallback(async () => {
    if (!state) return;
    setBusy(true);
    try {
      const res = await state.spec.action(state.phrase ? typed.trim() : undefined);
      setState(null);
      if (state.spec.success) toast(state.spec.success, "success");
      state.spec.onDone?.(res);
    } catch (e) {
      if (isCancelled(e)) {
        setState(null);
        return;
      }
      if (e instanceof ApiError && e.status === 428 && typeof e.data?.confirm === "string") {
        setTyped("");
        setState({ ...state, phrase: e.data.confirm as string, serverMsg: e.message });
      } else {
        setState(null);
        toast(state.spec.title.replace(/\?$/, "") + " failed", "error", errText(e));
      }
    } finally {
      setBusy(false);
    }
  }, [state, typed, toast]);

  const modal = state ? (
    <Modal open onClose={close} title={state.spec.title}>
      <div className="space-y-3">
        <div className="space-y-2">{state.spec.body}</div>
        {state.phrase && (
          <div className="rounded-xl border border-crimson/40 bg-crimson-soft p-3 space-y-2">
            <p className="flex gap-2 text-[12.5px] text-crimson-ink">
              <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{state.serverMsg}</span>
            </p>
            <label className="block text-[12px] font-semibold text-ink-2">
              Type <span className="font-mono text-ink">{state.phrase}</span> to continue
              <Input
                autoFocus
                className="mt-1.5 font-mono"
                value={typed}
                onChange={(e) => setTyped(e.target.value)}
                autoComplete="off"
                spellCheck={false}
                aria-label={`Type ${state.phrase} to confirm`}
              />
            </label>
          </div>
        )}
      </div>
      <div className="mt-5 flex flex-wrap justify-end gap-2">
        <Button variant="secondary" onClick={close} disabled={busy}>
          Cancel
        </Button>
        <Button
          variant={state.spec.tone === "primary" ? "primary" : "danger"}
          onClick={go}
          disabled={busy || (state.phrase !== null && typed.trim() !== state.phrase)}
        >
          {busy ? "Working…" : (state.spec.confirmLabel ?? "Continue")}
        </Button>
      </div>
    </Modal>
  ) : null;

  return { run, modal, busy };
}

/* ───────────────────────── Small parts ───────────────────────── */

export function Notice({
  tone = "info",
  title,
  children,
  className,
}: {
  tone?: "info" | "warn" | "danger";
  title?: React.ReactNode;
  children?: React.ReactNode;
  className?: string;
}) {
  const s = {
    info: { box: "border-line bg-sunk", ink: "text-ink-2", Icon: Info, icon: "text-ember-ink" },
    warn: { box: "border-saffron/45 bg-saffron-soft", ink: "text-saffron-ink", Icon: AlertTriangle, icon: "text-saffron-ink" },
    danger: { box: "border-crimson/45 bg-crimson-soft", ink: "text-crimson-ink", Icon: ShieldAlert, icon: "text-crimson-ink" },
  }[tone];
  return (
    <div role={tone === "danger" ? "alert" : undefined} className={cn("flex gap-3 rounded-2xl border p-3.5 text-[12.5px] leading-snug", s.box, className)}>
      <s.Icon className={cn("mt-0.5 h-4 w-4 shrink-0", s.icon)} />
      <div className="min-w-0 space-y-1">
        {title && <div className={cn("font-semibold", tone === "info" ? "text-ink" : s.ink)}>{title}</div>}
        {children && <div className={tone === "info" ? "text-ink-2" : s.ink}>{children}</div>}
      </div>
    </div>
  );
}

/** Horizontally scrollable table shell with the design-system header style. */
export function DataTable({ head, children, className }: { head: React.ReactNode[]; children: React.ReactNode; className?: string }) {
  return (
    <div className={cn("-mx-[var(--qm-pad)] overflow-x-auto", className)}>
      <table className="w-full min-w-max text-[13px]">
        <thead className="bg-sunk text-left text-[11.5px] font-semibold text-muted">
          <tr>
            {head.map((h, i) => (
              <th key={i} className="px-3 py-2 first:pl-[var(--qm-pad)] last:pr-[var(--qm-pad)] whitespace-nowrap">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-line">{children}</tbody>
      </table>
    </div>
  );
}

export function Td({ children, className, mono, num }: { children?: React.ReactNode; className?: string; mono?: boolean; num?: boolean }) {
  return (
    <td
      className={cn(
        "px-3 py-2 align-middle first:pl-[var(--qm-pad)] last:pr-[var(--qm-pad)]",
        mono && "font-mono text-[12px]",
        num && "text-right qm-tabular",
        className
      )}
    >
      {children}
    </td>
  );
}

export function EmptyRow({ cols, children }: { cols: number; children: React.ReactNode }) {
  return (
    <tr>
      <td colSpan={cols} className="px-[var(--qm-pad)] py-6 text-center text-[12.5px] text-muted">
        {children}
      </td>
    </tr>
  );
}

export function LoadError({ error, onRetry, title = "Could not load this view" }: { error: unknown; onRetry?: () => void; title?: string }) {
  return (
    <Notice tone="danger" title={title}>
      <span className="block">{errText(error)}</span>
      {onRetry && (
        <Button size="sm" variant="secondary" className="mt-2" onClick={onRetry}>
          Retry
        </Button>
      )}
    </Notice>
  );
}

export function Mono({ children, className }: { children: React.ReactNode; className?: string }) {
  return <span className={cn("font-mono text-[12px] break-all", className)}>{children}</span>;
}

export function Pre({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <pre className={cn("max-h-80 overflow-auto rounded-xl border border-line bg-sunk p-3 font-mono text-[11.5px] leading-relaxed text-ink-2 whitespace-pre-wrap break-all", className)}>
      {children}
    </pre>
  );
}

export function TextArea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  const { className, ...rest } = props;
  return (
    <textarea
      className={cn(
        "w-full rounded-xl border border-line bg-raised px-3.5 py-2.5 text-[13px] text-ink placeholder:text-muted/80 focus:outline-none focus:ring-4 focus:ring-ember/15 focus:border-ember transition",
        className
      )}
      {...rest}
    />
  );
}

export function formatAgo(secs: number | null | undefined): string {
  if (secs == null) return "never";
  if (secs < 90) return "just now";
  if (secs < 5400) return `${Math.round(secs / 60)} min ago`;
  if (secs < 172800) return `${Math.round(secs / 3600)} h ago`;
  return `${Math.round(secs / 86400)} days ago`;
}
