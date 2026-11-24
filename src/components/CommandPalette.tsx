import React, { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { CornerDownLeft, Search } from "lucide-react";
import { NAV } from "../lib/nav";
import { cn } from "../lib/utils";
import { navigate } from "../stores/route-store";
import { Kbd } from "./ui";
import { NavIcon } from "./NavIcon";

export interface PaletteAction {
  id: string;
  label: string;
  hint?: string;
  keywords?: string;
  icon: React.ReactNode;
  tone?: "danger";
  run: () => void;
}

interface Entry {
  id: string;
  group: "Go to" | "Actions";
  label: string;
  hint: string;
  haystack: string;
  icon: React.ReactNode;
  tone?: "danger";
  run: () => void;
}

/**
 * Lower-case and drop the separators used in labels ("Diagnostics › Latency", "TTL · MTU · DNS",
 * "Profiles & MBN") so a label typed or pasted in full matches its entry.
 */
export function normalize(s: string): string {
  return s
    .toLowerCase()
    .replace(/[›»>·•&|/,:;()]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Filter (every term must appear) and rank: the exact label first, then labels that start
 * with the query, then labels that contain every term, then the rest. Ties keep NAV order.
 */
export function rankEntries<E extends { label: string; haystack: string }>(entries: E[], query: string): E[] {
  const qn = normalize(query);
  const terms = qn.split(" ").filter(Boolean);
  if (!terms.length) return entries;
  const score = (e: E) => {
    const label = normalize(e.label);
    if (label === qn) return 1000;
    // the sub-view label alone ("Latency" for "Diagnostics › Latency")
    if (label.endsWith(` ${qn}`)) return 800;
    if (label.startsWith(qn)) return 600;
    if (terms.every((t) => label.split(" ").includes(t))) return 400;
    if (terms.every((t) => label.includes(t))) return 300;
    if (label.startsWith(terms[0])) return 100;
    return 0;
  };
  return entries
    .filter((e) => terms.every((t) => e.haystack.includes(t)))
    .map((e, i) => ({ e, i, s: score(e) }))
    .sort((a, b) => b.s - a.s || a.i - b.i)
    .map((x) => x.e);
}

export function CommandPalette({
  open,
  onClose,
  actions,
}: {
  open: boolean;
  onClose: () => void;
  actions: PaletteAction[];
}) {
  if (!open) return null;
  return <CommandPaletteDialog onClose={onClose} actions={actions} />;
}

function CommandPaletteDialog({
  onClose,
  actions,
}: {
  onClose: () => void;
  actions: PaletteAction[];
}) {
  const [q, setQ] = useState("");
  const [cursor, setCursor] = useState(0);
  const dialogRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const entries = useMemo<Entry[]>(() => {
    const out: Entry[] = [];
    for (const sec of NAV) {
      out.push({
        id: `go:${sec.route}`,
        group: "Go to",
        label: sec.label,
        hint: sec.hint,
        haystack: normalize(`${sec.label} ${sec.hint}`),
        icon: <NavIcon name={sec.icon} className="h-4 w-4" />,
        run: () => navigate(sec.route),
      });
      for (const sub of sec.subs) {
        out.push({
          id: `go:${sec.route}/${sub.id}`,
          group: "Go to",
          label: `${sec.label} › ${sub.label}`,
          hint: sub.hint,
          haystack: normalize(`${sec.label} ${sub.label} ${sub.hint} ${sub.keywords ?? ""}`),
          icon: <NavIcon name={sec.icon} className="h-4 w-4" />,
          run: () => navigate(sec.route, sub.id),
        });
      }
    }
    for (const a of actions) {
      out.push({
        id: `act:${a.id}`,
        group: "Actions",
        label: a.label,
        hint: a.hint ?? "",
        haystack: normalize(`${a.label} ${a.hint ?? ""} ${a.keywords ?? ""}`),
        icon: a.icon,
        tone: a.tone,
        run: a.run,
      });
    }
    return out;
  }, [actions]);

  const results = useMemo(() => rankEntries(entries, q), [entries, q]);

  useEffect(() => {
    inputRef.current?.focus();
    const raf = window.requestAnimationFrame(() => inputRef.current?.focus());
    const keepFocus = (ev: FocusEvent) => {
      const t = ev.target as Node | null;
      if (t && dialogRef.current && !dialogRef.current.contains(t)) {
        inputRef.current?.focus();
      }
    };
    document.addEventListener("focusin", keepFocus, true);
    return () => {
      window.cancelAnimationFrame(raf);
      document.removeEventListener("focusin", keepFocus, true);
    };
  }, []);

  useEffect(() => setCursor(0), [q]);

  useEffect(() => {
    listRef.current?.querySelector(`[data-idx="${cursor}"]`)?.scrollIntoView({ block: "nearest" });
  }, [cursor]);

  const choose = (e?: Entry) => {
    if (!e) return;
    onClose();
    e.run();
  };

  const onKey = (ev: React.KeyboardEvent) => {
    if (ev.key === "ArrowDown") {
      ev.preventDefault();
      setCursor((c) => Math.min(results.length - 1, c + 1));
    } else if (ev.key === "ArrowUp") {
      ev.preventDefault();
      setCursor((c) => Math.max(0, c - 1));
    } else if (ev.key === "Enter") {
      ev.preventDefault();
      choose(results[cursor]);
    } else if (ev.key === "Escape") {
      onClose();
    }
  };

  let lastGroup = "";
  const dialog = (
    <div
      ref={dialogRef}
      className="fixed inset-0 z-[80] flex items-start justify-center bg-stone-950/40 backdrop-blur-sm p-3 pt-[12vh]"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="Command palette"
    >
      <div className="qm-card qm-dialog qm-rise w-full max-w-xl overflow-hidden p-0 shadow-[var(--qm-shadow-pop)]" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-3 border-b border-line px-4">
          <Search className="h-4.5 w-4.5 text-ember-ink shrink-0" />
          <input
            ref={inputRef}
            autoFocus
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={onKey}
            placeholder="Jump to a page, setting or action…"
            className="h-14 w-full bg-transparent text-[16px] sm:text-[15px] text-ink placeholder:text-muted focus:outline-none"
            aria-label="Search commands"
          />
          <Kbd>esc</Kbd>
        </div>
        <div ref={listRef} className="max-h-[52vh] overflow-y-auto p-2">
          {results.length === 0 && <div className="px-3 py-10 text-center text-[13px] text-muted">Nothing matches “{q}”.</div>}
          {results.map((e, i) => {
            const header = e.group !== lastGroup ? e.group : null;
            lastGroup = e.group;
            return (
              <React.Fragment key={e.id}>
                {header && <div className="qm-eyebrow px-3 pt-3 pb-1.5">{header}</div>}
                <button
                  type="button"
                  data-idx={i}
                  onMouseMove={() => setCursor(i)}
                  onClick={() => choose(e)}
                  className={cn(
                    "flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-left cursor-pointer",
                    i === cursor ? "bg-ember-soft" : "hover:bg-sunk"
                  )}
                >
                  <span
                    className={cn(
                      "flex h-8 w-8 shrink-0 items-center justify-center rounded-lg",
                      e.tone === "danger" ? "bg-crimson-soft text-crimson-ink" : i === cursor ? "bg-raised text-ember-ink" : "bg-sunk text-ink-2"
                    )}
                  >
                    {e.icon}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className={cn("block text-[13.5px] font-semibold truncate", e.tone === "danger" ? "text-crimson-ink" : "text-ink")}>
                      {e.label}
                    </span>
                    {e.hint && <span className="block text-[12px] text-muted truncate">{e.hint}</span>}
                  </span>
                  {i === cursor && <CornerDownLeft className="h-4 w-4 text-ember-ink shrink-0" />}
                </button>
              </React.Fragment>
            );
          })}
        </div>
        <div className="flex items-center gap-3 border-t border-line bg-sunk px-4 py-2 text-[11.5px] text-muted">
          <span className="inline-flex items-center gap-1">
            <Kbd>↑</Kbd>
            <Kbd>↓</Kbd> move
          </span>
          <span className="inline-flex items-center gap-1">
            <Kbd>↵</Kbd> open
          </span>
          <span className="ml-auto inline-flex items-center gap-1">
            <Kbd>⌘</Kbd>
            <Kbd>K</Kbd> anywhere
          </span>
        </div>
      </div>
    </div>
  );
  return typeof document !== "undefined" ? createPortal(dialog, document.body) : dialog;
}
