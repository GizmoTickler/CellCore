import { useCallback, useEffect } from "react";
import { create } from "zustand";
import type { AppRoute } from "@/types/cellcore";

/**
 * Hash router: `#/<section>/<sub>`. Sections are the top-level pages, `sub` is the
 * optional sub-view inside a page (e.g. `#/cellular/bands`). Every view is
 * deep-linkable, so the rail, the command palette and browser history all agree.
 */
export type Section = Exclude<AppRoute, "/login">;

interface ParsedRoute {
  section: Section | "/login";
  sub: string | null;
}

const SECTIONS: Section[] = ["/", "/cellular", "/network", "/diagnostics", "/system", "/admin"];

export function parseHash(hash = window.location.hash): ParsedRoute {
  const raw = hash.replace(/^#/, "") || "/";
  if (raw.startsWith("/login")) return { section: "/login", sub: null };
  const parts = raw.split("/").filter(Boolean);
  const head = `/${parts[0] ?? ""}` as Section;
  const section = SECTIONS.includes(head) ? head : "/";
  const sub = section === "/" ? null : (parts[1] ?? null);
  return { section, sub };
}

export function hrefFor(section: Section, sub?: string | null): string {
  if (section === "/") return "#/";
  return sub ? `#${section}/${sub}` : `#${section}`;
}

export function navigate(section: Section, sub?: string | null) {
  const next = hrefFor(section, sub);
  if (window.location.hash !== next) window.location.hash = next;
  useRouteStore.getState().sync();
}

interface RouteState extends ParsedRoute {
  sync: () => void;
}

export const useRouteStore = create<RouteState>((set) => ({
  ...parseHash(),
  sync: () => set(parseHash()),
}));

if (typeof window !== "undefined") {
  window.addEventListener("hashchange", () => useRouteStore.getState().sync());
}

/**
 * Page-level sub-view state bound to the URL. Falls back to `fallback` when the
 * hash names an unknown sub-view.
 */
export function useSubRoute<T extends string>(
  section: Section,
  allowed: readonly T[],
  fallback: T
): [T, (next: T) => void] {
  const current = useRouteStore((s) => (s.section === section ? s.sub : null));
  const value = (current && (allowed as readonly string[]).includes(current) ? current : fallback) as T;
  const set = useCallback((next: T) => navigate(section, next), [section]);
  useEffect(() => {
    window.scrollTo({ top: 0 });
  }, [value]);
  return [value, set];
}
