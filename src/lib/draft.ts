import { useCallback, useRef, useState } from "react";

/**
 * A form field backed by server state that background polling can never clobber.
 *
 * While the user has not touched the field it shows the server value (or `fallback` until the
 * first load). The first edit makes it dirty: from then on only the user's value is shown, no
 * matter how often the query refetches, until `reset()` (call it after a successful save, once
 * the refetch has landed, or on "discard") hands the field back to the server.
 */
export function useDraft<T>(server: T | null | undefined, fallback: T) {
  const [local, setLocal] = useState<{ v: T } | null>(null);
  const base = server ?? fallback;
  const baseRef = useRef(base);
  baseRef.current = base;
  const value = local ? local.v : base;
  const set = useCallback((next: T | ((prev: T) => T)) => {
    setLocal((cur) => {
      const prev = cur ? cur.v : baseRef.current;
      return { v: typeof next === "function" ? (next as (p: T) => T)(prev) : next };
    });
  }, []);
  const reset = useCallback(() => setLocal(null), []);
  return [value, set, { dirty: local !== null, reset }] as const;
}

export type Draft<T> = ReturnType<typeof useDraft<T>>;

/** Reset several drafts at once (after a save that covered all of them). */
export function resetAll(...drafts: Array<{ reset: () => void }>) {
  for (const d of drafts) d.reset();
}
