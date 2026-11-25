import React, { useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ArrowRight, Eye, EyeOff, Lock, Moon, Sun } from "lucide-react";
import { apiFetch } from "../lib/api";
import { playHudSuccess } from "../lib/hud-fx";
import { usePointerGlow } from "../lib/motion";
import { cn, signalPercent } from "../lib/utils";
import { useAuthStore } from "../stores/auth-store";
import { SKINS, useThemeStore } from "../stores/theme-store";
import type { AuthStateResponse, PublicPreviewResponse } from "../types/cellcore";
import { APP_VERSION, BrandMark, Button, Input, SignalDial } from "../components/ui";

export function LoginPage({ onSuccess }: { onSuccess?: () => void }) {
  const theme = useThemeStore((s) => s.theme);
  const onToggleTheme = useThemeStore((s) => s.toggleTheme);
  const skin = useThemeStore((s) => s.skin);
  const setSkin = useThemeStore((s) => s.setSkin);
  const setAuthenticated = useAuthStore((s) => s.setAuthenticated);
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const signInCardRef = useRef<HTMLDivElement>(null);
  usePointerGlow(signInCardRef);

  const rfPreview = useQuery({
    queryKey: ["public-rf-preview"],
    queryFn: () => apiFetch<PublicPreviewResponse>("/api/v1/public/preview", { skipAuthRedirect: true }),
    refetchInterval: 5000,
    retry: 1,
  });

  const summary = useMemo(() => {
    const p = rfPreview.data;
    const carriers = p?.carriers ?? [];
    const mimo = p?.mimo ?? { rsrp: [null, null, null, null], rsrq: [null, null, null, null], sinr: [null, null, null, null], rat: "NR5G" };
    const totalBw = p?.totalBandwidthMhz ?? carriers.reduce((sum, c) => sum + (c.bandwidthMhz ?? 0), 0);
    const validRsrp = mimo.rsrp.filter((v): v is number => v != null);
    const avgRsrp =
      validRsrp.length > 0 ? Math.round((validRsrp.reduce((a, b) => a + b, 0) / validRsrp.length) * 10) / 10 : null;
    const validSinr = mimo.sinr.filter((v): v is number => v != null);
    const avgSinr =
      validSinr.length > 0 ? Math.round((validSinr.reduce((a, b) => a + b, 0) / validSinr.length) * 10) / 10 : null;
    return {
      carriers,
      mimo,
      operator: p?.operator || "Searching PLMN",
      rat: p?.rat || mimo.rat || "NR5G",
      model: p?.model || "RM551E-GL",
      totalBw,
      avgRsrp,
      avgSinr,
    };
  }, [rfPreview.data]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!password) {
      setError("Enter administrator password");
      return;
    }
    setSubmitting(true);
    setError("");
    try {
      const res = await apiFetch<AuthStateResponse>("/api/v1/auth/login", {
        method: "POST",
        skipAuthRedirect: true,
        body: JSON.stringify({ password }),
      });
      if (res?.status === "success" || res?.state === "success") {
        playHudSuccess();
        setAuthenticated(true, res.token, res.csrfToken ?? null);
        onSuccess?.();
      } else {
        setError(res?.error || res?.message || "Invalid administrator password");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Authentication failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex flex-col min-h-screen lg:grid lg:grid-cols-2">
      {/* ── Signal panel ─────────────────────────────────────────── */}
      <section className="relative overflow-hidden qm-sun-ink qm-grain text-on-ember px-6 py-8 sm:px-10 lg:px-14 lg:py-12 flex flex-col">
        {/* Volumetric bloom backdrop */}
        <div aria-hidden className="pointer-events-none absolute -bottom-48 -left-32 h-[520px] w-[520px] rounded-full bg-ember/25 blur-3xl" />
        <div
          aria-hidden
          className="pointer-events-none absolute -top-36 right-[-14%] h-[440px] w-[440px] rounded-full blur-3xl opacity-35"
          style={{ background: "radial-gradient(circle, rgba(255, 255, 255, 0.34) 0%, transparent 68%)" }}
        />
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0 opacity-25"
          style={{ background: "radial-gradient(620px 380px at 26% 62%, rgba(255, 255, 255, 0.22), transparent 68%)" }}
        />
        <div className="relative flex items-center gap-3">
          <BrandMark className="bg-on-ember/15 shadow-none ring-1 ring-on-ember/30 [background-image:none]" />
          <div className="leading-tight">
            <div className="qm-display text-[1.15rem]">CellCore</div>
            <div className="text-[12px] font-medium">
              {summary.model} · {APP_VERSION}
            </div>
          </div>
        </div>

        <div className="relative mt-8 lg:mt-auto flex flex-col items-center lg:items-start gap-6">
          <div className="flex flex-col sm:flex-row items-center gap-6 sm:gap-10">
            <SignalDial
              value={summary.avgRsrp != null ? Math.round(summary.avgRsrp) : null}
              sinr={summary.avgSinr ?? 22}
              activityPct={summary.avgRsrp != null ? 45 : 25}
              live
              size={200}
              unit="dBm mean RSRP"
              onDark
            />
            <div className="text-center sm:text-left">
              <div className="text-[11px] font-bold uppercase tracking-[0.16em]">Live right now</div>
              <div className="qm-display mt-1.5 text-[2rem] sm:text-[2.4rem] leading-[1.05]">{summary.operator}</div>
              <div className="mt-1 text-[14px]">
                {summary.rat}
                {summary.carriers.length > 0 && ` · ${summary.carriers.length} carriers · ${summary.totalBw} MHz`}
              </div>
            </div>
          </div>

          {summary.carriers.length > 0 && (
            <div className="flex flex-wrap w-full max-w-lg gap-1.5" aria-label="Aggregated carriers">
              {summary.carriers.map((c, idx) => (
                <div
                  key={`${c.arfcn}-${idx}`}
                  style={{ flexGrow: Math.max(c.bandwidthMhz ?? 10, 12), flexBasis: "58px" }}
                  className={cn(
                    "min-w-[58px] rounded-xl px-2.5 py-1.5 whitespace-nowrap overflow-hidden",
                    c.role === "PCC" ? "bg-on-ember text-ember" : "text-on-ember ring-1 ring-on-ember/40"
                  )}
                >
                  <div className="text-[12.5px] font-extrabold leading-tight">{c.band}</div>
                  <div className="text-[10.5px] font-semibold qm-tabular">{c.bandwidthMhz ?? "—"}M</div>
                </div>
              ))}
            </div>
          )}

          <div className="grid w-full max-w-lg grid-cols-4 gap-2">
            {[0, 1, 2, 3].map((idx) => {
              const rsrp = summary.mimo.rsrp[idx];
              return (
                <div key={idx} className="rounded-xl ring-1 ring-on-ember/25 px-2.5 py-2">
                  <div className="flex items-baseline justify-between text-[11px] font-bold">
                    <span className="font-semibold">RX{idx}</span>
                    <span className="qm-tabular">{rsrp ?? "—"}</span>
                  </div>
                  <div className="mt-1.5 h-1 rounded-full bg-on-ember/20 overflow-hidden">
                    <div className="h-full rounded-full bg-on-ember" style={{ width: `${rsrp != null ? signalPercent("rsrp", rsrp) : 0}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* ── Sign-in ──────────────────────────────────────────────── */}
      <section className="order-first lg:order-none flex flex-col px-6 py-10 sm:px-10 lg:px-16">
        <div className="flex justify-end">
          <Button variant="ghost" size="sm" className="px-2.5" onClick={onToggleTheme} aria-label="Toggle light or dark mode">
            {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </Button>
        </div>

        <div className="my-auto w-full max-w-sm mx-auto py-6">
          <div ref={signInCardRef} className="qm-card qm-hud-card qm-reticle qm-page-enter p-6 sm:p-7">
            <div className="qm-eyebrow">Gateway console</div>
            <h1 className="qm-display mt-2 text-[2.2rem] leading-tight text-ink">Sign in</h1>
            <p className="mt-2 text-[14px] text-ink-2">Use the gateway&apos;s root password.</p>

            <form onSubmit={handleSubmit} className="mt-7 space-y-4">
              <div>
                <label className="block text-[12.5px] font-semibold mb-1.5 text-ink-2" htmlFor="qm-password">
                  Password
                </label>
                <div className="relative">
                  <Lock className="h-4 w-4 text-muted absolute left-3.5 top-3.5 pointer-events-none" />
                  <Input
                    id="qm-password"
                    type={showPassword ? "text" : "password"}
                    autoComplete="current-password"
                    autoFocus={typeof window !== "undefined" && typeof window.matchMedia === "function" && window.matchMedia("(min-width: 1024px)").matches}
                    placeholder="Root password"
                    value={password}
                    onChange={(e: React.ChangeEvent<HTMLInputElement>) => setPassword(e.target.value)}
                    className="h-11 pl-10 pr-11 text-[16px] sm:text-[14px]"
                    aria-invalid={Boolean(error)}
                    aria-describedby={error ? "qm-login-error" : undefined}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((v) => !v)}
                    aria-label={showPassword ? "Hide password" : "Show password"}
                    className="absolute right-2 top-2 rounded-full p-1.5 text-muted hover:text-ink hover:bg-sunk cursor-pointer"
                  >
                    {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </div>

              {error && (
                <div id="qm-login-error" role="alert" className="rounded-xl bg-crimson-soft px-3.5 py-2.5 text-[13px] font-medium text-crimson-ink">
                  {error}
                </div>
              )}

              <Button type="submit" variant="tier1" size="lg" className="w-full" disabled={submitting}>
                {submitting ? "Signing in…" : "Sign in"}
                {!submitting && <ArrowRight className="h-4 w-4" />}
              </Button>
            </form>
          </div>
        </div>

        <div className="mx-auto w-full max-w-sm">
          <div className="qm-eyebrow mb-2">Theme</div>
          <div className="grid grid-cols-4 gap-1.5">
            {SKINS.map((sk) => (
              <button
                key={sk.id}
                type="button"
                onClick={() => setSkin(sk.id)}
                title={sk.hint}
                aria-pressed={skin === sk.id}
                className={cn(
                  "min-w-0 truncate rounded-xl border px-2 py-2 text-[11.5px] font-bold transition cursor-pointer",
                  skin === sk.id ? "border-ember bg-ember-soft text-ember-ink" : "border-line text-muted hover:text-ink"
                )}
              >
                {sk.label.split(" ")[0]}
              </button>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}
