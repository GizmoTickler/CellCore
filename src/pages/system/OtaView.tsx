import React, { useEffect, useState } from "react";
import { ArrowRight, CheckCircle2, Download, Loader2, Package, RefreshCw, ShieldCheck, TriangleAlert, XCircle } from "lucide-react";
import { cn } from "../../lib/utils";
import { Badge, Button, Card, CardHeader, Modal, Skeleton } from "../../components/ui";
import { FailoverWarning } from "../../components/obs";
import type { SystemController } from "./useSystemController";

/** Split "4.0.0-1" into [4,0,0] + release "1" (display only; ordering is decided by the daemon). */
function splitVersion(v: string): { nums: string[]; rel: string | null } {
  const [main, rel] = v.split("-", 2);
  return { nums: main.split("."), rel: rel ?? null };
}

function changeKind(from: string, to: string): string {
  const a = splitVersion(from);
  const b = splitVersion(to);
  const names = ["Major", "Minor", "Patch"];
  for (let i = 0; i < Math.max(a.nums.length, b.nums.length); i++) {
    if (a.nums[i] !== b.nums[i]) return `${names[i] ?? "Build"} update`;
  }
  if (a.rel !== b.rel) return "Package rebuild";
  return "Update";
}

/** "just now", "5 min ago", "3 h ago", "2 d ago". */
function relativeTime(unixSecs: number | null | undefined, now: number): string {
  if (!unixSecs) return "never";
  const d = Math.max(0, Math.round(now / 1000 - unixSecs));
  if (d < 45) return "just now";
  if (d < 3600) return `${Math.round(d / 60)} min ago`;
  if (d < 86400) return `${Math.round(d / 3600)} h ago`;
  return `${Math.round(d / 86400)} d ago`;
}

/** Render a version with the segments that differ from `base` emphasised. */
function VersionDiff({ version, base, tone }: { version: string; base: string; tone: "old" | "new" }) {
  const tokens = version.split(/([.-])/);
  const baseTokens = base.split(/([.-])/);
  let diverged = false;
  return (
    <span className="font-mono">
      {tokens.map((t, i) => {
        if (!diverged && t !== baseTokens[i]) diverged = true;
        const sep = t === "." || t === "-";
        return (
          <span
            key={i}
            className={cn(
              !sep && diverged && (tone === "new" ? "text-ember-ink font-semibold" : "text-muted line-through decoration-1")
            )}
          >
            {t}
          </span>
        );
      })}
    </span>
  );
}

export function OtaView({ ctl }: { ctl: SystemController }) {
  const q = ctl.pkgInfoQuery;
  const d = q.data;
  const pkg = d?.package ?? "sdxpinn-cellcore";
  const installed = d?.installedVersion ?? null;
  const available = d?.availableVersion ?? null;
  const state = d?.state ?? (d?.updateAvailable ? "updateAvailable" : "unknown");
  const upgrade = d?.upgrade;
  const installing = ctl.otaWatch != null || upgrade?.state === "running";
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), 30000);
    return () => window.clearInterval(t);
  }, []);
  const checking = ctl.busy === "ota-check";
  const checkedLabel = `checked ${relativeTime(d?.lastChecked, now)}`;
  const canInstall = state === "updateAvailable" && installed != null && available != null && !installing;

  return (
    <div className="grid gap-5 lg:grid-cols-12">
      {/* Verdict */}
      <Card className={cn("lg:col-span-8 min-w-0 relative overflow-hidden", canInstall && "qm-grain")}>
        {canInstall && <div className="pointer-events-none absolute inset-0 opacity-100" style={{ background: "var(--qm-sun-soft)" }} />}
        <div className="relative z-[1]">
          {q.isLoading ? (
            <div className="space-y-3">
              <Skeleton className="h-6 w-40" />
              <Skeleton className="h-14 w-72" />
              <Skeleton className="h-4 w-56" />
            </div>
          ) : installing ? (
            <InstallProgress
              status={upgrade?.state ?? "running"}
              from={upgrade?.from || installed || ""}
              target={upgrade?.target || ctl.otaWatch?.target || available || ""}
              message={upgrade?.message ?? null}
              log={d?.upgradeLog ?? []}
              reconnecting={q.isError}
            />
          ) : canInstall ? (
            <div className="space-y-5">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="info" dot>
                  Update available
                </Badge>
                <Badge variant="neutral">{changeKind(installed, available)}</Badge>
                <span className="text-[12px] text-muted">{checkedLabel}</span>
              </div>
              <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
                <span className="text-[1.5rem] sm:text-[1.9rem] leading-none text-ink-2">
                  <VersionDiff version={installed} base={available} tone="old" />
                </span>
                <ArrowRight className="h-6 w-6 shrink-0 text-ember-ink" />
                <span className="text-[1.9rem] sm:text-[2.4rem] leading-none text-ink">
                  <VersionDiff version={available} base={installed} tone="new" />
                </span>
              </div>
              <div className="rounded-2xl bg-surface/70 border border-line p-4">
                <div className="qm-eyebrow mb-2">What will change</div>
                <ul className="space-y-1.5 text-[13px] text-ink-2">
                  <li className="flex gap-2">
                    <Package className="h-4 w-4 mt-0.5 shrink-0 text-muted" />
                    <span>
                      <span className="font-mono text-ink">{pkg}</span> is replaced with {available} from the signed feed.
                    </span>
                  </li>
                  <li className="flex gap-2">
                    <RefreshCw className="h-4 w-4 mt-0.5 shrink-0 text-muted" />
                    <span>CellCore restarts during the install. This page follows along and reloads when it is back.</span>
                  </li>
                  {upgrade?.state === "failed" && (
                    <li className="flex gap-2 text-crimson-ink">
                      <XCircle className="h-4 w-4 mt-0.5 shrink-0" />
                      <span>
                        The last install of {upgrade.target} failed{upgrade.exitCode != null ? ` (opkg exit ${upgrade.exitCode})` : ""}.
                        {upgrade.message ? ` ${upgrade.message}` : ""}
                      </span>
                    </li>
                  )}
                </ul>
              </div>
              <div className="flex flex-wrap gap-2">
                <Button variant="tier1" size="lg" onClick={() => setConfirmOpen(true)} disabled={ctl.busy === "ota-upgrade"}>
                  <Download className="h-4 w-4" />
                  {ctl.busy === "ota-upgrade" ? "Starting…" : `Install ${available}`}
                </Button>
              </div>
            </div>
          ) : state === "unknown" ? (
            <div className="flex flex-col gap-5 sm:flex-row sm:items-center">
              <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl bg-saffron-soft text-saffron-ink">
                <TriangleAlert className="h-7 w-7" />
              </div>
              <div className="min-w-0">
                <div className="qm-eyebrow">Update status unknown</div>
                <div className="mt-1 text-[1.6rem] leading-none text-ink font-mono break-all">{installed ?? "Installed version unknown"}</div>
                <p className="mt-2 text-[13px] text-muted">
                  {available == null ? "The signed feed has not been read yet. Check for updates." : "The installed version could not be read."}
                </p>
                {(d?.errors ?? []).length > 0 && (
                  <ul className="mt-2 space-y-0.5 text-[12px] text-saffron-ink">
                    {d!.errors!.map((e) => (
                      <li key={e} className="break-all">
                        {e}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          ) : (
            <div className="flex flex-col gap-5 sm:flex-row sm:items-center">
              <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl bg-jade-soft text-jade-ink">
                <CheckCircle2 className="h-7 w-7" />
              </div>
              <div className="min-w-0">
                <div className="qm-eyebrow">
                  Up to date · {checkedLabel}
                </div>
                <div className="mt-1 text-[2rem] sm:text-[2.4rem] leading-none text-ink font-mono break-all">{installed}</div>
                <p className="mt-2 text-[13px] text-muted">
                  {state === "feedOlder"
                    ? `The feed offers ${available}, which is older than what is installed.`
                    : "No newer build on the signed feed."}
                </p>
              </div>
            </div>
          )}
        </div>
      </Card>

      {/* Package facts */}
      <Card className="lg:col-span-4 min-w-0">
        <CardHeader title="Package" icon={<Package className="h-4 w-4" />} />
        <dl className="divide-y divide-line border-y border-line text-[13px]">
          <Row label="Name">
            <span className="font-mono text-[12.5px] break-all">{pkg}</span>
          </Row>
          <Row label="Installed">
            <span className="font-mono">{installed ?? "unknown"}</span>
          </Row>
          <Row label="On feed">
            <span className={cn("font-mono", state === "updateAvailable" && "text-ember-ink font-semibold")}>{available ?? "not read"}</span>
          </Row>
          <Row label="Last checked">
            <span>{relativeTime(d?.lastChecked, now)}</span>
          </Row>
          <Row label="Active boot slot">
            <span className="font-mono">Slot {ctl.internals?.bootSlot || "_a"}</span>
          </Row>
        </dl>
        <Button variant="secondary" className="mt-4 w-full" onClick={ctl.checkOtaFeed} disabled={checking || installing}>
          <RefreshCw className={cn("h-4 w-4", checking && "animate-spin")} />
          {checking ? "Checking feed…" : "Check for updates"}
        </Button>
        <p className={cn("mt-2 text-[11.5px] flex items-center gap-1.5", d?.signatureVerified === false ? "text-crimson-ink" : "text-muted")}>
          {d?.signatureVerified === false ? <XCircle className="h-3.5 w-3.5" /> : <ShieldCheck className="h-3.5 w-3.5" />}
          {d?.signatureVerified === true
            ? "Feed signature verified on the last check."
            : d?.signatureVerified === false
              ? "Feed signature check failed on the last check."
              : "Packages are verified against the SDXPINN feed signature."}
        </p>
      </Card>

      <Modal open={confirmOpen} onClose={() => setConfirmOpen(false)} title={`Install ${available ?? "update"}?`}>
        <FailoverWarning action="Installing" />
        <p className="mt-3">
          This upgrades <span className="font-mono text-ink">{pkg}</span> from {installed} to {available}. CellCore restarts while
          it installs, so the console disconnects for a short time and then reloads.
        </p>
        <div className="mt-5 flex justify-end gap-2">
          <Button variant="secondary" onClick={() => setConfirmOpen(false)}>
            Cancel
          </Button>
          <Button
            variant="primary"
            onClick={() => {
              setConfirmOpen(false);
              if (available) void ctl.upgradePackage(available);
            }}
          >
            Install now
          </Button>
        </div>
      </Modal>
    </div>
  );
}

function InstallProgress({
  status,
  from,
  target,
  message,
  log,
  reconnecting,
}: {
  status: string;
  from: string;
  target: string;
  message: string | null;
  log: string[];
  reconnecting: boolean;
}) {
  const failed = status === "failed";
  const done = status === "succeeded";
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        {failed ? (
          <Badge variant="danger" dot>
            Install failed
          </Badge>
        ) : done ? (
          <Badge variant="success" dot>
            Installed, reloading
          </Badge>
        ) : (
          <Badge variant="info" dot>
            Installing
          </Badge>
        )}
        {reconnecting && !failed && <span className="text-[12px] text-muted">Waiting for CellCore to come back…</span>}
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-[1.5rem] sm:text-[1.9rem] leading-none">
        <span className="font-mono text-ink-2">{from}</span>
        <ArrowRight className="h-6 w-6 shrink-0 text-ember-ink" />
        <span className="font-mono text-ink">{target}</span>
        {!failed && !done && <Loader2 className="h-5 w-5 animate-spin text-muted" />}
      </div>
      {message && <p className="text-[13px] text-crimson-ink">{message}</p>}
      <pre className="qm-subcard max-h-56 overflow-auto whitespace-pre-wrap break-all rounded-xl bg-sunk p-3 font-mono text-[11.5px] text-ink-2">
        {log.length ? log.join("\n") : "Starting installer…"}
      </pre>
    </div>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3 py-2.5">
      <dt className="text-muted shrink-0">{label}</dt>
      <dd className="min-w-0 text-right text-ink">{children}</dd>
    </div>
  );
}
