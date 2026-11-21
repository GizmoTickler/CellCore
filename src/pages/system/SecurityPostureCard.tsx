import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, Lock, RefreshCw, Shield, ShieldCheck, Usb, XCircle } from "lucide-react";
import { apiFetch } from "../../lib/api";
import { cn } from "../../lib/utils";
import { useToastStore } from "../../stores/toast-store";
import { Badge, Button, Card, CardHeader, Meter, Skeleton } from "../../components/ui";
import { LoadError, errText } from "../admin/shared";

interface SecurityCheck {
  id: string;
  title: string;
  status: "pass" | "warn" | "fail";
  detail: string;
  fixAction?: string | null;
}

interface SecurityAuditReport {
  scorePct: number;
  passed: number;
  total: number;
  checks: SecurityCheck[];
}

interface AuditResp {
  status: string;
  audit: SecurityAuditReport;
}

const KEY = ["security-audit"];

function actionLabel(action: string): string {
  switch (action) {
    case "dropbear_lan_only":
      return "Bind SSH to LAN";
    case "apply_sysctls":
      return "Apply Sysctls";
    case "fix_perms":
      return "Fix 0600 Perms";
    case "lock_usb":
      return "Lock USB Port";
    case "unlock_usb":
      return "Unlock USB";
    default:
      return "Fix";
  }
}

export function SecurityPostureCard() {
  const qc = useQueryClient();
  const toast = useToastStore((s) => s.push);
  const [busyAction, setBusyAction] = useState<string | null>(null);

  const q = useQuery({
    queryKey: KEY,
    queryFn: () => apiFetch<AuditResp>("/api/v1/security/audit"),
    staleTime: 20_000,
  });

  async function runHarden(action: string) {
    setBusyAction(action);
    try {
      const res = await apiFetch<{ actions?: string[]; audit?: SecurityAuditReport }>("/api/v1/security/harden", {
        method: "POST",
        body: JSON.stringify({ action }),
      });
      toast("Security hardening applied", "success", res.actions?.join(" · "));
      if (res.audit) {
        qc.setQueryData(KEY, { status: "ok", audit: res.audit });
      } else {
        await qc.invalidateQueries({ queryKey: KEY });
      }
    } catch (e) {
      toast("Hardening action failed", "error", errText(e));
    } finally {
      setBusyAction(null);
    }
  }

  const audit = q.data?.audit;
  const hasAutoFixable = Boolean(
    audit?.checks.some(
      (c) =>
        c.status !== "pass" &&
        c.fixAction &&
        c.fixAction !== "lock_usb" &&
        c.fixAction !== "unlock_usb"
    )
  );

  return (
    <Card className="space-y-4">
      <CardHeader
        title="Security Posture & Hardening"
        subtitle="Live gateway audit across SSH binding, WAN firewall, USB gadget lock, TLS/HSTS/CSP, kernel sysctls, and 5G air-interface cipher"
        icon={<Shield className="h-4 w-4" />}
        action={
          <div className="flex items-center gap-2">
            {hasAutoFixable && (
              <Button
                size="sm"
                variant="primary"
                disabled={busyAction !== null}
                onClick={() => void runHarden("harden_all")}
              >
                <ShieldCheck className="h-3.5 w-3.5" />
                {busyAction === "harden_all" ? "Hardening…" : "Harden Recommended"}
              </Button>
            )}
            <Button
              size="sm"
              variant="ghost"
              disabled={q.isFetching}
              onClick={() => void q.refetch()}
            >
              <RefreshCw className={cn("h-3.5 w-3.5", q.isFetching && "animate-spin")} />
              Re-scan
            </Button>
          </div>
        }
      />

      {q.error ? (
        <LoadError error={q.error} onRetry={() => void q.refetch()} />
      ) : !audit ? (
        <Skeleton className="h-40 w-full" />
      ) : (
        <div className="space-y-4">
          <div className="qm-subcard p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="space-y-1 min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="text-[13.5px] font-semibold text-ink">
                  Hardening Score: {audit.passed} / {audit.total} Checks Passing
                </span>
                <Badge
                  variant={
                    audit.scorePct >= 90 ? "success" : audit.scorePct >= 70 ? "warning" : "danger"
                  }
                >
                  {audit.scorePct}%
                </Badge>
              </div>
              <Meter
                pct={audit.scorePct}
                tone={audit.scorePct >= 90 ? "jade" : audit.scorePct >= 70 ? "saffron" : "crimson"}
                thin
              />
            </div>
            <div className="text-[11.5px] text-muted font-mono shrink-0">
              CLI: cellctl security audit
            </div>
          </div>

          <div className="grid gap-2.5 md:grid-cols-2">
            {audit.checks.map((c) => {
              const Icon =
                c.status === "pass"
                  ? CheckCircle2
                  : c.status === "fail"
                    ? XCircle
                    : AlertTriangle;
              const tone =
                c.status === "pass"
                  ? "text-jade-ink"
                  : c.status === "fail"
                    ? "text-crimson-ink"
                    : "text-saffron-ink";
              return (
                <div
                  key={c.id}
                  className="qm-subcard p-3.5 flex items-start justify-between gap-3 min-w-0"
                >
                  <div className="flex items-start gap-2.5 min-w-0">
                    <Icon className={cn("h-4 w-4 mt-0.5 shrink-0", tone)} />
                    <div className="min-w-0">
                      <div className="text-[13px] font-semibold text-ink">{c.title}</div>
                      <div className="text-[11.5px] text-muted leading-snug mt-0.5 break-words">
                        {c.detail}
                      </div>
                    </div>
                  </div>
                  {c.fixAction && (
                    <Button
                      size="sm"
                      variant={c.status === "pass" ? "ghost" : "secondary"}
                      className="shrink-0"
                      disabled={busyAction !== null}
                      onClick={() => void runHarden(c.fixAction!)}
                    >
                      {c.fixAction.includes("usb") ? (
                        <Usb className="h-3 w-3" />
                      ) : (
                        <Lock className="h-3 w-3" />
                      )}
                      {busyAction === c.fixAction ? "…" : actionLabel(c.fixAction)}
                    </Button>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </Card>
  );
}
