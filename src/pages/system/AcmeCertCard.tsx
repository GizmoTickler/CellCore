import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Award, CheckCircle2, Globe, KeyRound, Loader2, RefreshCw, ShieldCheck, TriangleAlert } from "lucide-react";
import { apiFetch } from "../../lib/api";
import { useToastStore } from "../../stores/toast-store";
import { Badge, Button, Card, CardHeader, Input, SegmentedTabs, Select, Switch } from "../../components/ui";
import { Field } from "./parts";

type AcmeIssuer =
  | "letsencrypt"
  | "letsencrypt_staging"
  | "zerossl"
  | "google"
  | "google_staging"
  | "custom";

type ValidationMethod = "dns-01" | "http-01";

type DnsProvider =
  | "cloudflare"
  | "route53"
  | "digitalocean"
  | "hetzner"
  | "porkbun"
  | "duckdns"
  | "desec"
  | "rfc2136"
  | "webhook";

interface ActiveCertInfo {
  source: string;
  path: string;
  subject: string;
  issuer: string;
  sans: string[];
  notBefore: string;
  notAfter: string;
  daysRemaining: number | null;
}

interface AcmeConfigRedacted {
  enabled: boolean;
  issuer: AcmeIssuer;
  customDirectoryUrl: string;
  email: string;
  domains: string[];
  validation: ValidationMethod;
  eabKid: string;
  hasEabHmacKey: boolean;
  dnsProvider: DnsProvider;
  savedDnsCredentialKeys: string[];
  propagationSeconds: number;
  renewBeforeDays: number;
}

interface AcmeRunState {
  running: boolean;
  lastAttemptTs: number | null;
  lastSuccessTs: number | null;
  lastError: string | null;
  lastMessage: string | null;
  log: string[];
}

interface AcmeResponse {
  status: string;
  cert: ActiveCertInfo;
  config: AcmeConfigRedacted;
  runState: AcmeRunState;
}

const ISSUER_OPTIONS: Array<{ id: AcmeIssuer; label: string; eab?: "required" | "optional"; hint: string }> = [
  { id: "letsencrypt", label: "Let's Encrypt (Production)", hint: "Free 90-day DV certs, no EAB required" },
  { id: "letsencrypt_staging", label: "Let's Encrypt (Staging)", hint: "Untrusted test certs with high rate limits" },
  { id: "zerossl", label: "ZeroSSL", eab: "required", hint: "Free 90-day certs; requires EAB Key ID + HMAC Key from ZeroSSL Developer tab" },
  { id: "google", label: "Google Public CA (GTS)", eab: "required", hint: "Google Trust Services DV certs; requires EAB from gcloud publicca external-account-keys create" },
  { id: "google_staging", label: "Google Public CA (Staging)", eab: "required", hint: "GTS test CA; requires staging EAB credentials" },
  { id: "custom", label: "Custom ACME Directory", eab: "optional", hint: "Step-CA, Vault, Buypass, or any RFC 8555 HTTPS directory" },
];

interface DnsFieldDef {
  key: string;
  label: string;
  placeholder: string;
  secret?: boolean;
  optional?: boolean;
}

const DNS_PROVIDERS: Array<{ id: DnsProvider; label: string; fields: DnsFieldDef[] }> = [
  {
    id: "cloudflare",
    label: "Cloudflare",
    fields: [
      { key: "apiToken", label: "API Token (Zone:DNS:Edit)", placeholder: "Cloudflare scoped API token", secret: true },
      { key: "zoneId", label: "Zone ID (optional — auto-detected)", placeholder: "Leave blank to auto-detect", optional: true },
    ],
  },
  {
    id: "route53",
    label: "AWS Route 53",
    fields: [
      { key: "accessKeyId", label: "AWS Access Key ID", placeholder: "AKIA..." },
      { key: "secretAccessKey", label: "AWS Secret Access Key", placeholder: "Secret key", secret: true },
      { key: "hostedZoneId", label: "Hosted Zone ID", placeholder: "Z0123456789ABCDEF" },
    ],
  },
  {
    id: "digitalocean",
    label: "DigitalOcean",
    fields: [{ key: "apiToken", label: "Personal Access Token", placeholder: "dop_v1_...", secret: true }],
  },
  {
    id: "hetzner",
    label: "Hetzner DNS",
    fields: [{ key: "apiToken", label: "Hetzner DNS API Token", placeholder: "API token", secret: true }],
  },
  {
    id: "porkbun",
    label: "Porkbun",
    fields: [
      { key: "apiKey", label: "API Key", placeholder: "pk1_..." },
      { key: "secretApiKey", label: "Secret API Key", placeholder: "sk1_...", secret: true },
    ],
  },
  {
    id: "duckdns",
    label: "DuckDNS",
    fields: [{ key: "token", label: "DuckDNS Token", placeholder: "UUID token", secret: true }],
  },
  {
    id: "desec",
    label: "deSEC",
    fields: [{ key: "apiToken", label: "deSEC API Token", placeholder: "API token", secret: true }],
  },
  {
    id: "rfc2136",
    label: "RFC 2136 / Knot DNS (TSIG)",
    fields: [
      { key: "server", label: "Authoritative DNS Server (IP[:port])", placeholder: "192.168.120.53:53" },
      { key: "zone", label: "Zone Apex", placeholder: "example.com" },
      { key: "tsigKeyName", label: "TSIG Key Name (HMAC-SHA256)", placeholder: "acme-update." },
      { key: "tsigSecret", label: "TSIG Secret (Base64)", placeholder: "Base64 HMAC-SHA256 secret", secret: true },
    ],
  },
  {
    id: "webhook",
    label: "Custom HTTPS Webhook",
    fields: [
      { key: "url", label: "Webhook HTTPS URL", placeholder: "https://dns-hook.example.com/acme" },
      { key: "bearerToken", label: "Bearer Token (optional)", placeholder: "Optional Authorization token", secret: true, optional: true },
    ],
  },
];

export function AcmeCertCard() {
  const qc = useQueryClient();
  const pushToast = useToastStore((s) => s.push);

  const acmeQuery = useQuery({
    queryKey: ["system-acme"],
    queryFn: () => apiFetch<AcmeResponse>("/api/v1/system/acme"),
    refetchInterval: (q) => (q.state.data?.runState?.running ? 2000 : 30000),
  });

  const data = acmeQuery.data;
  const [hydrated, setHydrated] = useState(false);
  const [enabled, setEnabled] = useState(false);
  const [issuer, setIssuer] = useState<AcmeIssuer>("letsencrypt");
  const [customUrl, setCustomUrl] = useState("");
  const [email, setEmail] = useState("");
  const [domainsText, setDomainsText] = useState("");
  const [validation, setValidation] = useState<ValidationMethod>("dns-01");
  const [eabKid, setEabKid] = useState("");
  const [eabHmac, setEabHmac] = useState("");
  const [dnsProvider, setDnsProvider] = useState<DnsProvider>("cloudflare");
  const [dnsCreds, setDnsCreds] = useState<Record<string, string>>({});
  const [propagationSecs, setPropagationSecs] = useState("30");
  const [renewDays, setRenewDays] = useState("30");
  const [busy, setBusy] = useState<"save" | "issue" | null>(null);

  useEffect(() => {
    if (!data || hydrated) return;
    const c = data.config;
    setEnabled(c.enabled);
    setIssuer(c.issuer);
    setCustomUrl(c.customDirectoryUrl);
    setEmail(c.email);
    setDomainsText(c.domains.join(", "));
    setValidation(c.validation);
    setEabKid(c.eabKid);
    setDnsProvider(c.dnsProvider);
    setPropagationSecs(String(c.propagationSeconds || 30));
    setRenewDays(String(c.renewBeforeDays || 30));
    setHydrated(true);
  }, [data, hydrated]);

  const issuerMeta = useMemo(() => ISSUER_OPTIONS.find((o) => o.id === issuer) ?? ISSUER_OPTIONS[0], [issuer]);
  const providerMeta = useMemo(() => DNS_PROVIDERS.find((p) => p.id === dnsProvider) ?? DNS_PROVIDERS[0], [dnsProvider]);
  const savedKeys = useMemo(() => new Set(data?.config.savedDnsCredentialKeys ?? []), [data]);

  async function saveConfig(): Promise<boolean> {
    setBusy("save");
    try {
      const domains = domainsText
        .split(/[,\s]+/)
        .map((d) => d.trim())
        .filter(Boolean);
      await apiFetch<AcmeResponse>("/api/v1/system/acme", {
        method: "PUT",
        body: JSON.stringify({
          enabled,
          issuer,
          customDirectoryUrl: customUrl,
          email,
          domains,
          validation,
          eabKid,
          ...(eabHmac.trim() ? { eabHmacKey: eabHmac.trim() } : {}),
          dnsProvider,
          dnsCredentials: dnsCreds,
          propagationSeconds: Number(propagationSecs) || 30,
          renewBeforeDays: Number(renewDays) || 30,
        }),
      });
      setEabHmac("");
      setDnsCreds({});
      await qc.invalidateQueries({ queryKey: ["system-acme"] });
      pushToast("ACME settings saved", "success");
      return true;
    } catch (e) {
      pushToast("Failed to save ACME settings", "error", e instanceof Error ? e.message : String(e));
      return false;
    } finally {
      setBusy(null);
    }
  }

  async function handleIssue() {
    const ok = await saveConfig();
    if (!ok) return;
    setBusy("issue");
    try {
      await apiFetch("/api/v1/system/acme/issue", { method: "POST", body: "{}" });
      pushToast(
        "ACME certificate issuance started",
        "success",
        "Watch progress below; TLS reloads automatically on completion."
      );
      await qc.invalidateQueries({ queryKey: ["system-acme"] });
    } catch (e) {
      pushToast("Could not start ACME issuance", "error", e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  const cert = data?.cert;
  const runState = data?.runState;
  const days = cert?.daysRemaining ?? null;
  const certVariant =
    cert?.source === "acme"
      ? days != null && days <= 14
        ? "danger"
        : days != null && days <= 30
          ? "warning"
          : "success"
      : "info";

  return (
    <Card>
      <CardHeader
        title="TLS & ACME Certificates"
        subtitle="Automated HTTPS certificates via Let's Encrypt, ZeroSSL, Google Public CA, or custom ACME (HTTP-01 & DNS-01)"
        icon={<Award className="h-4 w-4" />}
        action={
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="secondary" size="sm" onClick={saveConfig} disabled={busy != null}>
              {busy === "save" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}
              Save
            </Button>
            <Button variant="primary" size="sm" onClick={handleIssue} disabled={busy != null || Boolean(runState?.running)}>
              {busy === "issue" || runState?.running ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <RefreshCw className="h-3.5 w-3.5" />
              )}
              {runState?.running ? "Issuing…" : "Issue / Renew Now"}
            </Button>
          </div>
        }
      />

      {/* Active certificate banner */}
      {cert && (
        <div className="mb-5 rounded-2xl border border-line bg-sunk/60 p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant={certVariant} dot>
                {cert.source === "acme" ? "Trusted ACME" : cert.source === "self-signed" ? "CellCore Self-Signed" : cert.source}
              </Badge>
              {days != null && (
                <span className="text-[12px] font-semibold text-ink qm-tabular">
                  {days >= 0 ? `${days} days remaining` : `Expired ${Math.abs(days)}d ago`}
                </span>
              )}
            </div>
            {cert.notAfter && <span className="text-[11.5px] text-muted font-mono">Expires {cert.notAfter}</span>}
          </div>
          <div className="mt-2 grid gap-1 text-[12px] text-ink-2 sm:grid-cols-2">
            <div className="truncate">
              <span className="text-muted">Subject: </span>
              <span className="font-mono">{cert.subject || "—"}</span>
            </div>
            <div className="truncate">
              <span className="text-muted">Issuer: </span>
              <span className="font-mono">{cert.issuer || "—"}</span>
            </div>
          </div>
          {cert.sans.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {cert.sans.slice(0, 8).map((san) => (
                <span key={san} className="rounded-md border border-line bg-surface px-2 py-0.5 text-[11px] font-mono text-ink-2">
                  {san}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Configuration form */}
      <div className="grid gap-4 lg:grid-cols-12">
        <div className="lg:col-span-6 space-y-4">
          <Switch
            label="Automatic ACME renewal"
            description="Checks every 6 hours and renews automatically before expiry with zero-downtime TLS reload"
            checked={enabled}
            onChange={setEnabled}
          />

          <Field label="ACME Certificate Authority (Issuer)" htmlFor="cc-acme-issuer" hint={issuerMeta.hint}>
            <Select id="cc-acme-issuer" value={issuer} onChange={(e) => setIssuer(e.target.value as AcmeIssuer)}>
              {ISSUER_OPTIONS.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.label}
                </option>
              ))}
            </Select>
          </Field>

          {issuer === "custom" && (
            <Field label="Custom ACME Directory URL" htmlFor="cc-acme-custom-url">
              <Input
                id="cc-acme-custom-url"
                value={customUrl}
                onChange={(e) => setCustomUrl(e.target.value)}
                placeholder="https://ca.internal/acme/acme/directory"
              />
            </Field>
          )}

          <Field
            label="Domains (comma-separated)"
            htmlFor="cc-acme-domains"
            hint="Wildcard domains (*.example.com) require DNS-01 validation"
          >
            <Input
              id="cc-acme-domains"
              value={domainsText}
              onChange={(e) => setDomainsText(e.target.value)}
              placeholder="mgateway1.example.com"
            />
          </Field>

          <Field label="Account Email (expiry notices)" htmlFor="cc-acme-email">
            <Input
              id="cc-acme-email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="admin@example.com"
            />
          </Field>

          {issuerMeta.eab && (
            <div className="rounded-2xl border border-line bg-sunk/40 p-3.5 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1.5 text-[12.5px] font-semibold text-ink">
                  <KeyRound className="h-3.5 w-3.5 text-ember-ink" />
                  External Account Binding (EAB)
                </div>
                {data?.config.hasEabHmacKey && <Badge variant="success">HMAC Saved</Badge>}
              </div>
              <Field label="EAB Key ID (KID)" htmlFor="cc-acme-eab-kid">
                <Input
                  id="cc-acme-eab-kid"
                  value={eabKid}
                  onChange={(e) => setEabKid(e.target.value)}
                  placeholder="EAB Key Identifier"
                />
              </Field>
              <Field label="EAB HMAC Key (Base64URL)" htmlFor="cc-acme-eab-hmac">
                <Input
                  id="cc-acme-eab-hmac"
                  type="password"
                  value={eabHmac}
                  onChange={(e) => setEabHmac(e.target.value)}
                  placeholder={data?.config.hasEabHmacKey ? "•••••••• (saved — leave blank to keep)" : "Paste EAB HMAC key"}
                />
              </Field>
            </div>
          )}
        </div>

        <div className="lg:col-span-6 space-y-4">
          <div>
            <div className="qm-eyebrow mb-2">Challenge Validation Method</div>
            <SegmentedTabs
              value={validation}
              onChange={(v) => setValidation(v as ValidationMethod)}
              options={[
                { id: "dns-01", label: "DNS-01 (Private LAN / Wildcards)" },
                { id: "http-01", label: "HTTP-01 (Port 80)" },
              ]}
            />
          </div>

          {validation === "http-01" ? (
            <div className="rounded-2xl border border-line bg-sunk/50 p-4 text-[12.5px] text-ink-2 space-y-1.5">
              <div className="flex items-center gap-2 font-semibold text-ink">
                <Globe className="h-4 w-4 text-ember-ink" />
                Built-in HTTP-01 Responder on Port 80
              </div>
              <p>
                CellCore serves <code className="font-mono text-[11.5px]">/.well-known/acme-challenge/&lt;token&gt;</code>{" "}
                directly on port 80 — even when <strong>Redirect HTTP to HTTPS</strong> is enabled. Your domain&apos;s DNS A/AAAA
                record must reach this modem on TCP port 80 during validation.
              </p>
            </div>
          ) : (
            <div className="space-y-3 rounded-2xl border border-line bg-sunk/40 p-4">
              <Field label="DNS Provider" htmlFor="cc-acme-dns-provider">
                <Select
                  id="cc-acme-dns-provider"
                  value={dnsProvider}
                  onChange={(e) => {
                    setDnsProvider(e.target.value as DnsProvider);
                    setDnsCreds({});
                  }}
                >
                  {DNS_PROVIDERS.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.label}
                    </option>
                  ))}
                </Select>
              </Field>

              {providerMeta.fields.map((f) => {
                const isSaved = data?.config.dnsProvider === dnsProvider && savedKeys.has(f.key);
                return (
                  <Field
                    key={`${dnsProvider}-${f.key}`}
                    label={f.label}
                    aside={isSaved ? <Badge variant="success">Saved</Badge> : undefined}
                    htmlFor={`cc-dns-${f.key}`}
                  >
                    <Input
                      id={`cc-dns-${f.key}`}
                      type={f.secret ? "password" : "text"}
                      value={dnsCreds[f.key] ?? ""}
                      onChange={(e) => setDnsCreds((prev) => ({ ...prev, [f.key]: e.target.value }))}
                      placeholder={isSaved ? "•••••••• (saved — leave blank to keep)" : f.placeholder}
                    />
                  </Field>
                );
              })}

              <div className="grid grid-cols-2 gap-3 pt-1">
                <Field label="DNS Propagation Wait (s)" htmlFor="cc-acme-prop">
                  <Input
                    id="cc-acme-prop"
                    type="number"
                    min={5}
                    max={300}
                    value={propagationSecs}
                    onChange={(e) => setPropagationSecs(e.target.value)}
                  />
                </Field>
                <Field label="Renew Before Expiry (days)" htmlFor="cc-acme-renew">
                  <Input
                    id="cc-acme-renew"
                    type="number"
                    min={7}
                    max={60}
                    value={renewDays}
                    onChange={(e) => setRenewDays(e.target.value)}
                  />
                </Field>
              </div>
            </div>
          )}

          {/* Live issuance status / log */}
          {runState && (runState.running || runState.lastError || runState.lastMessage || runState.log.length > 0) && (
            <div className="rounded-2xl border border-line bg-surface p-3.5 space-y-2">
              <div className="flex items-center gap-2 text-[12.5px] font-semibold">
                {runState.running ? (
                  <>
                    <Loader2 className="h-3.5 w-3.5 animate-spin text-ember-ink" />
                    <span className="text-ink">Issuance in progress…</span>
                  </>
                ) : runState.lastError ? (
                  <>
                    <TriangleAlert className="h-3.5 w-3.5 text-crimson-ink" />
                    <span className="text-crimson-ink">{runState.lastError}</span>
                  </>
                ) : (
                  <>
                    <CheckCircle2 className="h-3.5 w-3.5 text-jade-ink" />
                    <span className="text-jade-ink">{runState.lastMessage}</span>
                  </>
                )}
              </div>
              {runState.log.length > 0 && (
                <pre className="max-h-36 overflow-y-auto rounded-xl bg-sunk p-2.5 text-[11px] font-mono text-ink-2 whitespace-pre-wrap">
                  {runState.log.join("\n")}
                </pre>
              )}
            </div>
          )}
        </div>
      </div>
    </Card>
  );
}
