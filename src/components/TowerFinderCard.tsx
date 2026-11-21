import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import {
  CheckCircle2,
  Compass,
  Copy,
  ExternalLink,
  KeyRound,
  LocateFixed,
  MapPin,
  Navigation,
  Radio,
  Search,
  Trash2,
} from "lucide-react";
import { Badge, Button, Card, Input } from "./ui";
import { apiFetch } from "@/lib/api";
import { angularDiffDeg, cardinalFromDeg, parseLatLonInput } from "@/lib/rf";
import { cn } from "@/lib/utils";
import { TONE_TEXT, rsrpPct, rsrpTone } from "@/pages/cellular/shared";

interface HomeLocation {
  lat: number;
  lon: number;
  label: string;
}

interface PinnedTower {
  id: string;
  label: string;
  mcc: string;
  mnc: string;
  rat: string;
  pci: number | null;
  gnbId: number | null;
  cellId: string;
  band: string;
  arfcn: number | null;
  lat: number;
  lon: number;
  source: string;
  savedAt: number;
}

interface DecodedServingCell {
  rat: string;
  mcc: string;
  mnc: string;
  band: string;
  pci: number | null;
  arfcn: number | null;
  tacHex: string;
  tacDec: number | null;
  cellIdHex: string;
  nciDec: number | null;
  gnbId: number | null;
  gnbId22: number | null;
  sectorId: number | null;
  enbId: number | null;
  taMeters: number | null;
  cellmapperUrl: string;
}

interface ActiveTowerTarget {
  tower: PinnedTower;
  bearingDeg: number;
  cardinal: string;
  distanceMeters: number;
  taMeters: number | null;
  taDeltaMeters: number | null;
}

interface TowerFinderResponse {
  status: string;
  home: HomeLocation | null;
  hasOpencellidKey: boolean;
  pinnedTowers: PinnedTower[];
  serving: DecodedServingCell | null;
  activeTarget: ActiveTowerTarget | null;
}

interface SweepBin {
  bestRsrp: number;
  bestSinr: number | null;
  count: number;
}

const SWEEP_BINS = 36; // 10-degree sectors around 360°

function latLonToTileFloat(lat: number, lon: number, zoom: number): { x: number; y: number } {
  const n = 2 ** zoom;
  const latRad = (lat * Math.PI) / 180;
  const x = ((lon + 180) / 360) * n;
  const y = ((1 - Math.log(Math.tan(latRad) + 1 / Math.cos(latRad)) / Math.PI) / 2) * n;
  return { x, y };
}

function chooseZoom(radiusMeters: number, lat: number, fitRadiusPx: number): number {
  const cosLat = Math.max(0.2, Math.cos((lat * Math.PI) / 180));
  const targetMpp = Math.max(1.5, radiusMeters / Math.max(40, fitRadiusPx));
  const z = Math.floor(Math.log2((156543.03392 * cosLat) / targetMpp));
  return Math.max(9, Math.min(16, z));
}

function binColor(rsrp: number): string {
  if (rsrp >= -85) return "var(--qm-jade)";
  if (rsrp >= -95) return "var(--qm-saffron)";
  if (rsrp >= -105) return "var(--qm-ember)";
  return "var(--qm-crimson)";
}

function fmtDist(meters: number): string {
  if (meters >= 1000) return `${(meters / 1000).toFixed(2)} km (${(meters / 1609.34).toFixed(2)} mi)`;
  return `${Math.round(meters)} m`;
}

/** Pure-SVG 360° Polar Compass + Signal Sweep Heatmap + Target Bearing Ray. */
function PolarCompassSvg({
  heading,
  targetBearing,
  targetLabel,
  sweep,
  liveRsrp,
}: {
  heading: number | null;
  targetBearing: number | null;
  targetLabel: string | null;
  sweep: Record<number, SweepBin>;
  liveRsrp: number | null;
}) {
  const gid = useId().replace(/:/g, "");
  const cx = 140;
  const cy = 140;
  const maxR = 104;

  const toXY = (deg: number, r: number) => {
    const rad = ((deg - 90) * Math.PI) / 180;
    return [cx + r * Math.cos(rad), cy + r * Math.sin(rad)] as const;
  };

  const wedgePath = (degStart: number, degEnd: number, r: number) => {
    const [x1, y1] = toXY(degStart, r);
    const [x2, y2] = toXY(degEnd, r);
    return `M ${cx} ${cy} L ${x1.toFixed(1)} ${y1.toFixed(1)} A ${r.toFixed(1)} ${r.toFixed(1)} 0 0 1 ${x2.toFixed(1)} ${y2.toFixed(1)} Z`;
  };

  const bestBin = useMemo(() => {
    let best: { idx: number; rsrp: number } | null = null;
    for (const [k, b] of Object.entries(sweep)) {
      const idx = Number(k);
      if (!best || b.bestRsrp > best.rsrp) best = { idx, rsrp: b.bestRsrp };
    }
    return best;
  }, [sweep]);

  const aligned =
    heading != null && targetBearing != null && Math.abs(angularDiffDeg(heading, targetBearing)) <= 10;

  return (
    <svg viewBox="0 0 280 280" className="w-full max-w-[270px] mx-auto select-none">
      <defs>
        <radialGradient id={`rad-${gid}`} cx="50%" cy="50%" r="50%">
          <stop offset="0%" style={{ stopColor: "var(--qm-ember)", stopOpacity: 0.08 }} />
          <stop offset="100%" style={{ stopColor: "var(--qm-ember)", stopOpacity: 0 }} />
        </radialGradient>
      </defs>

      {/* Radar base rings */}
      <circle cx={cx} cy={cy} r={maxR} fill={`url(#rad-${gid})`} className="stroke-line-strong" strokeWidth="1.5" />
      {[0.75, 0.5, 0.25].map((f) => (
        <circle
          key={f}
          cx={cx}
          cy={cy}
          r={maxR * f}
          fill="none"
          className="stroke-line"
          strokeWidth="1"
          strokeDasharray="3 4"
        />
      ))}

      {/* Degree ticks */}
      {Array.from({ length: 36 }, (_, i) => {
        const deg = i * 10;
        const major = deg % 90 === 0;
        const med = deg % 30 === 0;
        const [x1, y1] = toXY(deg, maxR);
        const [x2, y2] = toXY(deg, maxR - (major ? 10 : med ? 6 : 3));
        return (
          <line
            key={deg}
            x1={x1}
            y1={y1}
            x2={x2}
            y2={y2}
            className={major ? "stroke-ink" : "stroke-line-strong"}
            strokeWidth={major ? 1.8 : 1}
          />
        );
      })}

      {/* 360° Polar Signal Sweep Petals */}
      {Object.entries(sweep).map(([k, bin]) => {
        const idx = Number(k);
        const start = idx * 10 - 5;
        const end = idx * 10 + 5;
        const pct = Math.max(0.18, rsrpPct(bin.bestRsrp) / 100);
        const r = maxR * pct;
        const isBest = bestBin?.idx === idx;
        return (
          <path
            key={idx}
            d={wedgePath(start, end, r)}
            style={{ fill: binColor(bin.bestRsrp), stroke: isBest ? "var(--qm-ink)" : "none" }}
            fillOpacity={isBest ? 0.65 : 0.38}
            strokeWidth={isBest ? 1.5 : 0}
          >
            <title>
              {idx * 10}° ({cardinalFromDeg(idx * 10)}): {bin.bestRsrp} dBm
              {bin.bestSinr != null ? ` · SINR ${bin.bestSinr} dB` : ""} ({bin.count} samples)
            </title>
          </path>
        );
      })}

      {/* Target Tower ±10° Cone + Bearing Arrow */}
      {targetBearing != null && (
        <g>
          <path
            d={wedgePath(targetBearing - 10, targetBearing + 10, maxR)}
            style={{ fill: aligned ? "var(--qm-jade)" : "var(--qm-ember)" }}
            fillOpacity={aligned ? 0.28 : 0.16}
          />
          {(() => {
            const [tx, ty] = toXY(targetBearing, maxR);
            return (
              <>
                <line
                  x1={cx}
                  y1={cy}
                  x2={tx}
                  y2={ty}
                  style={{ stroke: aligned ? "var(--qm-jade)" : "var(--qm-ember)" }}
                  strokeWidth="2.5"
                  strokeDasharray="5 3"
                />
                <circle
                  cx={tx}
                  cy={ty}
                  r="6"
                  style={{ fill: aligned ? "var(--qm-jade)" : "var(--qm-ember)", stroke: "var(--qm-raised)" }}
                  strokeWidth="2"
                >
                  <title>{targetLabel ?? `Target ${targetBearing}°`}</title>
                </circle>
              </>
            );
          })()}
        </g>
      )}

      {/* Live Heading Needle */}
      {heading != null && (
        <g>
          {(() => {
            const [hx, hy] = toXY(heading, maxR - 6);
            const [bx, by] = toXY(heading + 180, 18);
            return (
              <>
                <line
                  x1={bx}
                  y1={by}
                  x2={hx}
                  y2={hy}
                  style={{ stroke: aligned ? "var(--qm-jade)" : "var(--qm-ink)" }}
                  strokeWidth="3"
                  strokeLinecap="round"
                />
                <circle
                  cx={hx}
                  cy={hy}
                  r="4.5"
                  style={{ fill: aligned ? "var(--qm-jade)" : "var(--qm-ink)" }}
                />
              </>
            );
          })()}
        </g>
      )}

      {/* Cardinal labels */}
      {[
        ["N", 0],
        ["E", 90],
        ["S", 180],
        ["W", 270],
      ].map(([lbl, deg]) => {
        const [lx, ly] = toXY(deg as number, maxR + 18);
        return (
          <text
            key={lbl as string}
            x={lx}
            y={ly + 4}
            textAnchor="middle"
            className={cn("text-[12px] font-bold", lbl === "N" ? "fill-ember-ink" : "fill-muted")}
          >
            {lbl}
          </text>
        );
      })}
      {[
        ["NE", 45],
        ["SE", 135],
        ["SW", 225],
        ["NW", 315],
      ].map(([lbl, deg]) => {
        const [lx, ly] = toXY(deg as number, maxR + 16);
        return (
          <text key={lbl as string} x={lx} y={ly + 3.5} textAnchor="middle" className="text-[9.5px] font-semibold fill-muted">
            {lbl}
          </text>
        );
      })}

      {/* Center hub */}
      <circle cx={cx} cy={cy} r="18" className="fill-raised stroke-line-strong" strokeWidth="1.5" />
      <text x={cx} y={cy + 4} textAnchor="middle" className="text-[11px] font-bold fill-ink font-mono">
        {liveRsrp != null ? `${Math.round(liveRsrp)}` : "—"}
      </text>
    </svg>
  );
}

/** Interactive Sightline Map using keyless Esri Street / Satellite tiles + 1:1 pixel SVG overlay. */
function SightlineMap({
  home,
  target,
  taMeters,
}: {
  home: HomeLocation | null;
  target: ActiveTowerTarget | null;
  taMeters: number | null;
}) {
  const [tilesFailed, setTilesFailed] = useState(false);
  const [mapStyle, setMapStyle] = useState<"street" | "satellite">("street");
  const boxRef = useRef<HTMLDivElement | null>(null);
  const [boxSize, setBoxSize] = useState<{ w: number; h: number }>({ w: 520, h: 240 });

  useEffect(() => {
    setTilesFailed(false);
  }, [mapStyle]);

  useEffect(() => {
    const el = boxRef.current;
    if (!el) return;
    const measure = () => {
      const r = el.getBoundingClientRect();
      if (r.width > 40 && r.height > 40) {
        setBoxSize({ w: Math.round(r.width), h: Math.round(r.height) });
      }
    };
    measure();
    const ro = typeof ResizeObserver !== "undefined" ? new ResizeObserver(measure) : null;
    ro?.observe(el);
    return () => ro?.disconnect();
  }, []);

  const geom = useMemo(() => {
    if (!home) return null;
    const W = boxSize.w;
    const H = boxSize.h;
    const centerLat = target ? (home.lat + target.tower.lat) / 2 : home.lat;
    const centerLon = target ? (home.lon + target.tower.lon) / 2 : home.lon;
    const fitRadiusPx = Math.min(W, H) * 0.42;
    const reqRadiusMeters = Math.max(
      target ? target.distanceMeters * 0.72 : 0,
      taMeters && taMeters > 0 ? taMeters : 0,
      1500
    );
    const zoom = chooseZoom(reqRadiusMeters, centerLat, fitRadiusPx);
    const c = latLonToTileFloat(centerLat, centerLon, zoom);
    const baseTx = Math.floor(c.x);
    const baseTy = Math.floor(c.y);
    const tileSize = 256;
    const toPx = (lat: number, lon: number) => {
      const f = latLonToTileFloat(lat, lon, zoom);
      return {
        x: W / 2 + (f.x - c.x) * tileSize,
        y: H / 2 + (f.y - c.y) * tileSize,
      };
    };
    const mpp = (156543.03392 * Math.cos((centerLat * Math.PI) / 180)) / 2 ** zoom;
    const halfCols = Math.ceil(W / 2 / tileSize) + 1;
    const halfRows = Math.ceil(H / 2 / tileSize) + 1;
    const service = mapStyle === "satellite" ? "World_Imagery" : "World_Street_Map";
    const tiles: { x: number; y: number; left: number; top: number; url: string }[] = [];
    for (let dx = -halfCols; dx <= halfCols; dx++) {
      for (let dy = -halfRows; dy <= halfRows; dy++) {
        const tx = baseTx + dx;
        const ty = baseTy + dy;
        tiles.push({
          x: tx,
          y: ty,
          left: W / 2 + (tx - c.x) * tileSize,
          top: H / 2 + (ty - c.y) * tileSize,
          url: `https://server.arcgisonline.com/ArcGIS/rest/services/${service}/MapServer/tile/${zoom}/${ty}/${tx}`,
        });
      }
    }
    const homePx = toPx(home.lat, home.lon);
    const towerPx = target ? toPx(target.tower.lat, target.tower.lon) : null;
    const taRadiusPx = taMeters && taMeters > 0 ? Math.min(Math.max(W, H), taMeters / mpp) : null;
    return { W, H, zoom, tiles, homePx, towerPx, taRadiusPx };
  }, [home, target, taMeters, boxSize, mapStyle]);

  if (!geom || !home) {
    return (
      <div className="flex h-[220px] flex-col items-center justify-center gap-2 rounded-2xl border border-dashed border-line-strong bg-sunk/50 px-4 text-center">
        <MapPin className="h-6 w-6 text-muted" />
        <div className="text-[12.5px] font-semibold text-ink">Set your Home location to unlock the sightline map</div>
        <div className="text-[11.5px] text-muted">
          Tap <strong>Use Phone GPS</strong> or paste coordinates below to see the Timing Advance ring &amp; tower bearing.
        </div>
      </div>
    );
  }

  const isSat = mapStyle === "satellite";
  const labelFill = isSat ? "#ffffff" : "#0f172a";
  const labelStroke = isSat ? "#0f172a" : "#ffffff";

  return (
    <div ref={boxRef} className="relative h-[240px] w-full overflow-hidden rounded-2xl border border-line bg-[#0f172a]">
      {!tilesFailed && (
        <div className="pointer-events-none absolute inset-0">
          {geom.tiles.map((t) => (
            <img
              key={`${mapStyle}-${geom.zoom}-${t.x}-${t.y}`}
              src={t.url}
              alt=""
              width={256}
              height={256}
              onError={() => setTilesFailed(true)}
              style={{
                position: "absolute",
                left: `${t.left}px`,
                top: `${t.top}px`,
                width: "256px",
                height: "256px",
                maxWidth: "none",
              }}
            />
          ))}
        </div>
      )}
      <svg
        viewBox={`0 0 ${geom.W} ${geom.H}`}
        width={geom.W}
        height={geom.H}
        className="relative z-[1] h-full w-full"
      >
        {/* Subtle scrim for crisp overlay legibility */}
        <rect x="0" y="0" width={geom.W} height={geom.H} fill="#0b1220" fillOpacity={tilesFailed ? 0.95 : isSat ? 0.22 : 0.08} />

        {/* Timing Advance distance ring around Home */}
        {geom.taRadiusPx != null && (
          <circle
            cx={geom.homePx.x}
            cy={geom.homePx.y}
            r={geom.taRadiusPx}
            fill={isSat ? "rgba(251,191,36,0.12)" : "rgba(245,158,11,0.09)"}
            stroke={isSat ? "#fbbf24" : "#d97706"}
            strokeWidth="2.2"
            strokeDasharray="6 4"
          />
        )}

        {/* Sightline vector Home -> Tower */}
        {geom.towerPx && (
          <>
            <line
              x1={geom.homePx.x}
              y1={geom.homePx.y}
              x2={geom.towerPx.x}
              y2={geom.towerPx.y}
              stroke={isSat ? "#34d399" : "#059669"}
              strokeWidth="3"
              strokeDasharray="7 4"
            />
            <circle cx={geom.towerPx.x} cy={geom.towerPx.y} r="11" fill="rgba(239,68,68,0.28)" />
            <circle cx={geom.towerPx.x} cy={geom.towerPx.y} r="5.5" fill="#dc2626" stroke="#ffffff" strokeWidth="2" />
            <text
              x={geom.towerPx.x + 10}
              y={geom.towerPx.y + 4}
              fill={labelFill}
              stroke={labelStroke}
              strokeWidth="3"
              paintOrder="stroke"
              fontSize="11.5"
              fontWeight="700"
            >
              {target?.tower.label}
            </text>
          </>
        )}

        {/* Home pin */}
        <circle cx={geom.homePx.x} cy={geom.homePx.y} r="10" fill="rgba(16,185,129,0.28)" />
        <circle cx={geom.homePx.x} cy={geom.homePx.y} r="5.5" fill="#059669" stroke="#ffffff" strokeWidth="2" />
        <text
          x={geom.homePx.x + 9}
          y={geom.homePx.y - 7}
          fill={labelFill}
          stroke={labelStroke}
          strokeWidth="3"
          paintOrder="stroke"
          fontSize="11"
          fontWeight="700"
        >
          {home.label || "Home"}
        </text>
      </svg>

      {/* Corner overlay badges */}
      <div className="pointer-events-none absolute top-2 left-2 z-[2] flex flex-wrap gap-1.5">
        {target && (
          <span className="rounded-full bg-black/75 px-2.5 py-0.5 text-[11px] font-bold text-emerald-300 backdrop-blur qm-tabular">
            {target.bearingDeg}° {target.cardinal} · {fmtDist(target.distanceMeters)}
          </span>
        )}
        {taMeters != null && taMeters > 0 && (
          <span className="rounded-full bg-black/75 px-2.5 py-0.5 text-[10.5px] font-semibold text-amber-300 backdrop-blur qm-tabular">
            TA ring ~{(taMeters / 1000).toFixed(2)} km
          </span>
        )}
      </div>

      {/* Street / Satellite toggle */}
      <div className="absolute top-2 right-2 z-[2] inline-flex overflow-hidden rounded-full bg-black/70 p-0.5 text-[10px] font-semibold backdrop-blur">
        <button
          type="button"
          onClick={() => setMapStyle("street")}
          className={cn(
            "rounded-full px-2 py-0.5 transition",
            !isSat ? "bg-white text-slate-900" : "text-white/80 hover:text-white"
          )}
        >
          Street
        </button>
        <button
          type="button"
          onClick={() => setMapStyle("satellite")}
          className={cn(
            "rounded-full px-2 py-0.5 transition",
            isSat ? "bg-white text-slate-900" : "text-white/80 hover:text-white"
          )}
        >
          Satellite
        </button>
      </div>

      {!tilesFailed && (
        <span className="pointer-events-none absolute bottom-1 right-2 z-[2] rounded bg-black/60 px-1.5 py-0.5 text-[9px] text-white/85">
          © Esri
        </span>
      )}
    </div>
  );
}

export function TowerFinderCard({
  meanRsrp,
  meanSinr,
  haptics,
}: {
  meanRsrp: number | null;
  meanSinr: number | null;
  haptics: boolean;
}) {
  const [data, setData] = useState<TowerFinderResponse | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ tone: "ok" | "warn" | "err"; text: string } | null>(null);

  // Inputs
  const [homeInput, setHomeInput] = useState("");
  const [towerInput, setTowerInput] = useState("");
  const [towerLabel, setTowerLabel] = useState("");
  const [showApiKey, setShowApiKey] = useState(false);
  const [apiKeyInput, setApiKeyInput] = useState("");
  const [copiedGnb, setCopiedGnb] = useState(false);

  // Compass & 360° Polar Sweep
  const [compassActive, setCompassActive] = useState(false);
  const [heading, setHeading] = useState<number | null>(null);
  const [manualHeading, setManualHeading] = useState<number>(0);
  const [sweep, setSweep] = useState<Record<number, SweepBin>>({});
  const lastLockBuzzRef = useRef<number>(0);

  const load = useCallback(async () => {
    try {
      const res = await apiFetch<TowerFinderResponse>("/api/v1/cellular/tower-finder");
      setData(res);
      if (res.home) {
        setHomeInput(`${res.home.lat.toFixed(5)}, ${res.home.lon.toFixed(5)}`);
      }
    } catch {
      // ignore initial load error
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // Phone Magnetometer listener (iOS webkitCompassHeading + Android alpha)
  useEffect(() => {
    if (!compassActive) return;
    const onOrient = (ev: DeviceOrientationEvent) => {
      const iosHeading = (ev as DeviceOrientationEvent & { webkitCompassHeading?: number }).webkitCompassHeading;
      let deg: number | null = null;
      if (typeof iosHeading === "number" && Number.isFinite(iosHeading)) {
        deg = iosHeading;
      } else if (typeof ev.alpha === "number" && Number.isFinite(ev.alpha)) {
        deg = (360 - ev.alpha) % 360;
      }
      if (deg != null) {
        const rounded = Math.round(((deg % 360) + 360) % 360);
        setHeading(rounded);
      }
    };
    window.addEventListener("deviceorientationabsolute", onOrient as EventListener, true);
    window.addEventListener("deviceorientation", onOrient as EventListener, true);
    return () => {
      window.removeEventListener("deviceorientationabsolute", onOrient as EventListener, true);
      window.removeEventListener("deviceorientation", onOrient as EventListener, true);
    };
  }, [compassActive]);

  const activeHeading = compassActive ? heading : manualHeading;
  const targetBearing = data?.activeTarget?.bearingDeg ?? null;

  // Record 360° sweep petal automatically while compass is active
  useEffect(() => {
    if (!compassActive || heading == null || meanRsrp == null) return;
    const binIdx = Math.round(heading / 10) % SWEEP_BINS;
    setSweep((prev) => {
      const cur = prev[binIdx];
      const nextRsrp = cur ? Math.max(cur.bestRsrp, meanRsrp) : meanRsrp;
      const nextSinr =
        meanSinr == null ? (cur?.bestSinr ?? null) : cur?.bestSinr != null ? Math.max(cur.bestSinr, meanSinr) : meanSinr;
      return {
        ...prev,
        [binIdx]: { bestRsrp: nextRsrp, bestSinr: nextSinr, count: (cur?.count ?? 0) + 1 },
      };
    });
  }, [compassActive, heading, meanRsrp, meanSinr]);

  // Subtle haptic tick when live compass locks onto target bearing (±10°)
  useEffect(() => {
    if (!compassActive || !haptics || heading == null || targetBearing == null) return;
    if (Math.abs(angularDiffDeg(heading, targetBearing)) <= 10) {
      const now = Date.now();
      if (now - lastLockBuzzRef.current > 3500) {
        lastLockBuzzRef.current = now;
        try {
          navigator.vibrate?.(30);
        } catch {
          // ignore
        }
      }
    }
  }, [compassActive, haptics, heading, targetBearing]);

  const toggleCompass = async () => {
    if (compassActive) {
      setCompassActive(false);
      return;
    }
    try {
      const DOE = DeviceOrientationEvent as unknown as { requestPermission?: () => Promise<string> };
      if (typeof DOE?.requestPermission === "function") {
        const perm = await DOE.requestPermission();
        if (perm !== "granted") {
          setMsg({ tone: "warn", text: "Compass permission denied — use the manual bearing slider instead." });
          return;
        }
      }
      setCompassActive(true);
      setMsg({ tone: "ok", text: "Live phone compass active — rotate slowly to paint the 360° signal heatmap." });
    } catch {
      setCompassActive(true);
    }
  };

  const logManualSweep = () => {
    if (meanRsrp == null) return;
    const binIdx = Math.round(manualHeading / 10) % SWEEP_BINS;
    setSweep((prev) => {
      const cur = prev[binIdx];
      return {
        ...prev,
        [binIdx]: {
          bestRsrp: cur ? Math.max(cur.bestRsrp, meanRsrp) : meanRsrp,
          bestSinr: meanSinr ?? cur?.bestSinr ?? null,
          count: (cur?.count ?? 0) + 1,
        },
      };
    });
  };

  const usePhoneGps = () => {
    if (!navigator.geolocation) {
      setMsg({ tone: "err", text: "Browser Geolocation API is unavailable. Paste Home lat, lon manually." });
      return;
    }
    setBusy("gps");
    navigator.geolocation.getCurrentPosition(
      async (pos) => {
        try {
          const res = await apiFetch<TowerFinderResponse>("/api/v1/cellular/tower-finder", {
            method: "PUT",
            body: JSON.stringify({
              home: { lat: pos.coords.latitude, lon: pos.coords.longitude, label: "Home" },
            }),
          });
          setData(res);
          setHomeInput(`${pos.coords.latitude.toFixed(5)}, ${pos.coords.longitude.toFixed(5)}`);
          setMsg({ tone: "ok", text: "Home location saved from GPS." });
        } catch (e) {
          setMsg({ tone: "err", text: e instanceof Error ? e.message : "Failed to save GPS location" });
        } finally {
          setBusy(null);
        }
      },
      (err) => {
        setBusy(null);
        setMsg({ tone: "warn", text: `GPS error (${err.message}). Paste "lat, lon" directly instead.` });
      },
      { enableHighAccuracy: true, timeout: 10000 }
    );
  };

  const saveHomeManual = async () => {
    const parsed = parseLatLonInput(homeInput);
    if (!parsed) {
      setMsg({ tone: "warn", text: 'Enter Home as "lat, lon" or paste a Google Maps / CellMapper URL.' });
      return;
    }
    setBusy("home");
    try {
      const res = await apiFetch<TowerFinderResponse>("/api/v1/cellular/tower-finder", {
        method: "PUT",
        body: JSON.stringify({ home: { lat: parsed.lat, lon: parsed.lon, label: "Home" } }),
      });
      setData(res);
      setMsg({ tone: "ok", text: "Home coordinates saved." });
    } catch (e) {
      setMsg({ tone: "err", text: e instanceof Error ? e.message : "Failed to save Home" });
    } finally {
      setBusy(null);
    }
  };

  const pinTowerManual = async () => {
    const parsed = parseLatLonInput(towerInput);
    if (!parsed) {
      setMsg({ tone: "warn", text: 'Paste Tower "lat, lon" or a CellMapper / Google Maps URL.' });
      return;
    }
    setBusy("tower");
    try {
      const s = data?.serving;
      const res = await apiFetch<TowerFinderResponse>("/api/v1/cellular/tower-finder", {
        method: "PUT",
        body: JSON.stringify({
          upsertTower: {
            id: s?.gnbId ? `gnb-${s.gnbId}` : s?.pci != null ? `pci-${s.pci}` : "",
            label: towerLabel.trim() || (s ? `${s.band || s.rat} PCI ${s.pci ?? "?"}` : "Target Tower"),
            mcc: s?.mcc ?? "",
            mnc: s?.mnc ?? "",
            rat: s?.rat ?? "",
            pci: s?.pci ?? null,
            gnbId: s?.gnbId ?? null,
            cellId: s?.cellIdHex ?? "",
            band: s?.band ?? "",
            arfcn: s?.arfcn ?? null,
            lat: parsed.lat,
            lon: parsed.lon,
            source: "manual",
            savedAt: 0,
          },
        }),
      });
      setData(res);
      setTowerInput("");
      setTowerLabel("");
      setMsg({ tone: "ok", text: "Tower pinned — bearing & sightline updated!" });
    } catch (e) {
      setMsg({ tone: "err", text: e instanceof Error ? e.message : "Failed to pin tower" });
    } finally {
      setBusy(null);
    }
  };

  const runAutoLookup = async () => {
    setBusy("lookup");
    setMsg(null);
    try {
      const res = await apiFetch<{
        found: boolean;
        lat?: number;
        lon?: number;
        accuracyMeters?: number;
        source?: string;
        message?: string;
      }>("/api/v1/cellular/tower-finder/lookup", { method: "POST", body: JSON.stringify({}) });
      if (res.found && res.lat != null && res.lon != null) {
        const s = data?.serving;
        const saved = await apiFetch<TowerFinderResponse>("/api/v1/cellular/tower-finder", {
          method: "PUT",
          body: JSON.stringify({
            upsertTower: {
              id: s?.gnbId ? `gnb-${s.gnbId}` : s?.pci != null ? `pci-${s.pci}` : "",
              label: s ? `${s.band || s.rat} PCI ${s.pci ?? "?"}` : "Tower",
              mcc: s?.mcc ?? "",
              mnc: s?.mnc ?? "",
              rat: s?.rat ?? "",
              pci: s?.pci ?? null,
              gnbId: s?.gnbId ?? null,
              cellId: s?.cellIdHex ?? "",
              band: s?.band ?? "",
              arfcn: s?.arfcn ?? null,
              lat: res.lat,
              lon: res.lon,
              source: res.source ?? "lookup",
              savedAt: 0,
            },
          }),
        });
        setData(saved);
        setMsg({
          tone: "ok",
          text: `Found tower via ${res.source} (${res.lat.toFixed(5)}, ${res.lon.toFixed(5)})${res.accuracyMeters ? ` ±${Math.round(res.accuracyMeters)}m` : ""} and pinned it!`,
        });
      } else {
        setMsg({ tone: "warn", text: res.message || "Tower not in public DB — open CellMapper to copy its coordinates." });
      }
    } catch (e) {
      setMsg({ tone: "err", text: e instanceof Error ? e.message : "Lookup failed" });
    } finally {
      setBusy(null);
    }
  };

  const deleteTower = async (id: string) => {
    setBusy(`del-${id}`);
    try {
      const res = await apiFetch<TowerFinderResponse>("/api/v1/cellular/tower-finder", {
        method: "PUT",
        body: JSON.stringify({ deleteTowerId: id }),
      });
      setData(res);
    } finally {
      setBusy(null);
    }
  };

  const saveApiKey = async (clear = false) => {
    setBusy("apikey");
    try {
      const res = await apiFetch<TowerFinderResponse>("/api/v1/cellular/tower-finder", {
        method: "PUT",
        body: JSON.stringify(clear ? { clearOpencellidKey: true } : { opencellidApiKey: apiKeyInput }),
      });
      setData(res);
      setApiKeyInput("");
      setMsg({ tone: "ok", text: clear ? "OpenCelliD API key removed." : "OpenCelliD API key saved (0600 on modem)." });
    } catch (e) {
      setMsg({ tone: "err", text: e instanceof Error ? e.message : "Failed to save API key" });
    } finally {
      setBusy(null);
    }
  };

  const serving = data?.serving ?? null;
  const activeTarget = data?.activeTarget ?? null;
  const headingDelta =
    activeHeading != null && targetBearing != null ? angularDiffDeg(targetBearing, activeHeading) : null;

  const peakSweep = useMemo(() => {
    let best: { deg: number; rsrp: number } | null = null;
    for (const [k, b] of Object.entries(sweep)) {
      const deg = Number(k) * 10;
      if (!best || b.bestRsrp > best.rsrp) best = { deg, rsrp: b.bestRsrp };
    }
    return best;
  }, [sweep]);

  const copyGnb = async () => {
    const val = serving?.gnbId != null ? String(serving.gnbId) : serving?.enbId != null ? String(serving.enbId) : "";
    if (!val) return;
    try {
      await navigator.clipboard.writeText(val);
      setCopiedGnb(true);
      setTimeout(() => setCopiedGnb(false), 1800);
    } catch {
      // ignore
    }
  };

  return (
    <Card>
      <div className="flex flex-wrap items-start justify-between gap-3 mb-4">
        <div>
          <h3 className="qm-display text-[1.12rem] font-semibold text-ink flex items-center gap-2">
            <Compass className="h-4.5 w-4.5 text-ember-ink" /> Visual Tower Finder &amp; Polar Aim Radar
          </h3>
          <p className="text-[12px] text-muted">
            Start in the tower&apos;s direction with live compass + sightline map, then sweep 360° to see the strongest RF lobe
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {serving?.cellmapperUrl && (
            <a
              href={serving.cellmapperUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 rounded-xl border border-line-strong bg-raised px-3 py-1.5 text-[12px] font-semibold text-ink hover:bg-sunk transition"
            >
              <ExternalLink className="h-3.5 w-3.5 text-ember-ink" />
              Open on CellMapper
            </a>
          )}
          <Button size="sm" variant="secondary" onClick={runAutoLookup} disabled={busy === "lookup"}>
            <Search className="h-3.5 w-3.5" />
            {busy === "lookup" ? "Looking up…" : "Auto-lookup tower"}
          </Button>
        </div>
      </div>

      {msg && (
        <div
          className={cn(
            "mb-3 rounded-xl px-3 py-2 text-[12px] font-medium",
            msg.tone === "ok"
              ? "bg-jade-soft text-jade-ink"
              : msg.tone === "warn"
                ? "bg-saffron-soft text-saffron-ink"
                : "bg-crimson-soft text-crimson-ink"
          )}
        >
          {msg.text}
        </div>
      )}

      {/* Serving Cell ID Decoder strip */}
      {serving && (
        <div className="mb-4 flex flex-wrap items-center gap-2 rounded-2xl border border-line bg-sunk/60 px-3.5 py-2.5 text-[12px] qm-tabular">
          <Badge variant="plum">{serving.rat || "Cellular"}</Badge>
          <span className="font-semibold text-ink">
            {serving.band || "—"} · PCI {serving.pci ?? "—"}
          </span>
          {serving.gnbId != null && (
            <button
              type="button"
              onClick={copyGnb}
              className="inline-flex items-center gap-1 rounded-lg bg-raised px-2 py-0.5 font-mono text-[11.5px] font-semibold text-ink hover:bg-line/50 cursor-pointer"
              title="Click to copy gNB ID for CellMapper search"
            >
              gNB {serving.gnbId}
              {copiedGnb ? <CheckCircle2 className="h-3 w-3 text-jade-ink" /> : <Copy className="h-3 w-3 text-muted" />}
            </button>
          )}
          {serving.enbId != null && (
            <button
              type="button"
              onClick={copyGnb}
              className="inline-flex items-center gap-1 rounded-lg bg-raised px-2 py-0.5 font-mono text-[11.5px] font-semibold text-ink hover:bg-line/50 cursor-pointer"
            >
              eNB {serving.enbId}
              {copiedGnb ? <CheckCircle2 className="h-3 w-3 text-jade-ink" /> : <Copy className="h-3 w-3 text-muted" />}
            </button>
          )}
          {serving.sectorId != null && <span className="text-muted">Sector {serving.sectorId}</span>}
          {serving.tacDec != null && <span className="text-muted">TAC {serving.tacDec}</span>}
          {serving.taMeters != null && serving.taMeters > 0 && (
            <span className="ml-auto font-semibold text-ember-ink">
              TA ~{(serving.taMeters / 1000).toFixed(2)} km
            </span>
          )}
        </div>
      )}

      <div className="grid gap-5 lg:grid-cols-12">
        {/* Left: Polar Compass + 360° Sweep Plot */}
        <div className="lg:col-span-5 flex flex-col items-center">
          <PolarCompassSvg
            heading={activeHeading}
            targetBearing={targetBearing}
            targetLabel={activeTarget ? `${activeTarget.tower.label} (${activeTarget.bearingDeg}°)` : null}
            sweep={sweep}
            liveRsrp={meanRsrp}
          />

          {/* Turn guidance banner */}
          <div className="mt-2 flex flex-wrap items-center justify-center gap-2 text-[12px] qm-tabular">
            {activeHeading != null && (
              <Badge variant="neutral">
                Heading {activeHeading}° {cardinalFromDeg(activeHeading)}
              </Badge>
            )}
            {headingDelta != null && (
              <Badge variant={Math.abs(headingDelta) <= 10 ? "success" : "warning"}>
                {Math.abs(headingDelta) <= 10
                  ? "Aligned on tower!"
                  : headingDelta > 0
                    ? `Turn ${Math.round(headingDelta)}° right →`
                    : `← Turn ${Math.round(Math.abs(headingDelta))}° left`}
              </Badge>
            )}
            {peakSweep && (
              <Badge variant="info">
                Sweep peak: {peakSweep.deg}° {cardinalFromDeg(peakSweep.deg)} ({peakSweep.rsrp} dBm)
              </Badge>
            )}
          </div>

          <div className="mt-3 flex flex-wrap items-center justify-center gap-2 w-full">
            <Button
              size="sm"
              variant={compassActive ? "primary" : "secondary"}
              className="min-h-10"
              onClick={toggleCompass}
            >
              <Navigation className="h-3.5 w-3.5" />
              {compassActive ? "Phone Compass: ON" : "Enable Phone Compass"}
            </Button>
            {Object.keys(sweep).length > 0 && (
              <Button size="sm" variant="ghost" className="min-h-10" onClick={() => setSweep({})}>
                Clear sweep
              </Button>
            )}
          </div>

          {/* Manual Azimuth slider for desktop/attic sweep without phone magnetometer */}
          {!compassActive && (
            <div className="mt-3 w-full max-w-[300px] qm-subcard p-2.5">
              <div className="flex items-center justify-between text-[11px] text-muted mb-1 qm-tabular">
                <span>Manual bearing sweep</span>
                <span className="font-mono font-bold text-ink">
                  {manualHeading}° {cardinalFromDeg(manualHeading)}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="range"
                  min={0}
                  max={359}
                  step={5}
                  value={manualHeading}
                  onChange={(e) => setManualHeading(Number(e.target.value))}
                  className="flex-1 accent-[var(--qm-ember)]"
                />
                <Button size="sm" variant="secondary" onClick={logManualSweep} disabled={meanRsrp == null}>
                  Plot
                </Button>
              </div>
            </div>
          )}
        </div>

        {/* Right: Sightline Map + Home & Tower Pin Controls */}
        <div className="lg:col-span-7 space-y-3 min-w-0">
          <SightlineMap
            home={data?.home ?? null}
            target={activeTarget}
            taMeters={serving?.taMeters ?? null}
          />

          {/* TA Cross-Check callout */}
          {activeTarget && (
            <div className="grid grid-cols-3 gap-2 text-[11.5px] qm-tabular">
              <div className="qm-subcard p-2">
                <div className="text-[10px] uppercase font-semibold text-muted">Tower Bearing</div>
                <div className="font-bold text-ink mt-0.5">
                  {activeTarget.bearingDeg}° {activeTarget.cardinal}
                </div>
              </div>
              <div className="qm-subcard p-2">
                <div className="text-[10px] uppercase font-semibold text-muted">Direct Distance</div>
                <div className="font-bold text-ink mt-0.5">
                  {(activeTarget.distanceMeters / 1000).toFixed(2)} km
                </div>
              </div>
              <div className="qm-subcard p-2">
                <div className="text-[10px] uppercase font-semibold text-muted">vs Timing Advance</div>
                <div
                  className={cn(
                    "font-bold mt-0.5",
                    activeTarget.taDeltaMeters == null
                      ? "text-muted"
                      : Math.abs(activeTarget.taDeltaMeters) <= 600
                        ? "text-jade-ink"
                        : "text-saffron-ink"
                  )}
                >
                  {activeTarget.taDeltaMeters == null
                    ? "—"
                    : `${activeTarget.taDeltaMeters >= 0 ? "+" : ""}${Math.round(activeTarget.taDeltaMeters)} m`}
                </div>
              </div>
            </div>
          )}

          {/* Home + Tower Coordinate Forms */}
          <div className="grid gap-2.5 sm:grid-cols-2">
            <div className="qm-subcard p-2.5 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-semibold text-ink">1. Home / Modem Location</span>
                <button
                  type="button"
                  onClick={usePhoneGps}
                  disabled={busy === "gps"}
                  className="inline-flex items-center gap-1 text-[11px] font-semibold text-ember-ink hover:underline cursor-pointer"
                >
                  <LocateFixed className="h-3 w-3" />
                  {busy === "gps" ? "Locating…" : "Use Phone GPS"}
                </button>
              </div>
              <div className="flex gap-1.5">
                <Input
                  value={homeInput}
                  onChange={(e) => setHomeInput(e.target.value)}
                  placeholder="39.1234, -84.5678"
                  className="h-9 text-[12px]"
                />
                <Button size="sm" variant="secondary" onClick={saveHomeManual} disabled={busy === "home"}>
                  Save
                </Button>
              </div>
            </div>

            <div className="qm-subcard p-2.5 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-semibold text-ink">2. Pin Tower (CellMapper / Maps)</span>
                <button
                  type="button"
                  onClick={() => setShowApiKey((v) => !v)}
                  className="inline-flex items-center gap-1 text-[11px] font-semibold text-muted hover:text-ink cursor-pointer"
                >
                  <KeyRound className="h-3 w-3" />
                  {data?.hasOpencellidKey ? "OpenCelliD: Keyed" : "API Key"}
                </button>
              </div>
              <div className="flex gap-1.5">
                <Input
                  value={towerInput}
                  onChange={(e) => setTowerInput(e.target.value)}
                  placeholder="Paste lat, lon or Maps URL"
                  className="h-9 text-[12px]"
                />
                <Button size="sm" variant="primary" onClick={pinTowerManual} disabled={busy === "tower"}>
                  Pin
                </Button>
              </div>
            </div>
          </div>

          {showApiKey && (
            <div className="qm-subcard p-2.5 flex flex-wrap items-center gap-2">
              <Input
                type="password"
                value={apiKeyInput}
                onChange={(e) => setApiKeyInput(e.target.value)}
                placeholder="Optional free OpenCelliD API key (1,000 req/day)"
                className="h-9 flex-1 min-w-[200px] text-[12px]"
              />
              <Button size="sm" variant="secondary" onClick={() => saveApiKey(false)} disabled={!apiKeyInput.trim() || busy === "apikey"}>
                Save key
              </Button>
              {data?.hasOpencellidKey && (
                <Button size="sm" variant="ghost" onClick={() => saveApiKey(true)} disabled={busy === "apikey"}>
                  Remove
                </Button>
              )}
            </div>
          )}

          {/* Pinned towers list */}
          {data && data.pinnedTowers.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5 text-[11.5px]">
              <span className="font-semibold text-muted mr-1">Pinned towers:</span>
              {data.pinnedTowers.map((t) => (
                <span
                  key={t.id}
                  className="inline-flex items-center gap-1.5 rounded-full border border-line bg-raised px-2.5 py-1 text-ink"
                >
                  <Radio className="h-3 w-3 text-ember-ink" />
                  <span className="font-semibold">{t.label}</span>
                  <span className="font-mono text-[10.5px] text-muted">
                    {t.lat.toFixed(4)}, {t.lon.toFixed(4)}
                  </span>
                  <button
                    type="button"
                    onClick={() => deleteTower(t.id)}
                    className="text-muted hover:text-crimson-ink cursor-pointer"
                    aria-label={`Delete pinned tower ${t.label}`}
                  >
                    <Trash2 className="h-3 w-3" />
                  </button>
                </span>
              ))}
            </div>
          )}

          {/* Hidden live RSRP legend reference */}
          {meanRsrp != null && (
            <div className="flex items-center justify-between text-[11px] text-muted">
              <span>Sweep color scale: emerald ≥ −85 · saffron ≥ −95 · ember ≥ −105 · crimson &lt; −105 dBm</span>
              <span className={cn("font-mono font-semibold", TONE_TEXT[rsrpTone(meanRsrp)])}>{meanRsrp} dBm</span>
            </div>
          )}
        </div>
      </div>
    </Card>
  );
}
