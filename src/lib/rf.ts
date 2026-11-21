/**
 * Pure RF / cellular utilities: NR-ARFCN & LTE-EARFCN frequency/band decoding,
 * PLMN carrier metadata, coordinate/URL parsing, and CellMapper deep links.
 */

export interface CarrierMeta {
  name: string;
  short: string;
  badge: "plum" | "danger" | "info" | "warning" | "neutral" | "success";
}

const PLMN_MAP: Record<string, CarrierMeta> = {
  "310-260": { name: "T-Mobile", short: "TMO", badge: "plum" },
  "310-160": { name: "T-Mobile", short: "TMO", badge: "plum" },
  "310-240": { name: "T-Mobile", short: "TMO", badge: "plum" },
  "311-490": { name: "T-Mobile", short: "TMO", badge: "plum" },
  "312-250": { name: "T-Mobile", short: "TMO", badge: "plum" },
  "311-480": { name: "Verizon", short: "VZW", badge: "danger" },
  "311-481": { name: "Verizon", short: "VZW", badge: "danger" },
  "310-004": { name: "Verizon", short: "VZW", badge: "danger" },
  "310-410": { name: "AT&T", short: "ATT", badge: "info" },
  "310-280": { name: "AT&T", short: "ATT", badge: "info" },
  "313-100": { name: "FirstNet", short: "FN", badge: "info" },
  "313-340": { name: "Dish / Boost", short: "DISH", badge: "warning" },
  "311-580": { name: "US Cellular", short: "USC", badge: "neutral" },
  "310-120": { name: "Sprint", short: "SPR", badge: "warning" },
  "312-530": { name: "Sprint", short: "SPR", badge: "warning" },
  "302-720": { name: "Rogers", short: "RCI", badge: "danger" },
  "302-610": { name: "Bell", short: "BEL", badge: "info" },
  "302-220": { name: "Telus", short: "TLS", badge: "success" },
};

export function normalizePlmn(mcc: string, mnc: string): string {
  const cleanMcc = mcc.trim();
  const cleanMnc = mnc.trim();
  const paddedMnc = cleanMnc.length === 2 ? `0${cleanMnc}` : cleanMnc;
  return `${cleanMcc}-${paddedMnc}`;
}

export function getCarrierMeta(mcc: string, mnc: string): CarrierMeta {
  const key = normalizePlmn(mcc, mnc);
  return PLMN_MAP[key] ?? { name: `PLMN ${key}`, short: key, badge: "neutral" };
}

/** 3GPP TS 38.104 NR-ARFCN -> downlink center frequency in MHz. */
export function nrArfcnToMhz(arfcn: number): number | null {
  if (!Number.isFinite(arfcn) || arfcn <= 0) return null;
  if (arfcn < 600_000) return Math.round(arfcn * 0.005 * 10) / 10;
  if (arfcn <= 2_016_666) return Math.round((3000 + (arfcn - 600_000) * 0.015) * 10) / 10;
  if (arfcn <= 3_279_165) return Math.round((24250.08 + (arfcn - 2_016_667) * 0.06) * 10) / 10;
  return null;
}

/** Infer 5G NR band from downlink MHz when QSCAN omits band number. */
export function inferNrBandFromMhz(mhz: number | null): string | null {
  if (mhz == null) return null;
  if (mhz >= 617 && mhz <= 652) return "n71";
  if (mhz >= 729 && mhz <= 746) return "n12";
  if (mhz >= 746 && mhz <= 756) return "n13";
  if (mhz >= 758 && mhz <= 768) return "n14";
  if (mhz >= 869 && mhz <= 894) return "n5";
  if (mhz >= 1930 && mhz <= 1995) return "n25";
  if (mhz >= 2110 && mhz <= 2200) return "n66";
  if (mhz >= 2350 && mhz <= 2360) return "n30";
  if (mhz >= 2496 && mhz <= 2690) return "n41";
  if (mhz >= 3300 && mhz <= 4200) return "n77";
  return null;
}

/** Common North American LTE EARFCN -> band + approximate DL MHz. */
export function decodeLteEarfcn(earfcn: number): { band: string; mhz: number } | null {
  if (!Number.isFinite(earfcn) || earfcn < 0) return null;
  const ranges: [number, number, string, number, number][] = [
    [600, 1199, "B2", 1930, 600],
    [1950, 2399, "B4", 2110, 1950],
    [2400, 2649, "B5", 869, 2400],
    [2750, 3449, "B7", 2620, 2750],
    [5010, 5179, "B12", 729, 5010],
    [5180, 5279, "B13", 746, 5180],
    [5280, 5379, "B14", 758, 5280],
    [8040, 8689, "B25", 1930, 8040],
    [9770, 9869, "B30", 2350, 9770],
    [39650, 41589, "B41", 2496, 39650],
    [55240, 56739, "B48", 3550, 55240],
    [66436, 67335, "B66", 2110, 66436],
    [68586, 68935, "B71", 617, 68586],
  ];
  for (const [lo, hi, band, fLow, nOffs] of ranges) {
    if (earfcn >= lo && earfcn <= hi) {
      return { band, mhz: Math.round((fLow + 0.1 * (earfcn - nOffs)) * 10) / 10 };
    }
  }
  return null;
}

export function describeChannel(rat: string, arfcn: number, rawBand?: string): { band: string; mhz: number | null } {
  const isNr = rat.toUpperCase().includes("NR");
  if (isNr) {
    const mhz = nrArfcnToMhz(arfcn);
    let band = rawBand?.trim() ?? "";
    if (band && !/^[nN]/.test(band)) band = `n${band}`;
    if (!band) band = inferNrBandFromMhz(mhz) ?? "NR";
    return { band, mhz };
  }
  const lte = decodeLteEarfcn(arfcn);
  let band = rawBand?.trim() ?? "";
  if (band && !/^[bB]/.test(band)) band = `B${band}`;
  if (!band && lte) band = lte.band;
  return { band: band || "LTE", mhz: lte?.mhz ?? null };
}

/**
 * Parse "lat, lon", "lat lon", Google Maps URLs (@lat,lon), or CellMapper URLs
 * (latitude=...&longitude=...) into validated coordinates.
 */
export function parseLatLonInput(raw: string): { lat: number; lon: number } | null {
  const text = raw.trim();
  if (!text) return null;

  // CellMapper / query params: latitude=...&longitude=...
  const qLat = text.match(/lat(?:itude)?=(-?\d+(?:\.\d+)?)/i);
  const qLon = text.match(/lon(?:gitude|g)?=(-?\d+(?:\.\d+)?)/i);
  if (qLat && qLon) {
    const lat = Number(qLat[1]);
    const lon = Number(qLon[1]);
    if (isValidCoords(lat, lon)) return { lat, lon };
  }

  // Google Maps: @39.1234,-84.5678
  const atMatch = text.match(/@(-?\d+(?:\.\d+)?),\s*(-?\d+(?:\.\d+)?)/);
  if (atMatch) {
    const lat = Number(atMatch[1]);
    const lon = Number(atMatch[2]);
    if (isValidCoords(lat, lon)) return { lat, lon };
  }

  // Plain pair: "39.1234, -84.5678" or "39.1234 -84.5678"
  const pair = text.match(/(-?\d+(?:\.\d+)?)\s*[,;\s]\s*(-?\d+(?:\.\d+)?)/);
  if (pair) {
    const lat = Number(pair[1]);
    const lon = Number(pair[2]);
    if (isValidCoords(lat, lon)) return { lat, lon };
  }
  return null;
}

export function isValidCoords(lat: number, lon: number): boolean {
  return Number.isFinite(lat) && Number.isFinite(lon) && lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180;
}

export function buildCellMapperUrl(
  mcc: string,
  mnc: string,
  rat: string,
  coords?: { lat: number; lon: number } | null
): string {
  const type = rat.toUpperCase().includes("NR") ? "NR" : "LTE";
  let url = `https://www.cellmapper.net/map?MCC=${encodeURIComponent(mcc.trim())}&MNC=${encodeURIComponent(mnc.trim())}&type=${type}`;
  if (coords && isValidCoords(coords.lat, coords.lon)) {
    url += `&latitude=${coords.lat.toFixed(5)}&longitude=${coords.lon.toFixed(5)}&zoom=13`;
  }
  return url;
}

export function cardinalFromDeg(deg: number): string {
  const dirs = ["N", "NNE", "NE", "ENE", "E", "ESE", "SE", "SSE", "S", "SSW", "SW", "WSW", "W", "WNW", "NW", "NNW"];
  const idx = Math.round((((deg % 360) + 360) % 360) / 22.5) % 16;
  return dirs[idx];
}

export function angularDiffDeg(a: number, b: number): number {
  const d = ((((a - b) % 360) + 540) % 360) - 180;
  return Math.round(d * 10) / 10;
}
