import type {
  AtCommandItem,
  CarrierComponent,
  MbnProfile,
  MimoSignalData,
  MpdnRule,
  NeighborCellInfo,
  ServingCellInfo,
  SignalHistoryPoint,
  TempSensor,
  TrafficInterfaceStats,
  WwanBearerInfo,
} from "../types/cellcore";

export function extractAtResponse(
  input: AtCommandItem[] | { items?: AtCommandItem[] } | undefined,
  cmd: string
): string {
  const items = Array.isArray(input) ? input : input?.items;
  if (!Array.isArray(items)) return "";
  const target = cmd.trim().toUpperCase();
  const exact = items.find((i) => i.command.trim().toUpperCase() === target);
  if (exact) return exact.response ?? "";
  const partial = items.find((i) => i.command.toUpperCase().includes(target));
  return partial?.response ?? "";
}

export function cleanAtLines(resp: string): string[] {
  return resp
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(
      (l) =>
        l.length > 0 &&
        l !== "OK" &&
        l !== "ERROR" &&
        !/^\+CM[ES]\s*ERROR/i.test(l) &&
        !/^AT(?:[+\w=?"/,\-.;*#]*)$/i.test(l)
    );
}

function unquote(v: string | undefined): string {
  if (!v) return "";
  const s = v.trim();
  if (s === "-" || s === "null" || s === "N/A") return "";
  return s.replace(/^"(.*)"$/, "$1").trim();
}

function toInt(v: string | undefined): number | null {
  const s = unquote(v);
  if (!s) return null;
  const n = Number(s);
  return Number.isFinite(n) ? Math.trunc(n) : null;
}

function toFloat(v: string | undefined): number | null {
  const s = unquote(v);
  if (!s) return null;
  const n = Number(s);
  return Number.isFinite(n) ? n : null;
}

function splitCsvFields(line: string): string[] {
  const fields: string[] = [];
  let cur = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      inQuotes = !inQuotes;
      cur += ch;
    } else if (ch === "," && !inQuotes) {
      fields.push(cur.trim());
      cur = "";
    } else {
      cur += ch;
    }
  }
  fields.push(cur.trim());
  return fields;
}

const LTE_RB_TO_MHZ: Record<number, number> = {
  6: 1.4,
  15: 3,
  25: 5,
  50: 10,
  75: 15,
  100: 20,
};

const LTE_QENG_CODE_TO_MHZ: Record<number, number> = {
  0: 1.4,
  1: 3,
  2: 5,
  3: 10,
  4: 15,
  5: 20,
};

const NR5G_BW_CODE_TO_MHZ: Record<number, number> = {
  0: 5,
  1: 10,
  2: 15,
  3: 20,
  4: 25,
  5: 30,
  6: 40,
  7: 50,
  8: 60,
  9: 70,
  10: 80,
  11: 90,
  12: 100,
  13: 200,
  14: 400,
};

export function decodeNrBwMhz(code: number | null, arfcn: number | null = null, fromQeng = false): number | null {
  if (code == null) return null;
  const isFr1 = arfcn != null && arfcn > 0 && arfcn < 2054166;
  // On SDX75 RM551E-GL R02A02, AT+QENG="servingcell" emits dlBwCode=14 for 90 MHz FR1 carriers.
  if (fromQeng && isFr1 && code === 14) return 90;
  const mapped = NR5G_BW_CODE_TO_MHZ[code];
  if (mapped != null) {
    if (isFr1 && mapped > 100) return null;
    return mapped;
  }
  return null;
}

export function decodeLteBwMhz(code: number | null): number | null {
  if (code == null) return null;
  return LTE_RB_TO_MHZ[code] ?? LTE_QENG_CODE_TO_MHZ[code] ?? null;
}

export function parseScalarAtValue(resp: string, prefix: string): string {
  for (const line of cleanAtLines(resp)) {
    if (prefix) {
      if (line.startsWith(prefix)) {
        return unquote(line.slice(prefix.length).replace(/^[\s:]+/, ""));
      }
      continue;
    }
    return unquote(line);
  }
  return "";
}

export function parse3gppRel(resp: string): string {
  for (const line of cleanAtLines(resp)) {
    if (line.includes('"3gpp_rel"') || line.startsWith("+QNWCFG:")) {
      const f = splitCsvFields(line.replace(/^\+QNWCFG:\s*/, ""));
      const token = unquote(f[1] ?? "");
      const m = token.match(/R?(\d+)/i);
      if (m) return `3GPP Rel-${m[1]}`;
    }
    const stripped = line.replace(/"3gpp_rel"/gi, "");
    const m2 = stripped.match(/R?(\d+)/i);
    if (m2) return `3GPP Rel-${m2[1]}`;
  }
  return "N/A";
}

export interface QmapLanIpInfo {
  poolStart: string;
  poolEnd: string;
  gatewayIp: string;
  netmask: string;
  raw: string;
}

function ipv4ToU32(ip: string): number | null {
  const octets = ip.split(".");
  if (octets.length !== 4 || !octets.every((o) => /^\d+$/.test(o) && Number(o) <= 255)) return null;
  return (
    ((Number(octets[0]) << 24) |
      (Number(octets[1]) << 16) |
      (Number(octets[2]) << 8) |
      Number(octets[3])) >>>
    0
  );
}

function inferLanNetmask(poolStart: string, poolEnd: string, gatewayIp: string): string {
  const nums = [poolStart, poolEnd, gatewayIp].map(ipv4ToU32).filter((v): v is number => v != null);
  if (nums.length < 2) return "";
  const minIp = Math.min(...nums);
  const maxIp = Math.max(...nums);
  const xor = (minIp ^ maxIp) >>> 0;
  const hostBits = xor === 0 ? 8 : Math.max(2, 32 - Math.clz32(xor));
  const prefix = 32 - hostBits;
  const maskInt = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const maskStr = [
    (maskInt >>> 24) & 255,
    (maskInt >>> 16) & 255,
    (maskInt >>> 8) & 255,
    maskInt & 255,
  ].join(".");
  return `${maskStr} (/${prefix})`;
}

export function parseQmapLanIp(resp: string): QmapLanIpInfo | null {
  for (const line of cleanAtLines(resp)) {
    if (!line.includes("LANIP")) continue;
    const f = splitCsvFields(line.replace(/^\+QMAP:\s*/, ""));
    const ips = f.slice(1).map((x) => unquote(x)).filter(Boolean);
    if (ips.length >= 4) {
      return {
        poolStart: ips[0],
        poolEnd: ips[1],
        gatewayIp: ips[2],
        netmask: ips[3],
        raw: ips.join(", "),
      };
    }
    if (ips.length === 3) {
      return {
        poolStart: ips[0],
        poolEnd: ips[1],
        gatewayIp: ips[2],
        netmask: inferLanNetmask(ips[0], ips[1], ips[2]),
        raw: ips.join(", "),
      };
    }
    if (ips.length > 0) {
      return {
        poolStart: ips[0] ?? "",
        poolEnd: ips[1] ?? "",
        gatewayIp: ips[0] ?? "",
        netmask: "",
        raw: ips.join(", "),
      };
    }
  }
  return null;
}

function decodeScsKhz(code: number | null): number | null {
  switch (code) {
    case 0:
      return 15;
    case 1:
      return 30;
    case 2:
      return 60;
    case 3:
      return 120;
    case 4:
      return 240;
    default:
      return null;
  }
}

export function parseServingCell(qengResp: string, carriers?: CarrierComponent[]): ServingCellInfo | null {
  const lines = cleanAtLines(qengResp).filter((l) => l.startsWith("+QENG:"));
  if (lines.length === 0) return null;

  const pcc = carriers?.find((c) => c.role === "PCC");

  for (const line of lines) {
    const body = line.replace(/^\+QENG:\s*/, "");
    const f = splitCsvFields(body);
    const kind = unquote(f[0]).toLowerCase();

    if (kind === "servingcell") {
      const state = unquote(f[1]) || "UNKNOWN";
      const rat = unquote(f[2]).toUpperCase();

      if (rat === "NR5G-SA") {
        const arfcn = toInt(f[9]);
        const bandNum = unquote(f[10]);
        const dlCode = toInt(f[11]);
        const pci = toInt(f[7]);
        const rawDlBw = decodeNrBwMhz(dlCode, arfcn, true);
        const pccMatches = pcc && ((arfcn != null && pcc.arfcn === arfcn) || (pci != null && pcc.pci === pci));
        const resolvedBw = (pccMatches ? pcc.bandwidthMhz : pcc?.bandwidthMhz) ?? rawDlBw;
        return {
          state,
          rat,
          duplexMode: unquote(f[3]) || "-",
          mcc: unquote(f[4]),
          mnc: unquote(f[5]),
          cellId: unquote(f[6]),
          pci,
          tac: unquote(f[8]),
          arfcn,
          band: bandNum ? `n${bandNum}` : pcc?.band ?? "-",
          ulBandwidthMhz: resolvedBw,
          dlBandwidthMhz: resolvedBw,
          rsrp: toFloat(f[12]),
          rsrq: toFloat(f[13]),
          sinr: toFloat(f[14]),
          txPower: null,
          scsKhz: decodeScsKhz(toInt(f[15])),
          srxlev: toFloat(f[16]),
          raw: line,
        };
      }

      if (rat === "LTE") {
        const ulBw = decodeLteBwMhz(toInt(f[10]));
        const dlBw = decodeLteBwMhz(toInt(f[11]));
        const bandNum = unquote(f[9]);
        return {
          state,
          rat,
          duplexMode: unquote(f[3]) || "-",
          mcc: unquote(f[4]),
          mnc: unquote(f[5]),
          cellId: unquote(f[6]),
          pci: toInt(f[7]),
          tac: unquote(f[12]),
          arfcn: toInt(f[8]),
          band: bandNum ? `B${bandNum}` : "-",
          ulBandwidthMhz: ulBw,
          dlBandwidthMhz: dlBw,
          rsrp: toFloat(f[13]),
          rsrq: toFloat(f[14]),
          sinr: toFloat(f[16]),
          txPower: null,
          srxlev: toFloat(f[17]),
          raw: line,
        };
      }

      return {
        state,
        rat: rat || "UNKNOWN",
        duplexMode: unquote(f[3]) || "-",
        mcc: unquote(f[4]),
        mnc: unquote(f[5]),
        cellId: unquote(f[6]),
        pci: toInt(f[7]),
        tac: unquote(f[8]),
        arfcn: toInt(f[9]),
        band: unquote(f[10]) || "-",
        ulBandwidthMhz: null,
        dlBandwidthMhz: null,
        rsrp: toFloat(f[12]),
        rsrq: toFloat(f[13]),
        sinr: toFloat(f[14]),
        txPower: null,
        srxlev: null,
        raw: line,
      };
    }

    if (kind === "lte") {
      const ulBw = decodeLteBwMhz(toInt(f[9]));
      const dlBw = decodeLteBwMhz(toInt(f[10]));
      const bandNum = unquote(f[8]);
      return {
        state: "CONNECT",
        rat: "LTE (EN-DC)",
        duplexMode: unquote(f[1]) || "-",
        mcc: unquote(f[2]),
        mnc: unquote(f[3]),
        cellId: unquote(f[4]),
        pci: toInt(f[5]),
        tac: unquote(f[11]),
        arfcn: toInt(f[6]),
        band: bandNum ? `B${bandNum}` : "-",
        ulBandwidthMhz: ulBw,
        dlBandwidthMhz: dlBw,
        rsrp: toFloat(f[12]),
        rsrq: toFloat(f[13]),
        sinr: toFloat(f[15]),
        txPower: null,
        srxlev: toFloat(f[16]),
        raw: line,
      };
    }
  }

  return null;
}

export function parseMimoSignal(qrsrpResp: string, qrsrqResp: string, qsinrResp: string): MimoSignalData {
  const parseTuple = (resp: string, prefix: string): { vals: (number | null)[]; rat: string } => {
    const line = cleanAtLines(resp).find((l) => l.startsWith(prefix));
    if (!line) return { vals: [null, null, null, null], rat: "" };
    const f = splitCsvFields(line.replace(new RegExp(`^\\${prefix}:\\s*`), ""));
    const nums = [0, 1, 2, 3].map((idx) => {
      const n = toFloat(f[idx]);
      if (n == null || n === -140 || n === -32768 || n === 255) return null;
      return n;
    });
    const rat = unquote(f[4]);
    return { vals: nums, rat };
  };

  const p = parseTuple(qrsrpResp, "+QRSRP");
  const q = parseTuple(qrsrqResp, "+QRSRQ");
  const s = parseTuple(qsinrResp, "+QSINR");

  return {
    rsrp: p.vals,
    rsrq: q.vals,
    sinr: s.vals,
    rat: p.rat || q.rat || s.rat || "NR5G",
  };
}

export function parseCarrierAggregation(qcainfoResp: string): CarrierComponent[] {
  const lines = cleanAtLines(qcainfoResp).filter((l) => l.startsWith("+QCAINFO:"));
  const out: CarrierComponent[] = [];

  for (const line of lines) {
    const f = splitCsvFields(line.replace(/^\+QCAINFO:\s*/, ""));
    const roleRaw = unquote(f[0]).toUpperCase();
    if (roleRaw !== "PCC" && roleRaw !== "SCC") continue;
    const arfcn = toInt(f[1]);
    const bwCode = toInt(f[2]);
    const bandRaw = unquote(f[3]);
    if (arfcn == null || bwCode == null) continue;

    const isNr = bandRaw.toUpperCase().includes("NR5G");
    const bandwidthMhz = isNr ? decodeNrBwMhz(bwCode, arfcn, false) : decodeLteBwMhz(bwCode);
    const filt = (v: number | null): number | null => (v != null && v !== -140 && v !== -32768 ? v : null);

    let pcellState: number | null = null;
    let pci: number | null = null;
    let ulConfigured = roleRaw === "PCC";
    let ulArfcn: number | null = null;
    let ulBandwidthMhz: number | null = null;
    let rsrp: number | null = null;
    let rsrq: number | null = null;
    let rssi: number | null = null;
    let sinr: number | null = null;

    if (isNr) {
      pcellState = roleRaw === "SCC" ? toInt(f[4]) : null;
      pci = roleRaw === "PCC" ? toInt(f[4]) : toInt(f[5]);
      const ulConfiguredFlag = roleRaw === "SCC" ? toInt(f[6]) : null;
      ulConfigured = roleRaw === "PCC" ? true : ulConfiguredFlag === 1;
      ulArfcn = roleRaw === "SCC" ? toInt(f[8]) : null;
      const ulBwCode = roleRaw === "SCC" ? toInt(f[7]) : null;
      ulBandwidthMhz =
        roleRaw === "SCC" && ulBwCode != null
          ? decodeNrBwMhz(ulBwCode, ulArfcn ?? arfcn, false)
          : null;
    } else {
      // Quectel LTE +QCAINFO: "PCC"|"SCC",<earfcn>,<bw>,<band>,<state>,<pcid>,<rsrp>,<rsrq>,<rssi>,<sinr>
      pcellState = f.length >= 6 ? toInt(f[4]) : null;
      pci = f.length >= 6 ? toInt(f[5]) : toInt(f[4]);
      rsrp = filt(toFloat(f[6]));
      rsrq = filt(toFloat(f[7]));
      rssi = filt(toFloat(f[8]));
      sinr = filt(toFloat(f[9]));
    }

    const compactBand = bandRaw
      .replace(/^NR5G\s+BAND\s+/i, "n")
      .replace(/^LTE\s+BAND\s+/i, "B");

    out.push({
      role: roleRaw,
      arfcn,
      bandwidthCode: bwCode,
      bandwidthMhz,
      band: compactBand || bandRaw,
      pci,
      pcellState,
      ulConfigured,
      ulArfcn,
      ulBandwidthMhz,
      rsrp,
      rsrq,
      rssi,
      sinr,
    });
  }

  return out;
}

function formatIpv6Rfc5952(hextets: number[]): string {
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;

  for (let i = 0; i < 8; i++) {
    if (hextets[i] === 0) {
      if (curStart === -1) curStart = i;
      curLen++;
      if (curLen > bestLen) {
        bestStart = curStart;
        bestLen = curLen;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }

  if (bestLen < 2) {
    return hextets.map((h) => h.toString(16)).join(":");
  }

  const left = hextets
    .slice(0, bestStart)
    .map((h) => h.toString(16))
    .join(":");
  const right = hextets
    .slice(bestStart + bestLen)
    .map((h) => h.toString(16))
    .join(":");
  return `${left}::${right}`;
}

export function decode3gppAddress(raw: string | undefined): { address: string; prefixLength: number | null } {
  const s = unquote(raw);
  if (!s) return { address: "", prefixLength: null };

  if (s.includes(":")) {
    const [addr, plen] = s.split("/");
    return {
      address: addr.trim(),
      prefixLength: plen != null && /^\d+$/.test(plen) ? Number(plen) : null,
    };
  }

  const parts = s.split(".");
  if (!parts.every((p) => /^\d+$/.test(p) && Number(p) >= 0 && Number(p) <= 255)) {
    return { address: s, prefixLength: null };
  }

  const octets = parts.map(Number);

  if (octets.length === 4) {
    return { address: octets.join("."), prefixLength: null };
  }

  if (octets.length === 8) {
    const maskBytes = octets.slice(4, 8);
    let prefix = 0;
    for (const b of maskBytes) {
      let tmp = b;
      for (let bit = 7; bit >= 0; bit--) {
        if ((tmp >> bit) & 1) prefix++;
        else break;
      }
    }
    return { address: octets.slice(0, 4).join("."), prefixLength: prefix || null };
  }

  if (octets.length === 16 || octets.length === 32) {
    const addrBytes = octets.slice(0, 16);
    const hextets: number[] = [];
    for (let i = 0; i < 16; i += 2) {
      hextets.push((addrBytes[i] << 8) | addrBytes[i + 1]);
    }
    let prefixLength: number | null = null;
    if (octets.length === 32) {
      let bits = 0;
      for (const b of octets.slice(16, 32)) {
        for (let bit = 7; bit >= 0; bit--) {
          if ((b >> bit) & 1) bits++;
          else break;
        }
      }
      prefixLength = bits || null;
    }
    return { address: formatIpv6Rfc5952(hextets), prefixLength };
  }

  return { address: s, prefixLength: null };
}

export function parseActiveWwan(
  qmapWwanResp: string,
  cgcontrdpResp: string
): WwanBearerInfo[] {
  const byCid = new Map<number, WwanBearerInfo>();

  for (const line of cleanAtLines(cgcontrdpResp)) {
    if (!line.startsWith("+CGCONTRDP:")) continue;
    const f = splitCsvFields(line.replace(/^\+CGCONTRDP:\s*/, ""));
    const cid = toInt(f[0]) ?? 1;
    const apn = unquote(f[2]);
    const localDecoded = decode3gppAddress(f[3]);
    const gwDecoded = decode3gppAddress(f[4]);
    const dns1Decoded = decode3gppAddress(f[5]);
    const dns2Decoded = decode3gppAddress(f[6]);

    const existing: WwanBearerInfo = byCid.get(cid) ?? {
      iface: "rmnet_data1",
      cid,
      ipType: "IPV4V6",
      status: "CONNECTED",
      apn,
    };

    const targetIsV6 = localDecoded.address.includes(":");
    if (targetIsV6) {
      existing.ipv6 = localDecoded.address;
      existing.ipv6PrefixLength = localDecoded.prefixLength;
      if (gwDecoded.address) existing.ipv6Gateway = gwDecoded.address;
      if (dns1Decoded.address) existing.ipv6Dns1 = dns1Decoded.address;
      if (dns2Decoded.address) existing.ipv6Dns2 = dns2Decoded.address;
    } else if (localDecoded.address) {
      existing.ipv4 = localDecoded.address;
      if (gwDecoded.address) existing.ipv4Gateway = gwDecoded.address;
      if (dns1Decoded.address) existing.ipv4Dns1 = dns1Decoded.address;
      if (dns2Decoded.address) existing.ipv4Dns2 = dns2Decoded.address;
    }

    if (!existing.apn && apn) existing.apn = apn;
    byCid.set(cid, existing);
  }

  for (const line of cleanAtLines(qmapWwanResp)) {
    if (!line.startsWith("+QMAP:")) continue;
    const f = splitCsvFields(line.replace(/^\+QMAP:\s*/, ""));
    if (unquote(f[0]).toUpperCase() !== "WWAN") continue;
    const stateNum = toInt(f[1]);
    const cid = toInt(f[2]) ?? 1;
    const ipTypeRaw = unquote(f[3]).toUpperCase();
    const addrRaw = unquote(f[4]);
    const ifaceRaw = unquote(f[5]);
    const statusText = stateNum === 1 ? "CONNECTED" : "DISCONNECTED";

    const existing = byCid.get(cid) ?? {
      iface: ifaceRaw || "rmnet_data1",
      cid,
      ipType: (ipTypeRaw === "IPV4" || ipTypeRaw === "IPV6" ? ipTypeRaw : "IPV4V6") as WwanBearerInfo["ipType"],
      status: statusText,
      apn: "",
    };

    if (ifaceRaw && ifaceRaw.startsWith("rmnet")) existing.iface = ifaceRaw;
    if (stateNum === 1) existing.status = "CONNECTED";
    if (ipTypeRaw === "IPV4" && addrRaw && addrRaw !== "0.0.0.0") existing.ipv4 = addrRaw;
    if (ipTypeRaw === "IPV6" && addrRaw && addrRaw !== "::") existing.ipv6 = addrRaw;

    byCid.set(cid, existing);
  }

  return Array.from(byCid.values());
}

export function pickActiveRmnetInterfaces(list: TrafficInterfaceStats[]): {
  primary: TrafficInterfaceStats | null;
  lan: TrafficInterfaceStats | null;
} {
  const allRmnets = list.filter((i) => i.name.startsWith("rmnet"));
  // Prefer actual L3 bearer interfaces (rmnet_data*) over the raw Qualcomm QMAP parent mux (rmnet_ipa0).
  const dataRmnets = allRmnets.filter((i) => i.name.startsWith("rmnet_data"));
  const rmnets = dataRmnets.length > 0 ? dataRmnets : allRmnets;
  const lan = list.find((i) => i.name === "eth0") ?? list.find((i) => i.name.startsWith("eth")) ?? null;

  if (rmnets.length === 0) return { primary: null, lan };

  const primary =
    rmnets.find(
      (i) =>
        i.state.toLowerCase() === "up" &&
        ((i.rx?.bps ?? 0) > 0 ||
          (i.tx?.bps ?? 0) > 0 ||
          (i.rx?.bytesTotal ?? i.rx?.bytes_total ?? 0) > 0)
    ) ??
    rmnets.find((i) => i.state.toLowerCase() === "up") ??
    [...rmnets].sort(
      (a, b) =>
        (b.rx?.bytesTotal ?? b.rx?.bytes_total ?? 0) -
        (a.rx?.bytesTotal ?? a.rx?.bytes_total ?? 0)
    )[0] ??
    rmnets[0];

  return { primary, lan };
}

export interface ParsedTimeAdvance {
  nr5gRaw: number | null;
  nr5gSteps: number | null;
  nr5gMeters: number | null;
  lteTa: number | null;
  lteMeters: number | null;
  activeMeters: number | null;
}

export function parseTimeAdvance(lteResp: string, nr5gResp: string): ParsedTimeAdvance {
  let nr5gRaw: number | null = null;
  let nr5gSteps: number | null = null;
  let nr5gMeters: number | null = null;

  for (const line of cleanAtLines(nr5gResp)) {
    if (!line.includes("nr5g_time_advance")) continue;
    const f = splitCsvFields(line.replace(/^\+QNWCFG:\s*/, ""));
    const valid = toInt(f[1]);
    const raw = toInt(f[2]);
    if (valid === 1 && raw != null && raw >= 0 && raw < 20000000) {
      nr5gRaw = raw;
      // SDX75 nr5g_time_advance returns Tc units (Tc = 1/(480000*4096) s; d = raw * c * Tc / 2)
      nr5gMeters = Math.round(raw * 0.07624);
      nr5gSteps = Math.round(raw / 512);
      break;
    }
  }

  let lteTa: number | null = null;
  let lteMeters: number | null = null;
  for (const line of cleanAtLines(lteResp)) {
    if (!line.includes("lte_time_advance")) continue;
    const f = splitCsvFields(line.replace(/^\+QNWCFG:\s*/, ""));
    const valid = f.length >= 3 ? toInt(f[1]) : 1;
    const ta = toInt(f.length >= 3 ? f[2] : f[1]);
    if (valid === 1 && ta != null && ta >= 0 && ta < 65535) {
      lteTa = ta;
      lteMeters = Math.round(ta * 78.12);
      break;
    }
  }

  return {
    nr5gRaw,
    nr5gSteps,
    nr5gMeters,
    lteTa,
    lteMeters,
    activeMeters: nr5gMeters ?? lteMeters ?? null,
  };
}

export function formatDistanceValue(meters: number | null, unit: "mi" | "km" = "mi"): string {
  if (meters == null || !Number.isFinite(meters) || meters < 0) return "--";
  if (unit === "km") {
    const km = meters / 1000;
    return `${km < 10 ? km.toFixed(2) : km.toFixed(1)} km`;
  }
  const miles = meters / 1609.344;
  return `${miles < 10 ? miles.toFixed(2) : miles.toFixed(1)} mi`;
}

export function parseTempSensors(resp: string): TempSensor[] {
  const out: TempSensor[] = [];
  for (const line of cleanAtLines(resp)) {
    if (!line.startsWith("+QTEMP:")) continue;
    const f = splitCsvFields(line.replace(/^\+QTEMP:\s*/, ""));
    const sensor = unquote(f[0]);
    const celsius = toFloat(f[1]);
    if (sensor && celsius != null && celsius > -40 && celsius < 150) {
      out.push({ sensor, celsius });
    }
  }
  return out;
}

export function parseMbnList(resp: string): MbnProfile[] {
  const out: MbnProfile[] = [];
  for (const line of cleanAtLines(resp)) {
    if (!line.startsWith("+QMBNCFG:")) continue;
    const f = splitCsvFields(line.replace(/^\+QMBNCFG:\s*/, ""));
    if (unquote(f[0]).toLowerCase() !== "list") continue;
    const index = toInt(f[1]);
    const selected = toInt(f[2]) === 1;
    const activated = toInt(f[3]) === 1;
    const name = unquote(f[4]);
    const version = unquote(f[5]);
    const date = unquote(f[6]);
    if (index != null && name) {
      out.push({ index, selected, activated, name, version, date });
    }
  }
  return out;
}

export function parseMpdnRules(resp: string): MpdnRule[] {
  const rules: MpdnRule[] = [];
  for (const line of cleanAtLines(resp)) {
    if (!line.includes("MPDN_rule") && !line.includes("MPDN_RULE")) continue;
    const f = splitCsvFields(line.replace(/^\+QMAP:\s*/, ""));
    const slot = toInt(f[1]);
    const apnSlot = toInt(f[2]);
    const vlanId = toInt(f[3]);
    const mode = unquote(f[4]);
    const macCandidate = unquote(f[6] ?? f[5]);
    const mac = /^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i.test(macCandidate) ? macCandidate : "";
    if (slot != null && apnSlot != null) {
      rules.push({ slot, apnSlot, vlanId: vlanId ?? 0, mode: mode || "0", mac, raw: line });
    }
  }
  return rules;
}

export function parseSignalHistory(
  entries: Array<{ datetime?: string; timestamp?: string; output?: string }> | undefined
): SignalHistoryPoint[] {
  if (!Array.isArray(entries)) return [];
  const points: SignalHistoryPoint[] = [];

  for (const entry of entries) {
    const dtStr = String(entry.datetime ?? entry.timestamp ?? "").trim();
    const rawOut = String(entry.output ?? "");
    const match = rawOut.match(/\+Q(?:RSRP|RSRQ|SINR):\s*([^\r\n]+)/i);
    if (!match) continue;

    const parts = splitCsvFields(match[1]).slice(0, 4);
    const chains = parts.map((p) => {
      const n = toFloat(p);
      if (n == null || n === -140 || n === -32768 || n === 255) return null;
      return n;
    });
    const valid = chains.filter((v): v is number => v != null);
    if (valid.length === 0) continue;

    const avg = Math.round((valid.reduce((a, b) => a + b, 0) / valid.length) * 10) / 10;
    const parsedTs = dtStr ? Date.parse(dtStr.replace(" ", "T")) : NaN;
    const ts = Number.isFinite(parsedTs) ? parsedTs : Date.now();
    const labelMatch = dtStr.match(/(\d{2}:\d{2}(?::\d{2})?)/);
    const label = labelMatch ? labelMatch[1].slice(0, 5) : "--:--";

    points.push({ ts, label, value: avg, chains });
  }

  return points.slice(-60);
}

export function getBandMetadata(band: string): { label: string; spectrum: string; duplex: string } {
  const b = band.trim().toLowerCase();
  const map: Record<string, { label: string; spectrum: string; duplex: string }> = {
    n41: { label: "n41", spectrum: "2.5 GHz", duplex: "TDD" },
    n25: { label: "n25", spectrum: "1.9 GHz PCS", duplex: "FDD" },
    n66: { label: "n66", spectrum: "AWS-3", duplex: "FDD/SDL" },
    n71: { label: "n71", spectrum: "600 MHz", duplex: "FDD" },
    n77: { label: "n77", spectrum: "3.7 GHz C", duplex: "TDD" },
    n78: { label: "n78", spectrum: "3.5 GHz C", duplex: "TDD" },
    n79: { label: "n79", spectrum: "4.9 GHz", duplex: "TDD" },
    n2: { label: "n2", spectrum: "1.9 GHz PCS", duplex: "FDD" },
    n5: { label: "n5", spectrum: "850 MHz", duplex: "FDD" },
    n7: { label: "n7", spectrum: "2.6 GHz", duplex: "FDD" },
    n12: { label: "n12", spectrum: "700 MHz", duplex: "FDD" },
    n28: { label: "n28", spectrum: "700 MHz APT", duplex: "FDD" },
    n30: { label: "n30", spectrum: "2.3 GHz WCS", duplex: "FDD" },
    n38: { label: "n38", spectrum: "2.6 GHz", duplex: "TDD" },
    n48: { label: "n48", spectrum: "3.5 GHz CBRS", duplex: "TDD" },
    b2: { label: "B2", spectrum: "1.9 GHz PCS", duplex: "FDD" },
    b4: { label: "B4", spectrum: "AWS-1", duplex: "FDD" },
    b5: { label: "B5", spectrum: "850 MHz", duplex: "FDD" },
    b7: { label: "B7", spectrum: "2.6 GHz", duplex: "FDD" },
    b12: { label: "B12", spectrum: "700 MHz", duplex: "FDD" },
    b13: { label: "B13", spectrum: "700 MHz", duplex: "FDD" },
    b14: { label: "B14", spectrum: "FirstNet 700", duplex: "FDD" },
    b25: { label: "B25", spectrum: "1.9 GHz PCS", duplex: "FDD" },
    b30: { label: "B30", spectrum: "2.3 GHz WCS", duplex: "FDD" },
    b38: { label: "B38", spectrum: "2.6 GHz", duplex: "TDD" },
    b41: { label: "B41", spectrum: "2.5 GHz", duplex: "TDD" },
    b48: { label: "B48", spectrum: "3.5 GHz CBRS", duplex: "TDD" },
    b66: { label: "B66", spectrum: "AWS-3", duplex: "FDD" },
    b71: { label: "B71", spectrum: "600 MHz", duplex: "FDD" },
  };
  return map[b] ?? { label: band, spectrum: b.startsWith("n") ? "5G NR" : "4G LTE", duplex: "-" };
}

export function parseNeighborCells(resp: string): NeighborCellInfo[] {
  const out: NeighborCellInfo[] = [];
  for (const line of cleanAtLines(resp)) {
    if (!line.startsWith("+QENG:")) continue;
    const f = splitCsvFields(line.replace(/^\+QENG:\s*/, ""));
    const kind = unquote(f[0]).toLowerCase();
    if (!kind.includes("neighbourcell") && !kind.includes("neighborcell")) continue;
    const rat = unquote(f[1]).toUpperCase() || (kind.includes("nr") ? "NR5G" : "LTE");
    const arfcn = toInt(f[2]);
    const pci = toInt(f[3]);
    const rsrp = toFloat(f[4]);
    const rsrq = toFloat(f[5]);
    const sinr = toFloat(f[6]);
    const srxlev = toFloat(f[7]);
    out.push({
      rat,
      type: kind.includes("inter") ? "inter" : "intra",
      arfcn,
      pci,
      rsrp: rsrp === -140 ? null : rsrp,
      rsrq: rsrq === -140 ? null : rsrq,
      sinr,
      srxlev,
      raw: line,
    });
  }
  return out;
}

export function parseQspnOperator(resp: string): string {
  for (const line of cleanAtLines(resp)) {
    if (!line.startsWith("+QSPN:")) continue;
    const f = splitCsvFields(line.replace(/^\+QSPN:\s*/, ""));
    const full = unquote(f[0]);
    const shortName = unquote(f[1]);
    if (full || shortName) return full || shortName;
  }
  return "";
}

export function parseRegState(resp: string): { stat: number | null; label: string; tac?: string; cellId?: string } {
  for (const line of cleanAtLines(resp)) {
    const m = line.match(/^\+C(?:5G|E|G)?REG:\s*(.+)$/);
    if (!m) continue;
    const f = splitCsvFields(m[1]);
    const stat = f.length >= 2 && Number(unquote(f[0])) <= 2 && Number(unquote(f[1])) <= 11 ? toInt(f[1]) : toInt(f[0]);
    const labels: Record<number, string> = {
      0: "Not Registered",
      1: "Registered (Home)",
      2: "Searching",
      3: "Denied",
      4: "Unknown",
      5: "Registered (Roaming)",
    };
    return {
      stat,
      label: stat != null ? labels[stat] ?? `State ${stat}` : "Unknown",
      tac: unquote(f[2]),
      cellId: unquote(f[3]),
    };
  }
  return { stat: null, label: "Unknown" };
}

export const SMS_UNKNOWN_TIME = "unknown time";

/**
 * Normalise an SMS time stamp to "YYYY-MM-DD hh:mm:ss". Accepts the daemon's format and the
 * modem's text-mode "yy/MM/dd,hh:mm:ss". Anything else (empty, corrupt SCTS) is SMS_UNKNOWN_TIME,
 * never a made-up date.
 */
export function parseSmsTimestamp(raw: string | null | undefined): string {
  const s = String(raw ?? "").trim();
  let y: number, mo: number, d: number, time: string;
  let m = s.match(/^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})$/);
  if (m) {
    [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
    time = `${m[4]}:${m[5]}:${m[6]}`;
  } else if ((m = s.match(/^"?(\d{2})\/(\d{2})\/(\d{2}),(\d{2}):(\d{2}):(\d{2})/))) {
    [y, mo, d] = [2000 + Number(m[1]), Number(m[2]), Number(m[3])];
    time = `${m[4]}:${m[5]}:${m[6]}`;
  } else {
    return SMS_UNKNOWN_TIME;
  }
  const [hh, mm, ss] = time.split(":").map(Number);
  if (mo < 1 || mo > 12 || d < 1 || d > 31 || hh > 23 || mm > 59 || ss > 59) return SMS_UNKNOWN_TIME;
  return `${y}-${String(mo).padStart(2, "0")}-${String(d).padStart(2, "0")} ${time}`;
}
