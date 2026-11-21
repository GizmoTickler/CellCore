//! Tower Finder & Sightline Bearing API (`/api/v1/cellular/tower-finder*`).
//!
//! Decodes serving-cell identifiers (5G NR gNB ID + sector, LTE eNB ID + sector),
//! persists Home coordinates, pinned tower coordinates, and an optional OpenCelliD
//! API key (`/etc/cellcore/tower_finder.json`, mode 0600), computes great-circle
//! distance & true azimuth bearing against Timing Advance, and performs safe
//! server-side tower geolocation lookups via OpenCelliD (when keyed) and beaconDB
//! (with `ipf: false` so IP fallback never produces fake tower pins).

use std::{fs, path::Path, sync::OnceLock};

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{
    admin::exec::{ExecOpts, run},
    auth::now_secs,
    http::HttpCtx,
    parsers::ServingCellInfo,
    state::save_json_atomic,
};

pub const TOWER_FINDER_PATH: &str = "/etc/cellcore/tower_finder.json";
const MAX_PINNED_TOWERS: usize = 64;
const LOOKUP_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HomeLocation {
    pub lat: f64,
    pub lon: f64,
    #[serde(default)]
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PinnedTower {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub mcc: String,
    #[serde(default)]
    pub mnc: String,
    #[serde(default)]
    pub rat: String,
    #[serde(default)]
    pub pci: Option<i32>,
    #[serde(default)]
    pub gnb_id: Option<u64>,
    #[serde(default)]
    pub cell_id: String,
    #[serde(default)]
    pub band: String,
    #[serde(default)]
    pub arfcn: Option<i64>,
    pub lat: f64,
    pub lon: f64,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub saved_at: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TowerFinderConfig {
    #[serde(default)]
    pub home: Option<HomeLocation>,
    #[serde(default)]
    pub opencellid_api_key: String,
    #[serde(default)]
    pub pinned_towers: Vec<PinnedTower>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecodedServingCell {
    pub rat: String,
    pub mcc: String,
    pub mnc: String,
    pub band: String,
    pub pci: Option<i32>,
    pub arfcn: Option<i64>,
    pub tac_hex: String,
    pub tac_dec: Option<u64>,
    pub cell_id_hex: String,
    pub nci_dec: Option<u64>,
    pub gnb_id: Option<u64>,
    pub gnb_id_22: Option<u64>,
    pub sector_id: Option<u64>,
    pub enb_id: Option<u64>,
    pub ta_meters: Option<i64>,
    pub cellmapper_url: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveTowerTarget {
    pub tower: PinnedTower,
    pub bearing_deg: f64,
    pub cardinal: &'static str,
    pub distance_meters: f64,
    pub ta_meters: Option<i64>,
    pub ta_delta_meters: Option<f64>,
}

static STORE: OnceLock<RwLock<Option<TowerFinderConfig>>> = OnceLock::new();

fn store_lock() -> &'static RwLock<Option<TowerFinderConfig>> {
    STORE.get_or_init(|| RwLock::new(None))
}

fn load_from_disk() -> TowerFinderConfig {
    let path = crate::paths::p(TOWER_FINDER_PATH);
    fs::read_to_string(Path::new(&path))
        .ok()
        .and_then(|s| serde_json::from_str::<TowerFinderConfig>(&s).ok())
        .unwrap_or_default()
}

async fn get_config() -> TowerFinderConfig {
    if let Some(cfg) = store_lock().read().await.as_ref() {
        return cfg.clone();
    }
    let loaded = tokio::task::spawn_blocking(load_from_disk)
        .await
        .unwrap_or_default();
    let mut g = store_lock().write().await;
    if g.is_none() {
        *g = Some(loaded.clone());
    }
    g.clone().unwrap_or(loaded)
}

async fn save_config(cfg: &TowerFinderConfig) -> Result<(), String> {
    let path = crate::paths::p(TOWER_FINDER_PATH);
    let clone = cfg.clone();
    tokio::task::spawn_blocking(move || save_json_atomic(&path, &clone, 0o600))
        .await
        .map_err(|e| format!("save join error: {e}"))??;
    *store_lock().write().await = Some(cfg.clone());
    Ok(())
}

fn valid_coords(lat: f64, lon: f64) -> bool {
    lat.is_finite() && lon.is_finite() && (-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon)
}

pub fn haversine_meters(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const EARTH_R_M: f64 = 6_371_000.0;
    let p1 = lat1.to_radians();
    let p2 = lat2.to_radians();
    let dp = (lat2 - lat1).to_radians();
    let dl = (lon2 - lon1).to_radians();
    let a = (dp / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dl / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).max(0.0).sqrt());
    (EARTH_R_M * c).round()
}

pub fn initial_bearing_deg(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let p1 = lat1.to_radians();
    let p2 = lat2.to_radians();
    let dl = (lon2 - lon1).to_radians();
    let y = dl.sin() * p2.cos();
    let x = p1.cos() * p2.sin() - p1.sin() * p2.cos() * dl.cos();
    let brng = (y.atan2(x).to_degrees() + 360.0) % 360.0;
    (brng * 10.0).round() / 10.0
}

pub fn compass_cardinal(deg: f64) -> &'static str {
    const DIRS: [&str; 16] = [
        "N", "NNE", "NE", "ENE", "E", "ESE", "SE", "SSE", "S", "SSW", "SW", "WSW", "W", "WNW", "NW", "NNW",
    ];
    let idx = (((deg % 360.0) + 360.0) % 360.0 / 22.5).round() as usize % 16;
    DIRS[idx]
}

fn parse_hex_u64(s: &str) -> Option<u64> {
    let trimmed = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    if trimmed.is_empty() {
        return None;
    }
    u64::from_str_radix(trimmed, 16).ok()
}

pub fn decode_serving_cell(
    serving: &ServingCellInfo,
    ta_meters: Option<i64>,
    home: Option<&HomeLocation>,
) -> DecodedServingCell {
    let rat_upper = serving.rat.to_ascii_uppercase();
    let is_nr = rat_upper.contains("NR5G") || rat_upper == "NR";
    let is_lte = rat_upper.contains("LTE");
    let tac_dec = parse_hex_u64(&serving.tac);
    let nci_dec = parse_hex_u64(&serving.cell_id);

    let (gnb_id, gnb_id_22, sector_id, enb_id) = if is_nr {
        if let Some(nci) = nci_dec {
            // 24-bit gNB ID (T-Mobile US / 3GPP default) + 22-bit alternative.
            (Some(nci >> 12), Some(nci >> 14), Some(nci & 0xFFF), None)
        } else {
            (None, None, None, None)
        }
    } else if is_lte {
        if let Some(ci) = nci_dec {
            (None, None, Some(ci & 0xFF), Some(ci >> 8))
        } else {
            (None, None, None, None)
        }
    } else {
        (None, None, None, None)
    };

    let cm_type = if is_nr { "NR" } else { "LTE" };
    let mut cellmapper_url = format!(
        "https://www.cellmapper.net/map?MCC={}&MNC={}&type={cm_type}",
        serving.mcc.trim(),
        serving.mnc.trim()
    );
    if let Some(h) = home {
        cellmapper_url.push_str(&format!("&latitude={:.5}&longitude={:.5}&zoom=13", h.lat, h.lon));
    }

    DecodedServingCell {
        rat: serving.rat.clone(),
        mcc: serving.mcc.clone(),
        mnc: serving.mnc.clone(),
        band: serving.band.clone(),
        pci: serving.pci,
        arfcn: serving.arfcn,
        tac_hex: serving.tac.clone(),
        tac_dec,
        cell_id_hex: serving.cell_id.clone(),
        nci_dec,
        gnb_id,
        gnb_id_22,
        sector_id,
        enb_id,
        ta_meters,
        cellmapper_url,
    }
}

fn match_pinned_tower<'a>(
    towers: &'a [PinnedTower],
    decoded: Option<&DecodedServingCell>,
) -> Option<&'a PinnedTower> {
    let d = decoded?;
    // 1. Exact cellId or gNB ID match
    if !d.cell_id_hex.is_empty()
        && let Some(t) = towers
            .iter()
            .find(|t| !t.cell_id.is_empty() && t.cell_id.eq_ignore_ascii_case(&d.cell_id_hex))
    {
        return Some(t);
    }
    if let Some(g) = d.gnb_id
        && let Some(t) = towers.iter().find(|t| t.gnb_id == Some(g))
    {
        return Some(t);
    }
    // 2. PCI + MCC/MNC match
    if let Some(pci) = d.pci
        && let Some(t) = towers
            .iter()
            .find(|t| t.pci == Some(pci) && (t.mcc.is_empty() || t.mcc == d.mcc))
    {
        return Some(t);
    }
    // 3. Fall back to most recently saved tower if only 1 exists
    if towers.len() == 1 {
        return towers.first();
    }
    None
}

fn build_active_target(
    home: Option<&HomeLocation>,
    tower: Option<&PinnedTower>,
    ta_meters: Option<i64>,
) -> Option<ActiveTowerTarget> {
    let h = home?;
    let t = tower?;
    let dist = haversine_meters(h.lat, h.lon, t.lat, t.lon);
    let brng = initial_bearing_deg(h.lat, h.lon, t.lat, t.lon);
    let ta_delta = ta_meters.filter(|&v| v > 0).map(|ta| (dist - ta as f64).round());
    Some(ActiveTowerTarget {
        tower: t.clone(),
        bearing_deg: brng,
        cardinal: compass_cardinal(brng),
        distance_meters: dist,
        ta_meters,
        ta_delta_meters: ta_delta,
    })
}

pub async fn get_tower_finder(State(ctx): State<HttpCtx>) -> Response {
    let cfg = get_config().await;
    let (serving, ta_meters) = {
        let m = ctx.app.modem.read().await;
        (m.serving.clone(), m.time_advance.active_meters)
    };
    let decoded = serving
        .as_ref()
        .map(|s| decode_serving_cell(s, ta_meters, cfg.home.as_ref()));
    let matched = match_pinned_tower(&cfg.pinned_towers, decoded.as_ref());
    let active_target = build_active_target(cfg.home.as_ref(), matched, ta_meters);
    Json(serde_json::json!({
        "status": "ok",
        "home": cfg.home,
        "hasOpencellidKey": !cfg.opencellid_api_key.trim().is_empty(),
        "pinnedTowers": cfg.pinned_towers,
        "serving": decoded,
        "activeTarget": active_target,
    }))
    .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutTowerFinderReq {
    #[serde(default)]
    pub home: Option<HomeLocation>,
    #[serde(default)]
    pub clear_home: bool,
    #[serde(default)]
    pub opencellid_api_key: Option<String>,
    #[serde(default)]
    pub clear_opencellid_key: bool,
    #[serde(default)]
    pub upsert_tower: Option<PinnedTower>,
    #[serde(default)]
    pub delete_tower_id: Option<String>,
}

pub async fn put_tower_finder(
    State(ctx): State<HttpCtx>,
    Json(req): Json<PutTowerFinderReq>,
) -> Response {
    let mut cfg = get_config().await;

    if req.clear_home {
        cfg.home = None;
    } else if let Some(mut h) = req.home {
        if !valid_coords(h.lat, h.lon) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "status": "error", "error": "Invalid home latitude/longitude" })),
            )
                .into_response();
        }
        h.label = h.label.trim().chars().take(64).collect();
        cfg.home = Some(h);
    }

    if req.clear_opencellid_key {
        cfg.opencellid_api_key.clear();
    } else if let Some(k) = req.opencellid_api_key {
        let trimmed = k.trim();
        if trimmed.len() > 128 || trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "status": "error", "error": "Invalid OpenCelliD API key format" })),
            )
                .into_response();
        }
        if !trimmed.is_empty() {
            cfg.opencellid_api_key = trimmed.to_string();
        }
    }

    if let Some(del_id) = req.delete_tower_id {
        cfg.pinned_towers.retain(|t| t.id != del_id);
    }

    if let Some(mut t) = req.upsert_tower {
        if !valid_coords(t.lat, t.lon) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "status": "error", "error": "Invalid tower latitude/longitude" })),
            )
                .into_response();
        }
        t.label = t.label.trim().chars().take(64).collect();
        if t.label.is_empty() {
            t.label = match (t.band.as_str(), t.pci) {
                (b, Some(p)) if !b.is_empty() => format!("{b} PCI {p}"),
                (_, Some(p)) => format!("Tower PCI {p}"),
                _ => "Pinned Tower".into(),
            };
        }
        if t.id.trim().is_empty() {
            t.id = format!("twr-{}", now_secs());
        } else {
            t.id = t.id.trim().chars().take(48).collect();
        }
        if t.source.trim().is_empty() {
            t.source = "manual".into();
        }
        t.saved_at = now_secs();
        if let Some(slot) = cfg.pinned_towers.iter_mut().find(|x| x.id == t.id) {
            *slot = t;
        } else {
            if cfg.pinned_towers.len() >= MAX_PINNED_TOWERS {
                cfg.pinned_towers.remove(0);
            }
            cfg.pinned_towers.push(t);
        }
    }

    if let Err(e) = save_config(&cfg).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "status": "error", "error": e })),
        )
            .into_response();
    }
    get_tower_finder(State(ctx)).await
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LookupTowerReq {
    #[serde(default)]
    pub mcc: Option<String>,
    #[serde(default)]
    pub mnc: Option<String>,
    #[serde(default)]
    pub tac: Option<u64>,
    #[serde(default)]
    pub cell_id: Option<u64>,
    #[serde(default)]
    pub pci: Option<i32>,
    #[serde(default)]
    pub rat: Option<String>,
}

fn curl_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\r' | '\n' => {}
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

async fn lookup_opencellid(
    api_key: &str,
    mcc: u32,
    mnc: u32,
    tac: u64,
    cell_id: u64,
    radio: &str,
) -> Result<Option<(f64, f64, Option<f64>)>, String> {
    let url = format!(
        "https://opencellid.org/cell/get?key={api_key}&mcc={mcc}&mnc={mnc}&lac={tac}&cellid={cell_id}&radio={radio}&format=json"
    );
    let cfg = format!(
        "url = {}\nsilent\nshow-error\nmax-time = {LOOKUP_TIMEOUT_SECS}\nproto = \"=https\"\n",
        curl_escape(&url)
    );
    let out = run("curl", &["-q", "-K", "-"], ExecOpts::new(LOOKUP_TIMEOUT_SECS + 2, 64 * 1024).stdin(cfg.into_bytes()))
        .await?;
    if !out.ok() {
        return Err(out.err_summary("opencellid"));
    }
    let v: serde_json::Value = serde_json::from_str(&out.stdout_str()).map_err(|e| format!("bad json: {e}"))?;
    if v.get("error").is_some() {
        return Ok(None);
    }
    let lat = v.get("lat").and_then(|x| x.as_f64());
    let lon = v.get("lon").and_then(|x| x.as_f64());
    let range = v.get("range").and_then(|x| x.as_f64());
    match (lat, lon) {
        (Some(la), Some(lo)) if valid_coords(la, lo) => Ok(Some((la, lo, range))),
        _ => Ok(None),
    }
}

async fn lookup_beacondb(
    mcc: u32,
    mnc: u32,
    tac: u64,
    cell_id: u64,
    pci: Option<i32>,
    radio: &str,
) -> Result<Option<(f64, f64, Option<f64>)>, String> {
    let mut cell = serde_json::json!({
        "radioType": radio,
        "mobileCountryCode": mcc,
        "mobileNetworkCode": mnc,
        "locationAreaCode": tac,
        "cellId": cell_id,
    });
    if let Some(p) = pci
        && let Some(obj) = cell.as_object_mut()
    {
        obj.insert("psc".into(), serde_json::json!(p));
    }
    let body = serde_json::json!({
        "radioType": radio,
        "cellTowers": [cell],
        "fallbacks": { "ipf": false },
    });
    let cfg = format!(
        "url = \"https://api.beacondb.net/v1/geolocate\"\nsilent\nshow-error\nmax-time = {LOOKUP_TIMEOUT_SECS}\nproto = \"=https\"\nheader = \"Content-Type: application/json\"\nheader = \"User-Agent: CellCore/1.0.0\"\ndata-raw = {}\n",
        curl_escape(&body.to_string())
    );
    let out = run("curl", &["-q", "-K", "-"], ExecOpts::new(LOOKUP_TIMEOUT_SECS + 2, 64 * 1024).stdin(cfg.into_bytes()))
        .await?;
    if !out.ok() {
        return Err(out.err_summary("beacondb"));
    }
    let v: serde_json::Value = serde_json::from_str(&out.stdout_str()).map_err(|e| format!("bad json: {e}"))?;
    // Strictly reject IP-geolocated fallbacks even if server ignores ipf:false.
    if v.get("fallback").is_some() || v.get("error").is_some() {
        return Ok(None);
    }
    let loc = v.get("location");
    let lat = loc.and_then(|l| l.get("lat")).and_then(|x| x.as_f64());
    let lon = loc.and_then(|l| l.get("lng")).and_then(|x| x.as_f64());
    let acc = v.get("accuracy").and_then(|x| x.as_f64());
    match (lat, lon) {
        (Some(la), Some(lo)) if valid_coords(la, lo) => Ok(Some((la, lo, acc))),
        _ => Ok(None),
    }
}

pub async fn post_tower_lookup(
    State(ctx): State<HttpCtx>,
    body: Option<Json<LookupTowerReq>>,
) -> Response {
    let req = body.map(|Json(r)| r).unwrap_or_default();
    let cfg = get_config().await;
    let (serving, ta_meters) = {
        let m = ctx.app.modem.read().await;
        (m.serving.clone(), m.time_advance.active_meters)
    };
    let decoded = serving
        .as_ref()
        .map(|s| decode_serving_cell(s, ta_meters, cfg.home.as_ref()));

    let mcc_s = req
        .mcc
        .or_else(|| decoded.as_ref().map(|d| d.mcc.clone()))
        .unwrap_or_default();
    let mnc_s = req
        .mnc
        .or_else(|| decoded.as_ref().map(|d| d.mnc.clone()))
        .unwrap_or_default();
    let tac = req.tac.or_else(|| decoded.as_ref().and_then(|d| d.tac_dec));
    let cell_id = req.cell_id.or_else(|| decoded.as_ref().and_then(|d| d.nci_dec));
    let pci = req.pci.or_else(|| decoded.as_ref().and_then(|d| d.pci));
    let rat = req
        .rat
        .or_else(|| decoded.as_ref().map(|d| d.rat.clone()))
        .unwrap_or_default();

    let (Ok(mcc), Ok(mnc), Some(tac), Some(cell_id)) = (
        mcc_s.trim().parse::<u32>(),
        mnc_s.trim().parse::<u32>(),
        tac,
        cell_id,
    ) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "status": "error",
                "error": "Serving cell MCC/MNC/TAC/CellID not available for lookup"
            })),
        )
            .into_response();
    };

    let is_nr = rat.to_ascii_uppercase().contains("NR");
    let mut providers_tried: Vec<&str> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    if !cfg.opencellid_api_key.trim().is_empty() {
        providers_tried.push("opencellid");
        let radio = if is_nr { "NR" } else { "LTE" };
        match lookup_opencellid(cfg.opencellid_api_key.trim(), mcc, mnc, tac, cell_id, radio).await {
            Ok(Some((lat, lon, acc))) => {
                return Json(serde_json::json!({
                    "status": "ok",
                    "found": true,
                    "source": "opencellid",
                    "lat": lat,
                    "lon": lon,
                    "accuracyMeters": acc,
                    "providersTried": providers_tried,
                }))
                .into_response();
            }
            Ok(None) => {}
            Err(e) => errors.push(format!("opencellid: {e}")),
        }
    }

    providers_tried.push("beacondb");
    let b_radio = if is_nr { "nr" } else { "lte" };
    match lookup_beacondb(mcc, mnc, tac, cell_id, pci, b_radio).await {
        Ok(Some((lat, lon, acc))) => {
            return Json(serde_json::json!({
                "status": "ok",
                "found": true,
                "source": "beacondb",
                "lat": lat,
                "lon": lon,
                "accuracyMeters": acc,
                "providersTried": providers_tried,
            }))
            .into_response();
        }
        Ok(None) => {}
        Err(e) => errors.push(format!("beacondb: {e}")),
    }

    let msg = if cfg.opencellid_api_key.trim().is_empty() {
        "Cell not found in beaconDB. Add a free OpenCelliD API key or open CellMapper to pin this tower's coordinates."
    } else {
        "Cell not found in OpenCelliD or beaconDB. Open CellMapper to find and pin this gNB/PCI directly."
    };
    Json(serde_json::json!({
        "status": "ok",
        "found": false,
        "providersTried": providers_tried,
        "errors": errors,
        "message": msg,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_tmobile_nr5g_gnb_and_sector_accurately() {
        let s = ServingCellInfo {
            rat: "NR5G-SA".into(),
            mcc: "310".into(),
            mnc: "260".into(),
            band: "n41".into(),
            pci: Some(589),
            arfcn: Some(521310),
            tac: "B0FB00".into(),
            cell_id: "10250D138".into(),
            ..Default::default()
        };
        let home = HomeLocation { lat: 39.10, lon: -84.51, label: "Home".into() };
        let d = decode_serving_cell(&s, Some(3630), Some(&home));
        assert_eq!(d.nci_dec, Some(4_333_818_168));
        assert_eq!(d.tac_dec, Some(11_598_592));
        assert_eq!(d.gnb_id, Some(1_058_061));
        assert_eq!(d.gnb_id_22, Some(264_515));
        assert_eq!(d.sector_id, Some(312));
        assert!(d.cellmapper_url.contains("MCC=310&MNC=260&type=NR"));
        assert!(d.cellmapper_url.contains("latitude=39.10000"));
    }

    #[test]
    fn bearing_and_distance_match_known_vectors() {
        // Due north ~111.2 km per degree of latitude
        let d_n = haversine_meters(39.0, -84.0, 40.0, -84.0);
        assert!((d_n - 111_195.0).abs() < 200.0, "d_n={d_n}");
        assert!((initial_bearing_deg(39.0, -84.0, 40.0, -84.0) - 0.0).abs() < 0.2);
        assert_eq!(compass_cardinal(0.0), "N");
        assert_eq!(compass_cardinal(90.0), "E");
        assert_eq!(compass_cardinal(135.0), "SE");
        assert_eq!(compass_cardinal(270.0), "W");
        assert_eq!(compass_cardinal(359.0), "N");
    }
}
