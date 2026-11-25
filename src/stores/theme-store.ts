import { create } from "zustand";

type Theme = "dark" | "light";
export type Layout = "rail" | "top" | "dock";
export type LayoutPref = "auto" | Layout;
export type Density = "cozy" | "compact";
export type MotionQuality = "full" | "balanced" | "reduced";
export type Skin =
  | "prism"
  | "ember"
  | "midnight"
  | "swiss"
  | "aurora"
  | "phosphor"
  | "blueprint"
  | "brutal"
  | "synthwave"
  | "obsidian"
  | "tokyo"
  | "nord"
  | "catppuccin"
  | "forest"
  | "radar";

export const SKINS: Array<{ id: Skin; label: string; short: string; hint: string; swatch: string; layout: Layout; density: Density; darkOnly?: boolean }> = [
  { id: "prism", label: "Prism Glass", short: "Prism", hint: "Futuristic deep glass, specular bloom & fluid motion", swatch: "linear-gradient(135deg,#070d19 15%,#22d3ee 55%,#34d399 82%,#a78bfa)", darkOnly: true, layout: "rail", density: "cozy" },
  { id: "midnight", label: "Midnight Signal", short: "Midnight", hint: "Instrument-panel navy, cyan→violet", swatch: "linear-gradient(118deg,#22d3ee,#3b82f6 48%,#8b5cf6)", layout: "rail", density: "cozy" },
  { id: "obsidian", label: "Obsidian OLED", short: "Obsidian", hint: "True pitch-black OLED, emerald→cyan", swatch: "linear-gradient(135deg,#000000 45%,#10b981 75%,#06b6d4)", darkOnly: true, layout: "rail", density: "compact" },
  { id: "tokyo", label: "Tokyo Night", short: "Tokyo", hint: "Deep indigo-slate, sky blue & violet", swatch: "linear-gradient(118deg,#1a1b26 15%,#7aa2f7 60%,#bb9af7)", layout: "rail", density: "cozy" },
  { id: "catppuccin", label: "Catppuccin", short: "Mocha", hint: "Velvety Mocha & Latte pastels", swatch: "linear-gradient(118deg,#cba6f7,#74c7ec 52%,#fab387)", layout: "rail", density: "cozy" },
  { id: "nord", label: "Nordic Frost", short: "Nord", hint: "Arctic polar slate & glacier cyan", swatch: "linear-gradient(118deg,#2e3440 20%,#88c0d0 65%,#a3be8c)", layout: "rail", density: "cozy" },
  { id: "forest", label: "Pine & Copper", short: "Forest", hint: "Botanical deep pine & warm copper", swatch: "linear-gradient(118deg,#0d261c 15%,#22c55e 55%,#e07a3f)", layout: "rail", density: "cozy" },
  { id: "radar", label: "Tactical Amber", short: "Radar", hint: "Avionics HUD, carbon & amber gold", swatch: "repeating-linear-gradient(0deg,#ffb000 0 2px,#140f05 2px 5px)", darkOnly: true, layout: "dock", density: "compact" },
  { id: "swiss", label: "Swiss Mono", short: "Swiss", hint: "Black and white, one signal accent", swatch: "linear-gradient(135deg,#0a0a0a 50%,#ff3b1f 50%)", layout: "top", density: "compact" },
  { id: "aurora", label: "Aurora Glass", short: "Aurora", hint: "Frosted glass on teal→indigo→pink", swatch: "linear-gradient(118deg,#14b8a6,#6366f1 52%,#ec4899)", layout: "rail", density: "cozy" },
  { id: "ember", label: "Ember", short: "Ember", hint: "Golden-hour warm", swatch: "linear-gradient(118deg,#ffb627,#ff6a2c 46%,#e0336f)", layout: "rail", density: "cozy" },
  { id: "phosphor", label: "Phosphor", short: "Phosphor", hint: "Green-screen CRT terminal", swatch: "repeating-linear-gradient(0deg,#39ff6a 0 2px,#062a0e 2px 4px)", darkOnly: true, layout: "dock", density: "compact" },
  { id: "blueprint", label: "Blueprint", short: "Blueprint", hint: "Drafting sheet, white linework", swatch: "repeating-linear-gradient(90deg,rgba(255,255,255,.35) 0 1px,transparent 1px 6px),repeating-linear-gradient(0deg,rgba(255,255,255,.35) 0 1px,transparent 1px 6px),#0d3874", darkOnly: true, layout: "top", density: "compact" },
  { id: "brutal", label: "Neo-Brutal", short: "Brutal", hint: "Thick outlines, hard shadows, candy colors", swatch: "linear-gradient(135deg,#ffd400 33%,#ff4fa3 33% 66%,#3d5afe 66%)", layout: "top", density: "cozy" },
  { id: "synthwave", label: "Synthwave", short: "Synth", hint: "Neon grid horizon", swatch: "linear-gradient(180deg,#7b2bff,#ff2bd6 60%,#ffd166)", darkOnly: true, layout: "dock", density: "cozy" },
];

export const LAYOUTS: Array<{ id: LayoutPref; label: string; hint: string }> = [
  { id: "auto", label: "Theme default", hint: "Use the layout the theme was designed with" },
  { id: "rail", label: "Sidebar", hint: "Left rail with live link capsule" },
  { id: "top", label: "Top bar", hint: "Horizontal navigation, full-width content" },
  { id: "dock", label: "Dock", hint: "Slim icon dock and a status line" },
];

export function skinMeta(skin: Skin) {
  return SKINS.find((s) => s.id === skin) ?? SKINS[0];
}

export function resolveLayout(skin: Skin, pref: LayoutPref): Layout {
  return pref === "auto" ? skinMeta(skin).layout : pref;
}

interface ThemeState {
  theme: Theme;
  skin: Skin;
  layoutPref: LayoutPref;
  motionQuality: MotionQuality;
  hudSfx: boolean;
  setLayoutPref: (pref: LayoutPref) => void;
  setTheme: (theme: Theme) => void;
  toggleTheme: () => void;
  setSkin: (skin: Skin) => void;
  setMotionQuality: (q: MotionQuality) => void;
  setHudSfx: (on: boolean) => void;
}

const THEME_STORAGE_KEY = "qm-theme-v32";
const SKIN_STORAGE_KEY = "qm-skin";
const LAYOUT_STORAGE_KEY = "qm-layout";
const MOTION_STORAGE_KEY = "qm-motion";
const HUD_SFX_STORAGE_KEY = "qm-hud-sfx";
const MOTION_QUALITIES: ReadonlyArray<MotionQuality> = ["full", "balanced", "reduced"];

function store(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {
    // ignore storage quota / private mode
  }
}

function syncThemeColorMeta() {
  if (typeof document === "undefined" || typeof window === "undefined") return;
  const apply = () => {
    const paper = window.getComputedStyle(document.documentElement).getPropertyValue("--qm-paper").trim();
    if (!paper) return;
    let meta = document.querySelector<HTMLMetaElement>('meta[name="theme-color"]');
    if (!meta) {
      meta = document.createElement("meta");
      meta.name = "theme-color";
      document.head.appendChild(meta);
    }
    meta.content = paper;
  };
  apply();
  window.requestAnimationFrame(apply);
}

function syncDarkClass(theme: Theme, skin: Skin) {
  if (typeof document === "undefined") return;
  const isDark = theme === "dark" || Boolean(skinMeta(skin).darkOnly);
  document.documentElement.classList.toggle("dark", isDark);
}

function applyDomTheme(theme: Theme, skin: Skin) {
  if (typeof document === "undefined") return;
  syncDarkClass(theme, skin);
  store(THEME_STORAGE_KEY, theme);
  syncThemeColorMeta();
}

function applyDomSkin(skin: Skin, pref: LayoutPref, theme: Theme) {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  root.dataset.skin = skin;
  root.dataset.layout = resolveLayout(skin, pref);
  root.dataset.density = skinMeta(skin).density;
  syncDarkClass(theme, skin);
  store(SKIN_STORAGE_KEY, skin);
  store(LAYOUT_STORAGE_KEY, pref);
  syncThemeColorMeta();
}

function applyDomMotion(q: MotionQuality) {
  if (typeof document === "undefined") return;
  document.documentElement.dataset.motion = q;
  store(MOTION_STORAGE_KEY, q);
}

const initialSkin: Skin = (() => {
  try {
    const v = localStorage.getItem(SKIN_STORAGE_KEY);
    return SKINS.some((s) => s.id === v) ? (v as Skin) : "prism";
  } catch {
    return "prism";
  }
})();

const initialTheme: Theme = (() => {
  try {
    const v = localStorage.getItem(THEME_STORAGE_KEY);
    if (v === "dark" || v === "light") return v;
    return skinMeta(initialSkin).darkOnly ? "dark" : "light";
  } catch {
    return skinMeta(initialSkin).darkOnly ? "dark" : "light";
  }
})();

const initialLayoutPref: LayoutPref = (() => {
  try {
    const v = localStorage.getItem(LAYOUT_STORAGE_KEY);
    return LAYOUTS.some((l) => l.id === v) ? (v as LayoutPref) : "auto";
  } catch {
    return "auto";
  }
})();

const initialMotionQuality: MotionQuality = (() => {
  try {
    const v = localStorage.getItem(MOTION_STORAGE_KEY);
    return MOTION_QUALITIES.includes(v as MotionQuality) ? (v as MotionQuality) : "full";
  } catch {
    return "full";
  }
})();

const initialHudSfx: boolean = (() => {
  try {
    const v = localStorage.getItem(HUD_SFX_STORAGE_KEY);
    return v === "true" || v === "1";
  } catch {
    return false;
  }
})();

applyDomTheme(initialTheme, initialSkin);
applyDomSkin(initialSkin, initialLayoutPref, initialTheme);
applyDomMotion(initialMotionQuality);
if (typeof window !== "undefined") {
  window.addEventListener("load", syncThemeColorMeta, { once: true });
}

export const useThemeStore = create<ThemeState>((set, get) => ({
  theme: initialTheme,
  skin: initialSkin,
  layoutPref: initialLayoutPref,
  motionQuality: initialMotionQuality,
  hudSfx: initialHudSfx,
  setLayoutPref: (layoutPref) => {
    applyDomSkin(get().skin, layoutPref, get().theme);
    set({ layoutPref });
  },
  setTheme: (theme) => {
    applyDomTheme(theme, get().skin);
    set({ theme });
  },
  toggleTheme: () => {
    const next: Theme = get().theme === "dark" ? "light" : "dark";
    applyDomTheme(next, get().skin);
    set({ theme: next });
  },
  setSkin: (skin) => {
    applyDomSkin(skin, get().layoutPref, get().theme);
    set({ skin });
  },
  setMotionQuality: (motionQuality) => {
    applyDomMotion(motionQuality);
    set({ motionQuality });
  },
  setHudSfx: (hudSfx) => {
    store(HUD_SFX_STORAGE_KEY, hudSfx ? "true" : "false");
    set({ hudSfx });
  },
}));
