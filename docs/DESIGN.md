# CellCore 4.1 design system

One UX, eight themes. Every component is written against **semantic tokens**. A theme (`data-skin`
on `<html>`) supplies the token values, the type faces, the card radius and the background, plus a
default **layout** (`data-layout`: `rail` sidebar, `top` bar, `dock`) and **density**
(`data-density`: `cozy` | `compact`). Light/dark is a separate `.dark` class on `<html>`; some themes
have a single look (`darkOnly`).

| Theme | Layout | Density | Character |
|---|---|---|---|
| Midnight Signal (default) | rail | cozy | Instrument-panel navy, cyan→violet, Space Grotesk numerals |
| Swiss Mono | top | compact | Off-white/black grid, one signal-red accent, Inter Tight |
| Aurora Glass | rail | cozy | Frosted glass over a teal/indigo/pink aurora |
| Ember | rail | cozy | Golden-hour cream, ember→berry, Fraunces numerals |
| Phosphor | dock | compact | Green-screen CRT, all-mono, scanlines (dark only) |
| Blueprint | top | compact | Drafting sheet, white linework, grid paper (dark only) |
| Neo-Brutal | top | cozy | Thick outlines, hard offset shadows, candy colors |
| Synthwave | dock | cozy | Neon grid horizon, glowing numerals (dark only) |

Themes live in `src/index.css` (one block per skin) and `src/stores/theme-store.ts` (`SKINS`).
Users switch from Appearance (rail/top bar/dock button) or ⌘K; the layout can be overridden
independently. Choices persist per browser (`qm-skin`, `qm-layout`, `qm-theme-v32`).

The signature accent is `qm-sun`, the theme's gradient. Use it sparingly, for the one thing on a
screen that matters most.

## Principles

1. **Answer first.** Every view opens with the verdict (is it healthy, what is it doing), then the
   detail. Don't show the same fact twice on one screen.
2. **One accent per region.** A card gets at most one gradient or solid-ember element. Everything
   else is ink and muted text on paper or surface.
3. **Status is semantic, not decorative.** jade = good, saffron = attention, crimson = bad,
   ember = brand/action, berry = upload/secondary series. Never use status colors for decoration.
4. **Numbers are the hero.** Key values use the display face (`qm-display`, Fraunces). Labels are
   small, muted and sentence-case. Units sit smaller beside the number.
5. **Every view is a URL.** Sub-views live in the hash (`#/cellular/bands`) through `useSubRoute`,
   so the rail, the ⌘K palette and the back button all work.
6. **Plain language.** Prefer "Lock to this cell" over "Apply PCI/ARFCN constraint". Keep the
   3GPP term as secondary text when it helps experts.

## Tokens (Tailwind utilities, flip automatically in dark mode, never hand-pair `dark:` variants)

| Role | Utilities |
|---|---|
| Page / card / raised / sunken fill | `bg-paper` `bg-surface` `bg-raised` `bg-sunk` |
| Borders | `border-line` `border-line-strong` |
| Text | `text-ink` (primary) `text-ink-2` (secondary) `text-muted` (labels/meta) |
| Brand / action | `bg-ember` (fill; put `text-on-ember` on it) `text-ember-ink` `bg-ember-soft` |
| Good | `bg-jade` `text-jade-ink` `bg-jade-soft` |
| Attention | `bg-saffron` `text-saffron-ink` `bg-saffron-soft` |
| Bad | `bg-crimson` `text-crimson-ink` `bg-crimson-soft` |
| Secondary series / upload | `bg-berry` `text-berry-ink` `bg-berry-soft` |
| Signature | `qm-sun` (bg gradient), `qm-sun-text` (gradient text), `qm-grain` (paper noise overlay) |
| Type | `qm-display` (Fraunces numerals/headings), `font-mono` (JetBrains Mono), `qm-eyebrow` (caps label), `qm-tabular` |
| Surfaces | `qm-card` (radius 1.4rem, warm shadow), `qm-subcard` (sunk tile) |

Token names are roles, not hues: `ember` is "brand" in every theme even when it is cyan or pink.
Never use `text-white` on `bg-ember`/`qm-sun`; use `text-on-ember` (dark text in Phosphor, Blueprint
and Neo-Brutal). SVG colors go in `style={{ stroke: "var(--qm-…)" }}`, never presentation
attributes, because attributes do not resolve `var()`.

Opacity modifiers work on every token (`bg-ember/15`, `border-jade/40`).
`stone-*` is remapped to a warm scale, but new code uses the semantic tokens above.
**No raw hex in components.** Charts that need literal colors read CSS vars (`var(--qm-ember)`).

## Components (`src/components/ui.tsx`)

- `PageHeader section sub onSubChange title? hint? actions?`: every page starts with it. It shows the
  section eyebrow, the active sub-view title and hint, and the sub-view chips wherever the layout
  has no sub-nav of its own (phones, dock). Pages must **not** render their own top-level tab bar.
- `Card`, `CardHeader title subtitle icon action`: CardHeader titles are display face.
- `Badge variant=neutral|success|warning|danger|plum|sage|info dot?`: pill.
- `Button variant=primary|tier1 (sun gradient, hero CTA only)|tier2 (ink)|tier3 (soft ember)|secondary|ghost|danger|success size=sm|md|lg`.
- `StatTile`, `Meter pct tone`, `SignalDial`, `SignalGauge`, `signalQuality(rsrp, sinr)`, `LiveDot`, `Kbd`.
- `SegmentedTabs`: only for *local* toggles inside a card (chart range, unit), not page navigation.
- `Input`, `Select`, `Switch`, `CopyButton`, `Skeleton`, `Modal` (Esc closes), `ToastViewport`.
- Feedback goes through the global toast store: `useToastStore((s) => s.push)(title, "success"|"error"|"info", description?)`.
  Don't add per-page inline toast banners.

## Navigation map (`src/lib/nav.ts`)

`/` Now · `/cellular` Radio (profiles, bands, lock, align, scan) · `/network` Network (lan, policy,
usage, warp, tailscale) · `/diagnostics` Diagnostics (speedtest, health, latency, at, sms, events) · `/system` System
(hardware, internals, logs, alerts, ota, backup, security) · `/admin` Admin (system, access, services, cron,
processes, software, firewall, mwan3, status, dhcp, tools, backup): the OpenWrt functions LuCI used to cover.
On phones Admin shares the System tab (`mobileTab`), so the bottom bar stays at five; the phone header links
between the two. In the top-bar layout section labels show from `xl` up (icons with tooltips below).

## Layout

- The content column is max 1240px. Use a 12-col grid at `lg`. Give the primary task the wider
  column, with supporting/context content on the right.
- Card padding is `p-[var(--qm-pad)]` (what `Card` uses) so it follows density.
- Spacing rhythm: page sections `space-y-6`, card gap `gap-5`, inside cards `space-y-4`.
- Body text is 13–14px. Use 11px only for meta. No text below 10.5px.
- Tables: `bg-sunk` header, `divide-line` rows, numbers right-aligned with `qm-tabular`.
- Destructive actions confirm in a `Modal` and say plainly what happens (downtime, data loss).
- It must work at 375px width: stack the columns, keep tables horizontally scrollable, and keep tap targets ≥ 36px.
