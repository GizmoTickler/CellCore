import { useThemeStore } from "../stores/theme-store";

type WebkitWindow = Window & { webkitAudioContext?: typeof AudioContext };

let sharedAudioCtx: AudioContext | null = null;

function getAudioContext(): AudioContext | null {
  if (!useThemeStore.getState().hudSfx) return null;
  if (typeof window === "undefined") return null;

  if (!sharedAudioCtx) {
    const Ctor = window.AudioContext ?? (window as WebkitWindow).webkitAudioContext;
    if (!Ctor) return null;
    try {
      sharedAudioCtx = new Ctor();
    } catch {
      return null;
    }
  }

  if (sharedAudioCtx.state === "closed") return null;
  if (sharedAudioCtx.state === "suspended") {
    try {
      void sharedAudioCtx.resume().catch(() => {});
    } catch {
      return null;
    }
    if (sharedAudioCtx.state === "suspended") return null;
  }

  return sharedAudioCtx;
}

function safePlay(fn: (ctx: AudioContext, now: number) => void): void {
  const ctx = getAudioContext();
  if (!ctx) return;
  try {
    fn(ctx, ctx.currentTime);
  } catch {
    // Gracefully no-op on any Web Audio scheduling error
  }
}

/**
 * Ultra-soft 14 ms filtered glass tap (~1400 -> 900 Hz, gain 0.025).
 */
export function playHudTick(): void {
  safePlay((ctx, now) => {
    const osc = ctx.createOscillator();
    const filter = ctx.createBiquadFilter();
    const gain = ctx.createGain();

    osc.type = "sine";
    osc.frequency.setValueAtTime(1400, now);
    osc.frequency.exponentialRampToValueAtTime(900, now + 0.014);

    filter.type = "bandpass";
    filter.frequency.setValueAtTime(1600, now);
    filter.Q.setValueAtTime(1.1, now);

    gain.gain.setValueAtTime(0.0001, now);
    gain.gain.linearRampToValueAtTime(0.025, now + 0.002);
    gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.014);

    osc.connect(filter);
    filter.connect(gain);
    gain.connect(ctx.destination);

    osc.onended = () => {
      osc.disconnect();
      filter.disconnect();
      gain.disconnect();
    };
    osc.start(now);
    osc.stop(now + 0.018);
  });
}

/**
 * Soft airy 45 ms glass slide chime (~520 -> 780 Hz sine, gain 0.028).
 */
export function playHudNav(): void {
  safePlay((ctx, now) => {
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();

    osc.type = "sine";
    osc.frequency.setValueAtTime(520, now);
    osc.frequency.exponentialRampToValueAtTime(780, now + 0.045);

    gain.gain.setValueAtTime(0.0001, now);
    gain.gain.linearRampToValueAtTime(0.028, now + 0.005);
    gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.045);

    osc.connect(gain);
    gain.connect(ctx.destination);

    osc.onended = () => {
      osc.disconnect();
      gain.disconnect();
    };
    osc.start(now);
    osc.stop(now + 0.05);
  });
}

/**
 * Crisp dual-harmonic target-lock shimmer (~660 Hz + 990 Hz, 90 ms, gain 0.032).
 */
export function playHudLock(): void {
  safePlay((ctx, now) => {
    const master = ctx.createGain();
    master.gain.setValueAtTime(0.0001, now);
    master.gain.linearRampToValueAtTime(0.032, now + 0.004);
    master.gain.exponentialRampToValueAtTime(0.0001, now + 0.09);
    master.connect(ctx.destination);

    const oscA = ctx.createOscillator();
    const oscB = ctx.createOscillator();
    const gainB = ctx.createGain();

    oscA.type = "sine";
    oscA.frequency.setValueAtTime(660, now);

    oscB.type = "sine";
    oscB.frequency.setValueAtTime(990, now);
    gainB.gain.setValueAtTime(0.45, now);

    oscA.connect(master);
    oscB.connect(gainB);
    gainB.connect(master);

    oscA.onended = () => {
      oscA.disconnect();
      oscB.disconnect();
      gainB.disconnect();
      master.disconnect();
    };

    oscA.start(now);
    oscB.start(now + 0.008);
    oscA.stop(now + 0.095);
    oscB.stop(now + 0.095);
  });
}

/**
 * Gentle ascending glass triad (~523 -> 659 -> 784 Hz, 140 ms, gain 0.03).
 */
export function playHudSuccess(): void {
  safePlay((ctx, now) => {
    const notes = [523.25, 659.25, 783.99];
    const step = 0.035;
    const end = now + 0.14;

    notes.forEach((freq, idx) => {
      const start = now + idx * step;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();

      osc.type = "sine";
      osc.frequency.setValueAtTime(freq, start);

      gain.gain.setValueAtTime(0.0001, start);
      gain.gain.linearRampToValueAtTime(0.015, start + 0.005);
      gain.gain.exponentialRampToValueAtTime(0.0001, end);

      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.onended = () => {
        osc.disconnect();
        gain.disconnect();
      };
      osc.start(start);
      osc.stop(end + 0.008);
    });
  });
}

/**
 * Calm low pulse (~320 -> 240 Hz, 110 ms, gain 0.035).
 */
export function playHudAlert(): void {
  safePlay((ctx, now) => {
    const osc = ctx.createOscillator();
    const filter = ctx.createBiquadFilter();
    const gain = ctx.createGain();

    osc.type = "sine";
    osc.frequency.setValueAtTime(320, now);
    osc.frequency.exponentialRampToValueAtTime(240, now + 0.11);

    filter.type = "lowpass";
    filter.frequency.setValueAtTime(900, now);

    gain.gain.setValueAtTime(0.0001, now);
    gain.gain.linearRampToValueAtTime(0.035, now + 0.008);
    gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.11);

    osc.connect(filter);
    filter.connect(gain);
    gain.connect(ctx.destination);

    osc.onended = () => {
      osc.disconnect();
      filter.disconnect();
      gain.disconnect();
    };
    osc.start(now);
    osc.stop(now + 0.118);
  });
}

/**
 * Subtle tactile haptic pulse via `navigator.vibrate`, safely guarded for platforms
 * without vibration support (e.g. iOS Safari). Active when `hudSfx` is enabled or on touch devices.
 */
export function triggerHaptic(ms = 8): void {
  try {
    if (typeof navigator === "undefined" || typeof navigator.vibrate !== "function") return;
    const isTouch =
      typeof window !== "undefined" &&
      ((typeof window.matchMedia === "function" && window.matchMedia("(pointer: coarse)").matches) ||
        navigator.maxTouchPoints > 0);
    if (!useThemeStore.getState().hudSfx && !isTouch) return;
    navigator.vibrate(ms);
  } catch {
    // Ignore unsupported or blocked vibration APIs
  }
}
