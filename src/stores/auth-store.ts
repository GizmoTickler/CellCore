import { create } from "zustand";

interface AuthState {
  authenticated: boolean;
  checking: boolean;
  token: string | null;
  csrfToken: string | null;
  setAuthenticated: (
    authenticated: boolean,
    token?: string | null,
    csrfToken?: string | null
  ) => void;
  setChecking: (checking: boolean) => void;
  clearAuth: () => void;
}

const TOKEN_STORAGE_KEY = "qm_session_token";
const CSRF_STORAGE_KEY = "qm_csrf_token";

function readStored(key: string): string | null {
  try {
    const val = sessionStorage.getItem(key);
    if (val && /^[0-9a-fA-F]{16,64}$/.test(val)) return val;
  } catch {
    // ignore
  }
  return null;
}

export const useAuthStore = create<AuthState>((set) => ({
  authenticated: false,
  checking: true,
  token: readStored(TOKEN_STORAGE_KEY),
  csrfToken: readStored(CSRF_STORAGE_KEY),
  setAuthenticated: (authenticated, token, csrfToken) => {
    const cleanTok = token && /^[0-9a-fA-F]{16,64}$/.test(token) ? token : null;
    const cleanCsrf = csrfToken && /^[0-9a-fA-F]{16,64}$/.test(csrfToken) ? csrfToken : null;
    try {
      if (authenticated && cleanTok) sessionStorage.setItem(TOKEN_STORAGE_KEY, cleanTok);
      else if (!authenticated) sessionStorage.removeItem(TOKEN_STORAGE_KEY);
      if (authenticated && cleanCsrf) sessionStorage.setItem(CSRF_STORAGE_KEY, cleanCsrf);
      else if (!authenticated) sessionStorage.removeItem(CSRF_STORAGE_KEY);
    } catch {
      // ignore
    }
    set((prev) => ({
      authenticated,
      checking: false,
      token: authenticated ? (cleanTok ?? prev.token) : null,
      csrfToken: authenticated ? (cleanCsrf ?? prev.csrfToken) : null,
    }));
  },
  setChecking: (checking) => set({ checking }),
  clearAuth: () => {
    try {
      sessionStorage.removeItem(TOKEN_STORAGE_KEY);
      sessionStorage.removeItem(CSRF_STORAGE_KEY);
    } catch {
      // ignore
    }
    set({ authenticated: false, checking: false, token: null, csrfToken: null });
  },
}));
