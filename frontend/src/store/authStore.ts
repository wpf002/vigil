import { create } from "zustand";
import type { AuthUser } from "@/api/auth";

const REFRESH_KEY = "vigil_refresh_token";
const USER_KEY = "vigil_user";

interface AuthState {
  // access_token lives in memory ONLY — never written to localStorage.
  accessToken: string | null;
  user: AuthUser | null;

  setSession: (
    access_token: string,
    refresh_token: string,
    user: AuthUser,
  ) => void;
  setAccessToken: (access_token: string) => void;
  setRefreshToken: (refresh_token: string) => void;
  clear: () => void;
  getRefreshToken: () => string | null;
  hydrate: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  accessToken: null,
  user: null,

  setSession: (access_token, refresh_token, user) => {
    localStorage.setItem(REFRESH_KEY, refresh_token);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
    set({ accessToken: access_token, user });
  },

  setAccessToken: (access_token) => set({ accessToken: access_token }),

  setRefreshToken: (refresh_token) => {
    localStorage.setItem(REFRESH_KEY, refresh_token);
  },

  clear: () => {
    localStorage.removeItem(REFRESH_KEY);
    localStorage.removeItem(USER_KEY);
    set({ accessToken: null, user: null });
  },

  getRefreshToken: () => localStorage.getItem(REFRESH_KEY),

  hydrate: () => {
    // Re-attach the cached user on page load. Without an access_token in
    // memory the protected-route wrapper will trigger a refresh on the
    // first API call.
    const userJson = localStorage.getItem(USER_KEY);
    if (userJson) {
      try {
        set({ user: JSON.parse(userJson) as AuthUser });
      } catch {
        localStorage.removeItem(USER_KEY);
      }
    }
  },
}));
