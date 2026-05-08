import axios, { AxiosError, type InternalAxiosRequestConfig } from "axios";
import { useAuthStore } from "@/store/authStore";
import { extractErrorMessage } from "./client";

const AUTH_URL =
  import.meta.env.VITE_AUTH_URL ?? "http://localhost:8000";

export interface AuthUser {
  user_id: string;
  email: string;
  role: string;
  tenant_id: string;
}

export interface MeResponse extends AuthUser {
  last_login: string | null;
}

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  user: AuthUser;
}

export interface RefreshResponse {
  access_token: string;
  refresh_token: string;
}

/** Axios instance for the api service (port 8000).
 *
 * The login/register/refresh routes don't need a Bearer token, but other
 * /auth/* routes (api-keys, audit-log, /webhooks, /onboarding) do. The
 * request interceptor opportunistically attaches the in-memory access
 * token; the response interceptor handles 401 → silent refresh exactly
 * like the other clients. */
export const authClient = axios.create({
  baseURL: AUTH_URL,
  timeout: 15000,
  headers: { "Content-Type": "application/json" },
});

type Retry = InternalAxiosRequestConfig & { _retry?: boolean };

authClient.interceptors.request.use((config) => {
  const token = useAuthStore.getState().accessToken;
  if (token && !config.headers.Authorization) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

let _refreshPromise: Promise<string | null> | null = null;

async function _silentRefresh(): Promise<string | null> {
  if (_refreshPromise) return _refreshPromise;
  _refreshPromise = (async () => {
    const store = useAuthStore.getState();
    const rt = store.getRefreshToken();
    if (!rt) return null;
    try {
      const result = await refresh(rt);
      store.setAccessToken(result.access_token);
      store.setRefreshToken(result.refresh_token);
      return result.access_token;
    } catch {
      store.clear();
      return null;
    } finally {
      setTimeout(() => {
        _refreshPromise = null;
      }, 0);
    }
  })();
  return _refreshPromise;
}

authClient.interceptors.response.use(
  (res) => res,
  async (err: AxiosError) => {
    const original = err.config as Retry | undefined;
    if (err.response?.status === 401 && original && !original._retry) {
      // Don't loop on the refresh endpoint itself.
      if (!String(original.url ?? "").includes("/auth/refresh")) {
        original._retry = true;
        const newToken = await _silentRefresh();
        if (newToken) {
          original.headers = original.headers ?? {};
          original.headers.Authorization = `Bearer ${newToken}`;
          return authClient(original);
        }
      }
    }
    err.message = extractErrorMessage(err.response?.data) ?? err.message;
    return Promise.reject(err);
  },
);

export async function register(
  email: string,
  password: string,
  tenant_name: string,
): Promise<TokenPair> {
  const res = await authClient.post<TokenPair>("/auth/register", {
    email,
    password,
    tenant_name,
  });
  return res.data;
}

export async function login(
  email: string,
  password: string,
): Promise<TokenPair> {
  const res = await authClient.post<TokenPair>("/auth/login", {
    email,
    password,
  });
  return res.data;
}

export async function refresh(refresh_token: string): Promise<RefreshResponse> {
  const res = await authClient.post<RefreshResponse>("/auth/refresh", {
    refresh_token,
  });
  return res.data;
}

export async function logout(
  access_token: string,
  refresh_token: string,
): Promise<void> {
  await authClient.post(
    "/auth/logout",
    { refresh_token },
    { headers: { Authorization: `Bearer ${access_token}` } },
  );
}

export async function fetchMe(access_token: string): Promise<MeResponse> {
  const res = await authClient.get<MeResponse>("/auth/me", {
    headers: { Authorization: `Bearer ${access_token}` },
  });
  return res.data;
}
