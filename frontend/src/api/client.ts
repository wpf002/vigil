import axios, { AxiosError, type InternalAxiosRequestConfig } from "axios";
import { refresh } from "./auth";
import { useAuthStore } from "@/store/authStore";

const API_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8002";
const DEV_TENANT = import.meta.env.VITE_DEV_TENANT_ID ?? "";

export const apiClient = axios.create({
  baseURL: API_URL,
  timeout: 15000,
  headers: {
    "Content-Type": "application/json",
  },
});

// Tag retried requests so we don't loop on a second 401.
type Retry = InternalAxiosRequestConfig & { _retry?: boolean };

apiClient.interceptors.request.use((config) => {
  const token = useAuthStore.getState().accessToken;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  } else if (DEV_TENANT && !config.headers.Authorization) {
    // Dev fallback when running the UI without the auth service. Drop this
    // by setting VITE_DEV_TENANT_ID="" in production.
    config.headers["X-Tenant-Id"] = DEV_TENANT;
  }
  return config;
});

// Coalesce concurrent 401s onto a single refresh.
let refreshPromise: Promise<string | null> | null = null;

async function attemptRefresh(): Promise<string | null> {
  if (refreshPromise) return refreshPromise;
  refreshPromise = (async () => {
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
      // Reset only after the in-flight callers have observed the result.
      setTimeout(() => {
        refreshPromise = null;
      }, 0);
    }
  })();
  return refreshPromise;
}

apiClient.interceptors.response.use(
  (res) => res,
  async (err: AxiosError) => {
    const original = err.config as Retry | undefined;

    if (err.response?.status === 401 && original && !original._retry) {
      original._retry = true;
      const newToken = await attemptRefresh();
      if (newToken) {
        original.headers = original.headers ?? {};
        original.headers.Authorization = `Bearer ${newToken}`;
        return apiClient(original);
      }
      // Refresh failed — bubble up so route guards can redirect.
      if (typeof window !== "undefined" && window.location.pathname !== "/login") {
        window.location.href = "/login";
      }
    }

    const data = err.response?.data as { error?: string; detail?: string } | undefined;
    if (data?.error) err.message = data.error;
    else if (data?.detail) err.message = data.detail;
    return Promise.reject(err);
  },
);
