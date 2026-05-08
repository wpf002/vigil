import axios, { AxiosError, type InternalAxiosRequestConfig } from "axios";
import { refresh } from "./auth";
import { useAuthStore } from "@/store/authStore";
import type {
  ExecutiveSummary,
  ExecutiveTrend,
  ComplianceReport,
} from "@/types/reporting";

const REPORTING_URL =
  import.meta.env.VITE_REPORTING_URL ?? "http://localhost:8009";
const DEV_TENANT = import.meta.env.VITE_DEV_TENANT_ID ?? "";

export const reportingClient = axios.create({
  baseURL: REPORTING_URL,
  timeout: 15000,
  headers: { "Content-Type": "application/json" },
});

type Retry = InternalAxiosRequestConfig & { _retry?: boolean };

reportingClient.interceptors.request.use((config) => {
  const token = useAuthStore.getState().accessToken;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  } else if (DEV_TENANT && !config.headers.Authorization) {
    config.headers["X-Tenant-Id"] = DEV_TENANT;
  }
  return config;
});

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
      setTimeout(() => {
        refreshPromise = null;
      }, 0);
    }
  })();
  return refreshPromise;
}

reportingClient.interceptors.response.use(
  (res) => res,
  async (err: AxiosError) => {
    const original = err.config as Retry | undefined;
    if (err.response?.status === 401 && original && !original._retry) {
      original._retry = true;
      const newToken = await attemptRefresh();
      if (newToken) {
        original.headers = original.headers ?? {};
        original.headers.Authorization = `Bearer ${newToken}`;
        return reportingClient(original);
      }
    }
    const data = err.response?.data as { error?: string; detail?: string } | undefined;
    if (data?.error) err.message = data.error;
    else if (data?.detail) err.message = data.detail;
    return Promise.reject(err);
  },
);

interface Envelope<T> {
  data: T;
  meta?: Record<string, unknown>;
  error?: string | null;
}

function unwrap<T>(env: Envelope<T>): T {
  if (env.error) throw new Error(env.error);
  return env.data;
}

export async function getExecutiveSummary(): Promise<ExecutiveSummary> {
  const res = await reportingClient.get<Envelope<ExecutiveSummary>>(
    "/executive/summary",
  );
  return unwrap(res.data);
}

export async function getExecutiveTrend(days = 30): Promise<ExecutiveTrend> {
  const res = await reportingClient.get<Envelope<ExecutiveTrend>>(
    "/executive/trend",
    { params: { days } },
  );
  return unwrap(res.data);
}

export async function getCompliance(
  framework: "soc2" | "pci" | "nist",
  period_days = 30,
): Promise<ComplianceReport> {
  const res = await reportingClient.get<Envelope<ComplianceReport>>(
    `/compliance/${framework}`,
    { params: { period_days } },
  );
  return unwrap(res.data);
}

export async function exportReport(
  type: "soc2" | "pci" | "nist" | "executive",
  period_days = 30,
): Promise<void> {
  const res = await reportingClient.get(`/reports/export`, {
    params: { type, format: "json", period_days },
    responseType: "blob",
  });
  const url = URL.createObjectURL(res.data as Blob);
  const a = document.createElement("a");
  a.href = url;
  const date = new Date().toISOString().slice(0, 10);
  a.download = `vigil-${type}-report-${date}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
