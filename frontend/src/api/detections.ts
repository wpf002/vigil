import axios, { AxiosError, type InternalAxiosRequestConfig } from "axios";
import { refresh } from "./auth";
import { useAuthStore } from "@/store/authStore";
import type {
  CoverageReport,
  DetectionPerformanceDetail,
  DetectionSignal,
  DetectionVersion,
} from "@/types/detections";

const DETECTION_URL =
  import.meta.env.VITE_DETECTION_ENGINE_URL ?? "http://localhost:8005";
const DEV_TENANT = import.meta.env.VITE_DEV_TENANT_ID ?? "";

export const detectionClient = axios.create({
  baseURL: DETECTION_URL,
  timeout: 15000,
  headers: { "Content-Type": "application/json" },
});

type Retry = InternalAxiosRequestConfig & { _retry?: boolean };

detectionClient.interceptors.request.use((config) => {
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

detectionClient.interceptors.response.use(
  (res) => res,
  async (err: AxiosError) => {
    const original = err.config as Retry | undefined;
    if (err.response?.status === 401 && original && !original._retry) {
      original._retry = true;
      const newToken = await attemptRefresh();
      if (newToken) {
        original.headers = original.headers ?? {};
        original.headers.Authorization = `Bearer ${newToken}`;
        return detectionClient(original);
      }
    }
    const data = err.response?.data as { error?: string; detail?: string } | undefined;
    if (data?.error) err.message = data.error;
    else if (data?.detail) err.message = data.detail;
    return Promise.reject(err);
  },
);

interface ApiEnvelope<T> {
  data: T;
  meta?: Record<string, unknown>;
  error?: string | null;
}

function unwrap<T>(env: ApiEnvelope<T>): T {
  if (env.error) throw new Error(env.error);
  return env.data;
}

export async function listDetections(): Promise<DetectionVersion[]> {
  const res = await detectionClient.get<ApiEnvelope<DetectionVersion[]>>("/detections");
  return unwrap(res.data);
}

export async function getDetection(id: string): Promise<DetectionVersion> {
  const res = await detectionClient.get<ApiEnvelope<DetectionVersion>>(
    `/detections/${id}`,
  );
  return unwrap(res.data);
}

export async function getDetectionHistory(id: string): Promise<DetectionVersion[]> {
  const res = await detectionClient.get<ApiEnvelope<DetectionVersion[]>>(
    `/detections/${id}/history`,
  );
  return unwrap(res.data);
}

export async function getDetectionPerformance(
  id: string,
  days = 30,
): Promise<DetectionPerformanceDetail> {
  const res = await detectionClient.get<ApiEnvelope<DetectionPerformanceDetail>>(
    `/detections/${id}/performance`,
    { params: { days } },
  );
  return unwrap(res.data);
}

export async function rollbackDetection(id: string): Promise<DetectionVersion> {
  const res = await detectionClient.patch<ApiEnvelope<DetectionVersion>>(
    `/detections/${id}/rollback`,
  );
  return unwrap(res.data);
}

export async function markFalsePositive(
  detectionId: string,
  signalId: string,
): Promise<DetectionSignal> {
  const res = await detectionClient.patch<ApiEnvelope<DetectionSignal>>(
    `/detections/${detectionId}/signals/${signalId}/false-positive`,
  );
  return unwrap(res.data);
}

export async function getCoverage(): Promise<CoverageReport> {
  const res = await detectionClient.get<ApiEnvelope<CoverageReport>>("/coverage");
  return unwrap(res.data);
}
