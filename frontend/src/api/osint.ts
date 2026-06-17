import axios, { type AxiosError, type InternalAxiosRequestConfig } from "axios";
import { useAuthStore } from "@/store/authStore";

const OSINT_URL = import.meta.env.VITE_OSINT_URL ?? "http://localhost:8012";
const DEV_TENANT = import.meta.env.VITE_DEV_TENANT_ID ?? "";

const osintClient = axios.create({
  baseURL: OSINT_URL,
  timeout: 30000,
  headers: { "Content-Type": "application/json" },
});

osintClient.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = useAuthStore.getState().accessToken;
  if (token) config.headers.Authorization = `Bearer ${token}`;
  else if (DEV_TENANT) config.headers["X-Tenant-Id"] = DEV_TENANT;
  return config;
});

osintClient.interceptors.response.use(
  (res) => res,
  (err: AxiosError) => {
    const data = err.response?.data as { detail?: string; error?: string } | undefined;
    if (data?.detail) err.message = typeof data.detail === "string" ? data.detail : err.message;
    else if (data?.error) err.message = data.error;
    return Promise.reject(err);
  },
);

export interface Observation {
  source: string;
  entity_type: string;
  entity_value: string;
  observed_at: string | null;
  retrieved_at: string;
  confidence_score: number;
  tlp: string;
  summary: Record<string, unknown>;
  raw: Record<string, unknown>;
  deep_link: string | null;
}

export interface DeepLink {
  connector: string;
  url: string;
  reason: string;
}

export interface EnrichResponse {
  parsed: { type: string; value: string };
  observations: Observation[];
  deep_links: DeepLink[];
  errors: { connector: string; error: string }[];
}

export async function enrich(
  query: string,
  connectors: string[] = [],
): Promise<EnrichResponse> {
  const res = await osintClient.post<EnrichResponse>("/osint/enrich", {
    query,
    connectors,
    filters: {},
  });
  return res.data;
}
