import axios, { type AxiosError, type InternalAxiosRequestConfig } from "axios";
import { useAuthStore } from "@/store/authStore";

const INGESTOR_URL =
  import.meta.env.VITE_INGESTOR_URL ?? "http://localhost:8001";

const simClient = axios.create({
  baseURL: INGESTOR_URL,
  timeout: 20000,
  headers: { "Content-Type": "application/json" },
});

simClient.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = useAuthStore.getState().accessToken;
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

simClient.interceptors.response.use(
  (res) => res,
  (err: AxiosError) => {
    const data = err.response?.data as { detail?: string; error?: string } | undefined;
    if (data?.detail) err.message = data.detail;
    else if (data?.error) err.message = data.error;
    return Promise.reject(err);
  },
);

export interface Scenario {
  id: string;
  name: string;
  description: string;
  severity: string;
  steps: number;
  expected_detections: string[];
  phases: string[];
}

export interface CoverageResult {
  detection_id: string;
  covered: boolean;
}

export interface SimulationResult {
  simulation_id: string;
  scenario: string;
  scenario_name: string;
  emitted: number;
  published: number;
  expected_detections: string[];
  expected_phases: string[];
  coverage: {
    results: CoverageResult[];
    covered: number;
    total: number;
    coverage_pct: number;
    verdict: "pass" | "partial" | "fail";
    gaps: string[];
  };
}

export async function listScenarios(): Promise<Scenario[]> {
  const res = await simClient.get<{ scenarios: Scenario[] }>("/simulations/scenarios");
  return res.data.scenarios;
}

export async function runSimulation(
  scenarioId: string,
  host?: string,
): Promise<SimulationResult> {
  const res = await simClient.post<SimulationResult>("/simulations/run", {
    scenario_id: scenarioId,
    host,
  });
  return res.data;
}
