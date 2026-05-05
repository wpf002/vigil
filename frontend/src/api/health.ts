import axios from "axios";

// Hit each service's /health directly. We don't proxy through one endpoint
// — each service is independently reachable in dev.
const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8002";
const CORRELATION_BASE =
  import.meta.env.VITE_CORRELATION_URL ?? "http://localhost:8003";

export type ServiceHealth = "ok" | "degraded" | "down";

interface ServiceStatus {
  name: string;
  status: ServiceHealth;
}

async function probe(name: string, url: string): Promise<ServiceStatus> {
  try {
    const res = await axios.get(`${url}/health`, { timeout: 3000 });
    const status: ServiceHealth =
      res.status === 200 && (res.data?.status ?? "ok") === "ok"
        ? "ok"
        : "degraded";
    return { name, status };
  } catch {
    return { name, status: "down" };
  }
}

export async function getPipelineHealth(): Promise<ServiceStatus[]> {
  return Promise.all([
    probe("API", API_BASE),
    probe("Correlation", CORRELATION_BASE),
  ]);
}
