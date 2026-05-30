import axios, { AxiosError, type InternalAxiosRequestConfig } from "axios";
import { refresh } from "./auth";
import { useAuthStore } from "@/store/authStore";
import type {
  NarrativeSummary,
  PlaybookRun,
} from "@/types/playbooks";

const PLAYBOOK_URL =
  import.meta.env.VITE_PLAYBOOK_ENGINE_URL ?? "http://localhost:8007";
const DEV_TENANT = import.meta.env.VITE_DEV_TENANT_ID ?? "";

export const playbookClient = axios.create({
  baseURL: PLAYBOOK_URL,
  timeout: 15000,
  headers: { "Content-Type": "application/json" },
});

type Retry = InternalAxiosRequestConfig & { _retry?: boolean };

playbookClient.interceptors.request.use((config) => {
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

playbookClient.interceptors.response.use(
  (res) => res,
  async (err: AxiosError) => {
    const original = err.config as Retry | undefined;
    if (err.response?.status === 401 && original && !original._retry) {
      original._retry = true;
      const newToken = await attemptRefresh();
      if (newToken) {
        original.headers = original.headers ?? {};
        original.headers.Authorization = `Bearer ${newToken}`;
        return playbookClient(original);
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

export async function listPlaybooks(): Promise<PlaybookRun[]> {
  const res = await playbookClient.get<ApiEnvelope<PlaybookRun[]>>("/playbooks");
  return unwrap(res.data);
}

export async function getPlaybook(runId: string): Promise<PlaybookRun> {
  const res = await playbookClient.get<ApiEnvelope<PlaybookRun>>(
    `/playbooks/${runId}`,
  );
  return unwrap(res.data);
}

export async function getPlaybooksForAttack(attackId: string): Promise<PlaybookRun[]> {
  const res = await playbookClient.get<ApiEnvelope<PlaybookRun[]>>(
    `/playbooks/attack/${attackId}`,
  );
  return unwrap(res.data);
}

export async function resumePlaybook(runId: string): Promise<{ run_id: string; status: string }> {
  const res = await playbookClient.post<ApiEnvelope<{ run_id: string; status: string }>>(
    `/playbooks/${runId}/resume`,
  );
  return unwrap(res.data);
}

export async function abortPlaybook(runId: string): Promise<{ run_id: string; status: string }> {
  const res = await playbookClient.post<ApiEnvelope<{ run_id: string; status: string }>>(
    `/playbooks/${runId}/abort`,
  );
  return unwrap(res.data);
}

export interface RunPlaybookResult {
  run_id: string;
  workflow_id: string;
  narrative_id: string | null;
  phase_at_trigger: string;
  trigger: string;
  action_count: number;
}

export async function runPlaybook(attackId: string): Promise<RunPlaybookResult> {
  const res = await playbookClient.post<ApiEnvelope<RunPlaybookResult>>(
    "/playbooks/run",
    { attack_id: attackId },
  );
  return unwrap(res.data);
}

export async function listNarratives(): Promise<NarrativeSummary[]> {
  const res = await playbookClient.get<ApiEnvelope<NarrativeSummary[]>>("/narratives");
  return unwrap(res.data);
}

// ── authored playbook definitions (build-a-playbook) ───────────────────────

export interface DefinitionAction {
  action_type: string;
  target: string;
  kind?: string;
  priority?: string;
  automated?: boolean;
  description?: string;
}

export interface PlaybookDefinition {
  definition_id: string;
  name: string;
  enabled: boolean;
  trigger_mode: string;
  trigger_phase: string | null;
  trigger_status: string | null;
  min_confidence: number;
  trigger_detection_id: string | null;
  actions: DefinitionAction[];
  created_at: string | null;
  updated_at: string | null;
}

export interface PlaybookDefinitionInput {
  name: string;
  trigger_mode: string;
  trigger_phase?: string | null;
  trigger_status?: string | null;
  min_confidence?: number;
  trigger_detection_id?: string | null;
  actions: DefinitionAction[];
  enabled?: boolean;
}

export async function listPlaybookDefinitions(): Promise<PlaybookDefinition[]> {
  const res = await playbookClient.get<ApiEnvelope<PlaybookDefinition[]>>("/playbook-definitions");
  return unwrap(res.data);
}

export async function createPlaybookDefinition(
  input: PlaybookDefinitionInput,
): Promise<PlaybookDefinition> {
  const res = await playbookClient.post<ApiEnvelope<PlaybookDefinition>>(
    "/playbook-definitions",
    input,
  );
  return unwrap(res.data);
}

export async function updatePlaybookDefinition(
  id: string,
  patch: Partial<PlaybookDefinitionInput>,
): Promise<PlaybookDefinition> {
  const res = await playbookClient.patch<ApiEnvelope<PlaybookDefinition>>(
    `/playbook-definitions/${id}`,
    patch,
  );
  return unwrap(res.data);
}

export async function deletePlaybookDefinition(id: string): Promise<void> {
  await playbookClient.delete(`/playbook-definitions/${id}`);
}
