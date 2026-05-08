import { authClient as apiClient } from "./auth";

export type SIEMType = "splunk_es" | "splunk_core" | "sentinel" | "elastic";

export interface ConnectionParams {
  siem_type: SIEMType;
  // Splunk
  host?: string;
  username?: string;
  password?: string;
  token?: string;
  verify_ssl?: boolean;
  // Sentinel
  tenant_id?: string;
  client_id?: string;
  client_secret?: string;
  subscription_id?: string;
  resource_group?: string;
  workspace_name?: string;
  // Elastic
  elastic_url?: string;
  api_key_id?: string;
  api_key_secret?: string;
}

export interface ConnectionResult {
  connected: boolean;
  version: string | null;
  error: string | null;
}

export async function checkConnection(
  params: ConnectionParams,
): Promise<ConnectionResult> {
  const res = await apiClient.post<ConnectionResult>(
    "/onboarding/check-connection",
    params,
  );
  return res.data;
}

export async function seedDemo(): Promise<{ published: number }> {
  const res = await apiClient.post<{ published: number }>(
    "/onboarding/seed-demo",
  );
  return res.data;
}

export async function markOnboardingComplete(): Promise<void> {
  await apiClient.patch("/auth/me/onboarding-complete");
}
