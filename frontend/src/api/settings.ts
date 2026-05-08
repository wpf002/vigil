import { apiClient } from "./client";

export interface APIKeySummary {
  key_id: string;
  name: string;
  key_prefix: string;
  scopes: string[];
  last_used_at: string | null;
  expires_at: string | null;
  revoked: boolean;
  created_at: string;
}

export interface APIKeyCreated extends APIKeySummary {
  raw_key: string;
}

export async function listAPIKeys(): Promise<APIKeySummary[]> {
  const res = await apiClient.get<APIKeySummary[]>("/auth/api-keys");
  return res.data;
}

export async function createAPIKey(
  name: string,
  scopes: string[],
  expires_at?: string,
): Promise<APIKeyCreated> {
  const res = await apiClient.post<APIKeyCreated>("/auth/api-keys", {
    name,
    scopes,
    expires_at: expires_at || null,
  });
  return res.data;
}

export async function revokeAPIKey(key_id: string): Promise<void> {
  await apiClient.delete(`/auth/api-keys/${key_id}`);
}

export interface WebhookSummary {
  webhook_id: string;
  url: string;
  events: string[];
  active: boolean;
  last_fired_at: string | null;
  failure_count: number;
  created_at: string;
}

export async function listWebhooks(): Promise<WebhookSummary[]> {
  const res = await apiClient.get<WebhookSummary[]>("/webhooks");
  return res.data;
}

export async function createWebhook(
  url: string,
  secret: string,
  events: string[],
): Promise<WebhookSummary> {
  const res = await apiClient.post<WebhookSummary>("/webhooks", {
    url,
    secret,
    events,
  });
  return res.data;
}

export async function deleteWebhook(webhook_id: string): Promise<void> {
  await apiClient.delete(`/webhooks/${webhook_id}`);
}

export async function testWebhook(webhook_id: string): Promise<{
  status_code: number | null;
  ok: boolean;
  error?: string;
}> {
  const res = await apiClient.post(`/webhooks/${webhook_id}/test`);
  return res.data;
}
