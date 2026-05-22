import { apiClient } from "./client";
import type {
  ApiEnvelope,
  AttackListFilters,
  AttackState,
  AttackStateStatus,
  AttackStateSummary,
  EvidenceItem,
  ResponseAction,
} from "@/types/attacks";

function unwrap<T>(env: ApiEnvelope<T>): T {
  if (env.error) throw new Error(env.error);
  return env.data;
}

export async function listAttacks(
  filters: AttackListFilters = {},
): Promise<AttackState[]> {
  const params: Record<string, unknown> = {};
  if (filters.phase) params.phase = filters.phase;
  if (filters.min_confidence !== undefined && filters.min_confidence > 0)
    params.min_confidence = filters.min_confidence;
  if (filters.momentum) params.momentum = filters.momentum;
  if (filters.status) params.status = filters.status;
  params.limit = filters.limit ?? 50;
  params.offset = filters.offset ?? 0;

  const res = await apiClient.get<ApiEnvelope<AttackState[]>>("/attacks", {
    params,
  });
  return unwrap(res.data);
}

export async function getAttack(attackId: string): Promise<AttackState> {
  const res = await apiClient.get<ApiEnvelope<AttackState>>(
    `/attacks/${attackId}`,
  );
  return unwrap(res.data);
}

export async function getEvidence(
  attackId: string,
  limit = 100,
  offset = 0,
): Promise<EvidenceItem[]> {
  const res = await apiClient.get<ApiEnvelope<EvidenceItem[]>>(
    `/attacks/${attackId}/evidence`,
    { params: { limit, offset } },
  );
  return unwrap(res.data);
}

export async function updateAttackStatus(
  attackId: string,
  status: AttackStateStatus,
  analystNote?: string,
): Promise<AttackState> {
  const res = await apiClient.patch<ApiEnvelope<AttackState>>(
    `/attacks/${attackId}/status`,
    { status, analyst_note: analystNote },
  );
  return unwrap(res.data);
}

export async function completeAction(
  attackId: string,
  actionId: number,
): Promise<ResponseAction> {
  const res = await apiClient.post<ApiEnvelope<ResponseAction>>(
    `/attacks/${attackId}/actions/${actionId}/complete`,
  );
  return unwrap(res.data);
}

export async function getStatsSummary(): Promise<AttackStateSummary> {
  const res = await apiClient.get<ApiEnvelope<AttackStateSummary>>(
    "/attacks/stats/summary",
  );
  return unwrap(res.data);
}
