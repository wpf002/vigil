import {analystPortalClient} from './client';
import type {EscalationQueueItem} from '../types';

interface Envelope<T> {
  data: T;
  meta?: Record<string, unknown>;
  error?: string | null;
}

function unwrap<T>(env: Envelope<T>): T {
  if (env.error) throw new Error(env.error);
  return env.data;
}

export async function listQueue(): Promise<EscalationQueueItem[]> {
  const res = await analystPortalClient.get<Envelope<EscalationQueueItem[]>>('/queue');
  return unwrap(res.data);
}

export async function acknowledgeEscalation(queue_id: string): Promise<void> {
  await analystPortalClient.post(`/queue/${queue_id}/acknowledge`);
}

export async function assignEscalation(queue_id: string, user_id: string): Promise<void> {
  await analystPortalClient.post(`/queue/${queue_id}/assign`, {user_id});
}
