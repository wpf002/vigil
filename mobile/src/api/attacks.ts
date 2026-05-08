import {attackStateClient} from './client';
import type {AttackState} from '../types';

interface Envelope<T> {
  data: T;
  meta?: Record<string, unknown>;
  error?: string | null;
}

function unwrap<T>(env: Envelope<T>): T {
  if (env.error) throw new Error(env.error);
  return env.data;
}

export async function getAttack(attack_id: string): Promise<AttackState> {
  const res = await attackStateClient.get<Envelope<AttackState>>(`/attacks/${attack_id}`);
  return unwrap(res.data);
}
