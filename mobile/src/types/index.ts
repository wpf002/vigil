export interface User {
  user_id: string;
  email: string;
  role: string;
  tenant_id: string;
}

export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  user: User;
}

export interface EscalationQueueItem {
  queue_id: string;
  attack_id: string;
  tenant_id: string;
  tenant_name: string;
  attack_name: string;
  current_phase: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  escalated_at: string;
  sla_deadline: string | null;
  sla_breached: boolean;
  assigned_to: string | null;
  status: string;
}

export interface EvidenceItem {
  detection_id: string;
  fired_at: string;
  source: string;
  summary?: string;
}

export interface RecommendedAction {
  action_type: string;
  priority: 'immediate' | 'follow_up';
  target_entity: string;
  completed: boolean;
}

export interface AttackState {
  attack_id: string;
  tenant_id: string;
  name: string;
  current_phase: string;
  status: string;
  confidence: number;
  momentum: number | null;
  narrative: string | null;
  analyst_summary: string | null;
  evidence: EvidenceItem[];
  recommended_actions: RecommendedAction[];
  opened_at: string;
  last_updated_at: string;
}
