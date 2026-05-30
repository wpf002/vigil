// Mirror of services/attack-state-engine/models/attack_state.py.
// Keep in sync — these are the wire types returned by the API.

export type MITRETactic =
  | "reconnaissance"
  | "resource-development"
  | "initial-access"
  | "execution"
  | "persistence"
  | "privilege-escalation"
  | "defense-evasion"
  | "credential-access"
  | "discovery"
  | "lateral-movement"
  | "collection"
  | "command-and-control"
  | "exfiltration"
  | "impact";

export type ImpactLevel = "Low" | "Medium" | "High" | "Critical";
export type Momentum = "Increasing" | "Stable" | "Decreasing";
export type PhaseStatus = "Observed" | "Confirmed" | "Blocked";
export type AttackStateStatus =
  | "active"
  | "contained"
  | "resolved"
  | "false_positive";

export interface MITREMapping {
  tactic?: string | null;
  tactic_id?: string | null;
  technique?: string | null;
  technique_id?: string | null;
}

export interface EvidenceItem {
  evidence_id: string;
  signal_id: string;
  detection_id: string | null;
  rule_name: string | null;
  source_siem: string;
  entity_type: string;
  entity_value: string;
  raw_reference: string | null;
  timestamp: string;
  phase: MITRETactic;
  technique_id: string | null;
  status_contributed: PhaseStatus;
  confidence_contribution: number;
  // enrichment (optional)
  title?: string | null;
  description?: string | null;
  severity?: string | null;
  host?: string | null;
  ip?: string | null;
  user?: string | null;
  process?: string | null;
  command_line?: string | null;
  dest_ip?: string | null;
  dest_port?: number | null;
  raw_event?: Record<string, unknown> | null;
}

export interface PhaseState {
  phase: MITRETactic;
  status: PhaseStatus;
  technique_id?: string | null;
  technique_name?: string | null;
  first_seen: string;
  last_seen: string;
  evidence_ids: string[];
  confidence: number;
}

export interface ResponseAction {
  action_type: string;
  priority: "immediate" | "follow_up" | string;
  kind?: "enrichment" | "response" | string;
  target_entity: string;
  description: string;
  automated: boolean;
  completed: boolean;
  completed_at?: string | null;
}

export interface ResponseStatus {
  containment: boolean;
  eradication: boolean;
  recovery: boolean;
  containment_at?: string | null;
  eradication_at?: string | null;
  recovery_at?: string | null;
}

export interface AttackState {
  attack_id: string;
  tenant_id: string;
  name: string;
  description?: string | null;

  status: AttackStateStatus;
  current_phase: MITRETactic;
  confidence: number;
  impact: ImpactLevel;
  momentum: Momentum;

  phases: PhaseState[];

  users: string[];
  hosts: string[];
  processes: string[];
  credentials: string[];
  cloud_resources: string[];

  evidence: EvidenceItem[];

  narrative?: string | null;
  predicted_next_phase?: MITRETactic | null;
  analyst_summary?: string | null;

  recommended_actions: ResponseAction[];
  response_status: ResponseStatus;

  first_seen: string;
  last_seen: string;
  last_updated: string;
}

export interface AttackStateSummary {
  total_active: number;
  phase_breakdown: Record<string, number>;
  momentum_breakdown: Record<string, number>;
  confidence_distribution: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
}

export interface ApiEnvelope<T> {
  data: T;
  meta?: Record<string, unknown>;
  error?: string | null;
}

export interface AttackListFilters {
  phase?: MITRETactic | null;
  min_confidence?: number;
  momentum?: Momentum | null;
  status?: string;
  limit?: number;
  offset?: number;
}

export const PHASE_ORDER: MITRETactic[] = [
  "reconnaissance",
  "resource-development",
  "initial-access",
  "execution",
  "persistence",
  "privilege-escalation",
  "defense-evasion",
  "credential-access",
  "discovery",
  "lateral-movement",
  "collection",
  "command-and-control",
  "exfiltration",
  "impact",
];
