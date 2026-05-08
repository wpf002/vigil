export interface ExecutiveSummary {
  active_attacks: number;
  attacks_resolved_7d: number;
  mttr_seconds_7d: number | null;
  sla_breach_rate_7d: number | null;
  coverage_score: number | null;
  top_tactic: string | null;
  open_escalations: number;
  fp_rate_30d: number | null;
  attacks_by_phase: Record<string, number>;
  computed_at: string;
}

export interface TrendPoint {
  date: string;
  count?: number;
  value?: number;
}

export interface ExecutiveTrend {
  days: number;
  attack_volume: TrendPoint[];
  mttr_seconds: TrendPoint[];
  sla_breach_rate: TrendPoint[];
}

export interface ComplianceCriteria {
  criterion?: string;
  requirement?: string;
  evidence: unknown;
}

export interface ComplianceReport {
  framework: string;
  tenant_id: string;
  period_start: string;
  period_end: string;
  generated_at: string;
  criteria?: ComplianceCriteria[];
  functions?: Record<string, unknown>;
}
