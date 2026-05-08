export type DetectionStatus = "active" | "deprecated" | "rolled_back";

export interface DetectionStateImpact {
  status?: string;
  transitions_to?: string;
  confidence_contribution?: number;
  progression?: boolean;
}

export interface DetectionPerformance {
  perf_id: string;
  detection_id: string;
  tenant_id: string;
  period_start: string | null;
  period_end: string | null;
  total_fires: number;
  false_positives: number;
  true_positives: number;
  escalations: number;
  fp_rate: number | null;
  avg_confidence: number | null;
  computed_at: string | null;
}

export interface DetectionVersion {
  version_id: string;
  detection_id: string;
  version: string;
  att_ck_tactic: string;
  att_ck_technique: string;
  state_impact: DetectionStateImpact;
  status: DetectionStatus;
  deployed_at: string | null;
  deployed_by: string | null;
  tenant_id: string;
  notes: string | null;
  yaml_content?: string | null;
  compiled_spl?: string | null;
  compiled_kql?: string | null;
  compiled_eql?: string | null;
  performance?: DetectionPerformance | null;
}

export interface DetectionSignal {
  signal_id: string;
  detection_id: string;
  tenant_id: string;
  fired_at: string;
  attack_id: string | null;
  phase_contributed: string | null;
  status_contributed: string | null;
  confidence_contribution: number | null;
  was_false_positive: boolean;
  closed_as: string | null;
}

export interface DetectionTrendPoint {
  day: string;
  fires: number;
  false_positives: number;
}

export interface DetectionPerformanceDetail {
  detection_id: string;
  summary: DetectionPerformance | null;
  trend: DetectionTrendPoint[];
  signals: DetectionSignal[];
}

export interface CoverageReport {
  total_detections: number;
  tactics: string[];
  counts_by_tactic: Record<string, number>;
  detections_by_tactic: Record<string, string[]>;
  covered_tactics: string[];
  uncovered_tactics: string[];
  coverage_score: number;
  unmapped_detections: string[];
}
