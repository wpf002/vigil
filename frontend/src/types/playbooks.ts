import type { ResponseAction } from "@/types/attacks";

export type PlaybookStatus = "running" | "completed" | "failed" | "paused";

export interface PlaybookRun {
  run_id: string;
  attack_id: string;
  tenant_id: string;
  workflow_id: string;
  narrative_id: string | null;
  triggered_at: string | null;
  status: PlaybookStatus;
  phase_at_trigger: string;
  confidence_at_trigger: number;
  completed_at: string | null;
  actions: ResponseAction[];
  completed_actions: ResponseAction[];
}

export interface NarrativePlaybookSummary {
  playbook_name: string;
  trigger: string;
  immediate_count: number;
  follow_up_count: number;
}

export interface NarrativeSummary {
  narrative_id: string;
  name: string;
  phases: string[];
  playbooks: NarrativePlaybookSummary[];
}

export type { ResponseAction };
