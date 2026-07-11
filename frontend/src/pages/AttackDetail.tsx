import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ArrowLeft, Play } from "lucide-react";
import {
  completeAction,
  getAttack,
  updateAttackStatus,
  updateResponseStatus,
} from "@/api/attacks";
import { runPlaybook } from "@/api/playbooks";
import { TriageChecklist } from "@/components/TriageChecklist";
import { ConfidenceBar } from "@/components/ConfidenceBar";
import { EvidenceList } from "@/components/EvidenceList";
import { MomentumIndicator } from "@/components/MomentumIndicator";
import { PhaseTimeline } from "@/components/PhaseTimeline";
import { RecommendedActions } from "@/components/RecommendedActions";
import {
  impactColorClasses,
  phaseColorClasses,
  phaseLabel,
  pct,
  timeAgo,
  titleCase,
} from "@/lib/format";
import type { AttackStateStatus } from "@/types/attacks";

export function AttackDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ["attack", id],
    queryFn: () => getAttack(id as string),
    enabled: !!id,
    refetchInterval: 30_000,
  });

  const statusMutation = useMutation({
    mutationFn: (status: AttackStateStatus) =>
      updateAttackStatus(id as string, status),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["attack", id] });
      queryClient.invalidateQueries({ queryKey: ["attacks"] });
    },
  });

  const actionMutation = useMutation({
    mutationFn: (actionIndex: number) =>
      completeAction(id as string, actionIndex),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["attack", id] });
    },
  });

  const triageMutation = useMutation({
    mutationFn: (v: { step: "containment" | "eradication" | "recovery"; value: boolean }) =>
      updateResponseStatus(id as string, v.step, v.value),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["attack", id] }),
  });

  const runPlaybookMutation = useMutation({
    mutationFn: () => runPlaybook(id as string),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["playbooks"] });
      navigate(`/playbooks/${result.run_id}`);
    },
    onError: (e) => {
      const msg = e instanceof Error ? e.message : "Failed to run playbook";
      alert(`Could not run playbook: ${msg}`);
    },
  });

  if (!id) return null;

  if (query.isLoading) {
    return (
      <div className="px-6 py-6">
        <div className="vigil-card p-8 text-center text-fg-muted font-mono text-sm">
          Loading attack…
        </div>
      </div>
    );
  }

  if (query.isError || !query.data) {
    return (
      <div className="px-6 py-6">
        <div className="vigil-card p-6 border-accent/40 bg-accent/5 text-accent font-mono text-sm">
          Failed to load attack: {(query.error as Error)?.message ?? "not found"}
        </div>
      </div>
    );
  }

  const attack = query.data;
  const isCritical = attack.confidence >= 0.7;

  return (
    <div className="px-6 py-6 max-w-[1400px] mx-auto space-y-5">
      <div>
        <Link
          to="/attacks"
          className="inline-flex items-center gap-1 text-xs font-mono text-fg-muted hover:text-fg"
        >
          <ArrowLeft size={12} /> Back to Attacks
        </Link>
      </div>

      <header
        className={`vigil-card p-5 ${
          isCritical ? "border-l-2 border-l-accent" : ""
        }`}
      >
        <div className="flex items-start justify-between gap-6 flex-wrap">
          <div className="min-w-0 flex-1">
            <div className="text-[10px] uppercase tracking-[0.18em] text-fg-faint font-mono mb-1">
              Attack Narrative · {attack.attack_id.slice(0, 8)}
            </div>
            <h1 className="font-mono text-xl text-fg break-words">
              {attack.name}
            </h1>
            <div className="flex flex-wrap gap-1.5 mt-3">
              <span
                className={`vigil-badge ${phaseColorClasses(attack.current_phase)}`}
              >
                {phaseLabel(attack.current_phase)}
              </span>
              <span className={`vigil-badge ${impactColorClasses(attack.impact)}`}>
                Impact: {attack.impact}
              </span>
              <span className="vigil-badge border-border-strong bg-surface-2 text-fg-muted">
                Status: {titleCase(attack.status)}
              </span>
              <MomentumIndicator momentum={attack.momentum} size="md" />
            </div>
            <div className="text-[11px] text-fg-faint mt-3 font-mono">
              first seen {timeAgo(attack.first_seen)} · last seen{" "}
              {timeAgo(attack.last_seen)} · {attack.evidence.length} signals
            </div>
          </div>

          <div className="w-full md:w-72 shrink-0">
            <div className="text-[10px] uppercase tracking-[0.18em] text-fg-faint font-mono mb-1">
              Confidence
            </div>
            <div
              className={`font-mono text-4xl tabular-nums ${
                isCritical ? "text-accent-hover" : "text-fg"
              }`}
            >
              {pct(attack.confidence)}
            </div>
            <div className="mt-2">
              <ConfidenceBar value={attack.confidence} showLabel={false} height="lg" />
            </div>
          </div>
        </div>

        <div className="mt-5 flex flex-wrap gap-2">
          <StatusButton
            current={attack.status}
            target="contained"
            onClick={() => statusMutation.mutate("contained")}
            disabled={statusMutation.isPending}
          >
            Mark Contained
          </StatusButton>
          <StatusButton
            current={attack.status}
            target="resolved"
            onClick={() => statusMutation.mutate("resolved")}
            disabled={statusMutation.isPending}
          >
            Mark Resolved
          </StatusButton>
          <StatusButton
            current={attack.status}
            target="false_positive"
            onClick={() => statusMutation.mutate("false_positive")}
            disabled={statusMutation.isPending}
          >
            False Positive
          </StatusButton>
        </div>
      </header>

      <PhaseTimeline
        phases={attack.phases}
        currentPhase={attack.current_phase}
        predictedNextPhase={attack.predicted_next_phase ?? null}
      />

      <TriageChecklist
        status={attack.response_status}
        onToggle={(step, value) => triageMutation.mutate({ step, value })}
        disabled={triageMutation.isPending}
      />

      {attack.analyst_summary && (
        <section
          className="vigil-card p-4 border-l-2 border-l-accent bg-accent/5"
          aria-label="Analyst summary"
        >
          <div className="text-[10px] uppercase tracking-[0.18em] text-accent-hover font-mono mb-1">
            Analyst summary
          </div>
          <div className="text-sm font-mono text-fg whitespace-pre-wrap">
            {attack.analyst_summary}
          </div>
        </section>
      )}

      <section>
        <h2 className="text-[10px] uppercase tracking-[0.18em] text-fg-faint font-mono mb-2">
          AI Narrative
        </h2>
        <div className="vigil-card p-4 text-sm font-mono whitespace-pre-wrap">
          {attack.narrative ? (
            attack.narrative
          ) : (
            <span className="text-fg-faint not-italic">
              No AI narrative generated for this attack.
            </span>
          )}
          {attack.predicted_next_phase && (
            <div className="mt-3 text-xs text-fg-muted">
              Predicted next phase:{" "}
              <span className="text-accent-hover">
                {phaseLabel(attack.predicted_next_phase)}
              </span>
            </div>
          )}
        </div>
      </section>

      <section>
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-[10px] uppercase tracking-[0.18em] text-fg-faint font-mono">
            Recommended Actions
          </h2>
          <button
            type="button"
            onClick={() => runPlaybookMutation.mutate()}
            disabled={runPlaybookMutation.isPending}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-mono border border-accent/40 bg-accent/10 text-accent-hover rounded-sm hover:bg-accent/20 disabled:opacity-50"
          >
            <Play size={12} />
            {runPlaybookMutation.isPending ? "Starting…" : "Run Playbook"}
          </button>
        </div>
        <RecommendedActions
          actions={attack.recommended_actions}
          onComplete={(idx) => actionMutation.mutate(idx)}
        />
      </section>

      <section>
        <h2 className="text-[10px] uppercase tracking-[0.18em] text-fg-faint font-mono mb-2">
          Evidence Chain ({attack.evidence.length})
        </h2>
        <EvidenceList evidence={attack.evidence} />
      </section>
    </div>
  );
}

function StatusButton({
  current,
  target,
  onClick,
  disabled,
  children,
}: {
  current: AttackStateStatus;
  target: AttackStateStatus;
  onClick: () => void;
  disabled?: boolean;
  children: React.ReactNode;
}) {
  const isActive = current === target;
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled || isActive}
      className={`vigil-badge font-mono py-1.5 px-3 text-xs ${
        isActive
          ? "border-accent bg-accent/15 text-accent-hover cursor-default"
          : "border-border-strong bg-surface-2 text-fg-muted hover:text-fg hover:border-accent/40"
      } disabled:opacity-50`}
    >
      {children}
    </button>
  );
}
