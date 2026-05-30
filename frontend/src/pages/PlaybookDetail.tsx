import type { ReactNode } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, AlertTriangle, Check, Pause, Square, XCircle } from "lucide-react";
import {
  abortPlaybook,
  getPlaybook,
  resumePlaybook,
} from "@/api/playbooks";
import { timeAgo, pct, titleCase } from "@/lib/format";
import type { ResponseAction } from "@/types/attacks";

export function PlaybookDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ["playbook", id],
    queryFn: () => getPlaybook(id!),
    enabled: !!id,
    refetchInterval: 10_000,
  });

  if (!id) {
    return (
      <div className="px-6 py-12 font-mono text-sm text-fg-muted">
        Missing run id.
      </div>
    );
  }

  async function handleResume() {
    if (!id) return;
    try {
      await resumePlaybook(id);
      await queryClient.invalidateQueries({ queryKey: ["playbook", id] });
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Resume failed";
      alert(`Resume failed: ${msg}`);
    }
  }

  async function handleAbort() {
    if (!id) return;
    if (!confirm("Abort this playbook run?")) return;
    try {
      await abortPlaybook(id);
      await queryClient.invalidateQueries({ queryKey: ["playbook", id] });
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Abort failed";
      alert(`Abort failed: ${msg}`);
    }
  }

  const run = query.data;

  return (
    <div className="px-6 py-6 max-w-[1400px] mx-auto">
      <button
        type="button"
        onClick={() => navigate("/playbooks")}
        className="mb-4 flex items-center gap-1 text-[12px] font-mono text-fg-muted hover:text-fg"
      >
        <ArrowLeft size={13} /> Back to Playbooks
      </button>

      {query.isLoading ? (
        <div className="vigil-card p-8 text-center text-fg-muted font-mono text-sm">
          Loading...
        </div>
      ) : query.isError || !run ? (
        <div className="vigil-card p-8 text-center text-accent font-mono text-sm">
          Failed to load run.
        </div>
      ) : (
        <>
          <div className="vigil-card p-4 mb-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h1
                  className="text-xl font-mono text-fg"
                  title={`Temporal workflow: ${run.workflow_id}`}
                >
                  Run {run.run_id.slice(0, 8)}
                </h1>
                <div className="text-[11px] font-mono text-fg-muted mt-1">
                  Triggered {run.triggered_at ? timeAgo(run.triggered_at) : "—"}
                </div>
              </div>
              <div className="flex flex-col items-end gap-1">
                <span
                  className={`vigil-badge ${
                    run.status === "running"
                      ? "border-info/40 bg-info/10 text-info"
                      : run.status === "completed"
                      ? "border-success/40 bg-success/10 text-success"
                      : run.status === "failed"
                      ? "border-accent/40 bg-accent/10 text-accent-hover"
                      : "border-warning/40 bg-warning/10 text-warning"
                  }`}
                >
                  {titleCase(run.status)}
                </span>
                <span className="text-[11px] font-mono text-fg-muted tabular-nums">
                  {titleCase(run.phase_at_trigger)} • {pct(run.confidence_at_trigger)}
                </span>
              </div>
            </div>
          </div>

          {run.status === "paused" && (
            <Banner
              tone="warning"
              icon={<AlertTriangle size={16} />}
              title="Workflow paused"
              detail="An action failed and is awaiting analyst intervention."
              actions={
                <>
                  <button
                    type="button"
                    onClick={handleResume}
                    className="inline-flex items-center gap-1 px-3 py-1 text-[12px] font-mono border border-success/40 bg-success/10 text-success rounded-sm hover:bg-success/20"
                  >
                    <Pause size={12} /> Resume
                  </button>
                  <button
                    type="button"
                    onClick={handleAbort}
                    className="inline-flex items-center gap-1 px-3 py-1 text-[12px] font-mono border border-accent/40 bg-accent/10 text-accent-hover rounded-sm hover:bg-accent/20"
                  >
                    <Square size={12} /> Abort
                  </button>
                </>
              }
            />
          )}

          {run.status === "failed" && (
            <Banner
              tone="danger"
              icon={<XCircle size={16} />}
              title="Workflow failed"
              detail="The run was aborted or hit a terminal failure."
            />
          )}

          <ActionSection
            title="Enrichment"
            subtitle="read-only context — runs first, automatically"
            actions={run.actions.filter((a) => a.kind === "enrichment")}
            completedActions={run.completed_actions}
          />

          <ActionSection
            title="Response"
            subtitle="state-changing — runs after enrichment"
            actions={run.actions.filter((a) => a.kind !== "enrichment")}
            completedActions={run.completed_actions}
          />
        </>
      )}
    </div>
  );
}

function Banner({
  tone,
  icon,
  title,
  detail,
  actions,
}: {
  tone: "warning" | "danger";
  icon: ReactNode;
  title: string;
  detail: string;
  actions?: ReactNode;
}) {
  const cls =
    tone === "warning"
      ? "border-warning/40 bg-warning/10 text-warning"
      : "border-accent/40 bg-accent/10 text-accent-hover";
  return (
    <div className={`vigil-card border ${cls} p-3 mb-4 flex items-start gap-3`}>
      <div className="mt-0.5">{icon}</div>
      <div className="flex-1">
        <div className="text-sm font-mono">{title}</div>
        <div className="text-[12px] font-mono text-fg-muted mt-0.5">{detail}</div>
      </div>
      {actions && <div className="flex gap-2 self-center">{actions}</div>}
    </div>
  );
}

function ActionSection({
  title,
  subtitle,
  actions,
  completedActions,
}: {
  title: string;
  subtitle?: string;
  actions: ResponseAction[];
  completedActions: ResponseAction[];
}) {
  if (actions.length === 0) {
    return null;
  }

  function isCompleted(a: ResponseAction): boolean {
    if (a.completed) return true;
    return completedActions.some(
      (c) =>
        c.action_type === a.action_type && c.target_entity === a.target_entity,
    );
  }

  return (
    <div className="vigil-card p-4 mb-3">
      <div className="mb-3">
        <div className="text-[11px] uppercase font-mono text-fg-faint tracking-wider">
          {title} ({actions.length})
        </div>
        {subtitle && (
          <div className="text-[10px] font-mono text-fg-faint/70 mt-0.5">{subtitle}</div>
        )}
      </div>
      <ul className="space-y-2">
        {actions.map((a, idx) => {
          const done = isCompleted(a);
          return (
            <li
              key={`${a.action_type}-${a.target_entity}-${idx}`}
              className="flex items-start gap-3 px-3 py-2 border border-border rounded-sm bg-surface"
            >
              <div
                className={`w-5 h-5 mt-0.5 flex items-center justify-center rounded-sm border ${
                  done
                    ? "border-success bg-success/10 text-success"
                    : "border-border-strong bg-surface-2 text-fg-faint"
                }`}
              >
                {done ? <Check size={12} /> : null}
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-mono text-fg">{titleCase(a.action_type)}</span>
                  {a.priority === "immediate" && (
                    <span className="text-[9px] font-mono uppercase tracking-wider px-1 py-px rounded-sm border border-accent/40 bg-accent/10 text-accent-hover">
                      immediate
                    </span>
                  )}
                </div>
                <div className="text-[12px] font-mono text-fg-muted">
                  {a.target_entity} • {a.description}
                </div>
                {done && a.completed_at && (
                  <div className="text-[11px] font-mono text-fg-faint mt-0.5">
                    completed {timeAgo(a.completed_at)}
                  </div>
                )}
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
