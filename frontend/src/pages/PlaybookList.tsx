import { useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ListChecks, Pause, Square, Wrench } from "lucide-react";
import {
  abortPlaybook,
  listPlaybooks,
  resumePlaybook,
} from "@/api/playbooks";
import { timeAgo, pct, titleCase } from "@/lib/format";
import type { PlaybookRun, PlaybookStatus } from "@/types/playbooks";

const STATUS_CLASSES: Record<PlaybookStatus, string> = {
  running: "border-info/40 bg-info/10 text-info",
  completed: "border-success/40 bg-success/10 text-success",
  failed: "border-accent/40 bg-accent/10 text-accent-hover",
  paused: "border-warning/40 bg-warning/10 text-warning",
};

export function PlaybookList() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ["playbooks"],
    queryFn: listPlaybooks,
    refetchInterval: 30_000,
  });

  const runs = query.data ?? [];

  async function handleResume(runId: string) {
    try {
      await resumePlaybook(runId);
      await queryClient.invalidateQueries({ queryKey: ["playbooks"] });
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Resume failed";
      alert(`Resume failed: ${msg}`);
    }
  }

  async function handleAbort(runId: string) {
    if (!confirm("Abort this playbook run?")) return;
    try {
      await abortPlaybook(runId);
      await queryClient.invalidateQueries({ queryKey: ["playbooks"] });
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Abort failed";
      alert(`Abort failed: ${msg}`);
    }
  }

  return (
    <div className="px-6 py-6 max-w-[1400px] mx-auto">
      <div className="mb-5 flex items-center gap-2">
        <ListChecks size={18} className="text-fg-muted" />
        <h1 className="text-xl font-mono text-fg">Response Playbooks</h1>
        <span className="ml-auto text-[11px] font-mono text-fg-faint tabular-nums">
          {runs.length} {runs.length === 1 ? "Run" : "Runs"}
        </span>
        <button
          type="button"
          onClick={() => navigate("/playbooks/build")}
          className="inline-flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-mono border border-border-strong bg-surface-2 text-fg-muted rounded-sm hover:text-fg hover:border-accent/40"
        >
          <Wrench size={12} /> Build Playbook
        </button>
      </div>
      <p className="text-[12px] font-mono text-fg-muted mb-4 -mt-3 max-w-3xl">
        Automated <span className="text-fg">response</span> runs — the actions
        taken when a detection fires an attack. Author them in Build Playbook.
        (Detections, the thing that fires, live under Detections/Marketplace.)
      </p>

      {query.isLoading ? (
        <div className="vigil-card p-8 text-center text-fg-muted font-mono text-sm">
          Loading playbook runs...
        </div>
      ) : query.isError ? (
        <div className="vigil-card p-8 text-center text-accent font-mono text-sm">
          Failed to load runs.
        </div>
      ) : runs.length === 0 ? (
        <div className="vigil-card p-8 text-center text-fg-muted font-mono text-sm">
          No playbook runs yet. They start automatically when an attack escalates.
        </div>
      ) : (
        <div className="vigil-card overflow-hidden">
          <table className="w-full text-sm font-mono">
            <thead className="bg-surface-2 border-b border-border">
              <tr className="text-left text-[11px] uppercase tracking-wider text-fg-faint">
                <th className="px-3 py-2">Phase at Trigger</th>
                <th className="px-3 py-2 text-right">Confidence</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2 text-right">Actions</th>
                <th className="px-3 py-2">Triggered</th>
                <th className="px-3 py-2 text-right">Controls</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((r) => (
                <PlaybookRow
                  key={r.run_id}
                  run={r}
                  onClick={() => navigate(`/playbooks/${r.run_id}`)}
                  onResume={() => handleResume(r.run_id)}
                  onAbort={() => handleAbort(r.run_id)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function PlaybookRow({
  run,
  onClick,
  onResume,
  onAbort,
}: {
  run: PlaybookRun;
  onClick: () => void;
  onResume: () => void;
  onAbort: () => void;
}) {
  const completed = run.completed_actions.length;
  const total = run.actions.length;

  return (
    <tr
      onClick={onClick}
      className="border-b border-border last:border-0 hover:bg-surface-2 cursor-pointer transition-colors"
    >
      <td className="px-3 py-2 text-fg-muted">{titleCase(run.phase_at_trigger)}</td>
      <td className="px-3 py-2 text-right tabular-nums text-fg">
        {pct(run.confidence_at_trigger)}
      </td>
      <td className="px-3 py-2">
        <span className={`vigil-badge ${STATUS_CLASSES[run.status]}`}>
          {titleCase(run.status)}
        </span>
      </td>
      <td className="px-3 py-2 text-right tabular-nums text-fg-muted">
        {completed}/{total}
      </td>
      <td className="px-3 py-2 text-fg-muted">
        {run.triggered_at ? timeAgo(run.triggered_at) : "—"}
      </td>
      <td
        className="px-3 py-2 text-right"
        onClick={(e) => e.stopPropagation()}
      >
        {run.status === "paused" ? (
          <div className="inline-flex gap-3 justify-end">
            <button
              type="button"
              onClick={onResume}
              className="inline-flex items-center gap-1 text-[12px] font-mono text-fg-muted hover:text-success"
            >
              <Pause size={12} /> Resume
            </button>
            <button
              type="button"
              onClick={onAbort}
              className="inline-flex items-center gap-1 text-[12px] font-mono text-fg-muted hover:text-accent"
            >
              <Square size={12} /> Abort
            </button>
          </div>
        ) : run.status === "running" ? (
          <button
            type="button"
            onClick={onAbort}
            className="inline-flex items-center gap-1 text-[12px] font-mono text-fg-muted hover:text-accent"
          >
            <Square size={12} /> Abort
          </button>
        ) : (
          <span className="text-[11px] font-mono text-fg-faint">—</span>
        )}
      </td>
    </tr>
  );
}
