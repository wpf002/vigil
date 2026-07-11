import { useMemo, useState } from "react";
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

const STATUS_OPTIONS: PlaybookStatus[] = [
  "running",
  "completed",
  "failed",
  "paused",
];
const PAGE_SIZE = 25;

export function PlaybookList() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [statusFilter, setStatusFilter] = useState<PlaybookStatus | "">("");
  const [phaseFilter, setPhaseFilter] = useState<string>("");
  const [page, setPage] = useState(0);

  const query = useQuery({
    queryKey: ["playbooks"],
    queryFn: listPlaybooks,
    refetchInterval: 30_000,
  });

  const allRuns = query.data ?? [];

  // Phase options derived from the data so the dropdown only shows real phases.
  const phaseOptions = useMemo(
    () =>
      Array.from(new Set(allRuns.map((r) => r.phase_at_trigger))).sort(),
    [allRuns],
  );

  const filtered = useMemo(
    () =>
      allRuns.filter(
        (r) =>
          (statusFilter === "" || r.status === statusFilter) &&
          (phaseFilter === "" || r.phase_at_trigger === phaseFilter),
      ),
    [allRuns, statusFilter, phaseFilter],
  );

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(page, pageCount - 1);
  const runs = filtered.slice(safePage * PAGE_SIZE, (safePage + 1) * PAGE_SIZE);
  const filtersActive = statusFilter !== "" || phaseFilter !== "";

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
          {filtered.length} {filtered.length === 1 ? "Run" : "Runs"}
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

      <div className="mb-3 flex flex-wrap items-center gap-3 px-3 py-2 border border-border rounded bg-surface">
        <select
          aria-label="Filter by status"
          className="vigil-input py-1 text-xs"
          value={statusFilter}
          onChange={(e) => {
            setStatusFilter(e.target.value as PlaybookStatus | "");
            setPage(0);
          }}
        >
          <option value="">All Statuses</option>
          {STATUS_OPTIONS.map((s) => (
            <option key={s} value={s}>
              {titleCase(s)}
            </option>
          ))}
        </select>

        <select
          aria-label="Filter by trigger phase"
          className="vigil-input py-1 text-xs"
          value={phaseFilter}
          onChange={(e) => {
            setPhaseFilter(e.target.value);
            setPage(0);
          }}
        >
          <option value="">All Phases</option>
          {phaseOptions.map((p) => (
            <option key={p} value={p}>
              {titleCase(p)}
            </option>
          ))}
        </select>

        <div className="flex-1" />

        {filtersActive && (
          <button
            type="button"
            onClick={() => {
              setStatusFilter("");
              setPhaseFilter("");
              setPage(0);
            }}
            className="text-[11px] font-mono text-fg-muted hover:text-accent"
          >
            Clear
          </button>
        )}
      </div>

      {query.isLoading ? (
        <div className="vigil-card p-8 text-center text-fg-muted font-mono text-sm">
          Loading playbook runs...
        </div>
      ) : query.isError ? (
        <div className="vigil-card p-8 text-center text-accent font-mono text-sm">
          Failed to load runs.
        </div>
      ) : filtered.length === 0 ? (
        <div className="vigil-card p-8 text-center text-fg-muted font-mono text-sm">
          {filtersActive
            ? "No playbook runs match these filters."
            : "No playbook runs yet. They start automatically when an attack escalates."}
        </div>
      ) : (
        <>
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

          {filtered.length > PAGE_SIZE && (
            <div className="mt-4 flex items-center justify-between px-3 py-2 border border-border rounded bg-surface font-mono text-[11px] text-fg-muted">
              <span className="tabular-nums">
                {safePage * PAGE_SIZE + 1}–
                {Math.min((safePage + 1) * PAGE_SIZE, filtered.length)} of{" "}
                {filtered.length}
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={safePage === 0}
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  className="px-2 py-1 rounded-sm border border-border text-fg-muted hover:text-fg hover:border-accent/40 disabled:opacity-30"
                >
                  Prev
                </button>
                <span className="tabular-nums text-fg-faint">
                  Page {safePage + 1} / {pageCount}
                </span>
                <button
                  type="button"
                  disabled={safePage + 1 >= pageCount}
                  onClick={() => setPage((p) => p + 1)}
                  className="px-2 py-1 rounded-sm border border-border text-fg-muted hover:text-fg hover:border-accent/40 disabled:opacity-30"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </>
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
