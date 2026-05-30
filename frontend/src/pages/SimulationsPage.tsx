import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { FlaskConical, Play, Check, X, AlertTriangle } from "lucide-react";
import { listScenarios, runSimulation, type SimulationResult } from "@/api/simulations";
import { titleCase } from "@/lib/format";

export function SimulationsPage() {
  const [result, setResult] = useState<SimulationResult | null>(null);

  const scenarios = useQuery({ queryKey: ["sim-scenarios"], queryFn: listScenarios });

  const runMutation = useMutation({
    mutationFn: (id: string) => runSimulation(id, "PURPLE-TEAM-01"),
    onSuccess: (r) => setResult(r),
    onError: (e) => alert(`Simulation failed: ${e instanceof Error ? e.message : e}`),
  });

  return (
    <div className="px-6 py-6 max-w-[1100px] mx-auto">
      <div className="mb-2 flex items-center gap-2">
        <FlaskConical size={18} className="text-fg-muted" />
        <h1 className="text-xl font-mono text-fg">Attack Simulation</h1>
      </div>
      <p className="text-[12px] font-mono text-fg-muted mb-5 max-w-2xl">
        Agent-less purple-team. Inject a synthetic ATT&CK kill-chain into the
        live pipeline — it flows through correlation and appears in Active
        Threats — then check whether your detections would have caught it.
      </p>

      {result && <ResultPanel result={result} onClose={() => setResult(null)} />}

      {scenarios.isLoading ? (
        <div className="vigil-card p-6 text-center text-fg-muted font-mono text-sm">Loading…</div>
      ) : (
        <div className="space-y-2">
          {scenarios.data?.map((s) => (
            <div key={s.id} className="vigil-card p-4 flex items-start gap-3">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-mono text-fg">{s.name}</span>
                  <span className="text-[9px] uppercase tracking-wider px-1 py-px rounded-sm border border-accent/40 bg-accent/10 text-accent-hover">
                    {s.severity}
                  </span>
                </div>
                <div className="text-[12px] font-mono text-fg-muted mt-1">{s.description}</div>
                <div className="text-[11px] font-mono text-fg-faint mt-1">
                  {s.steps} steps · {s.phases.map((p) => titleCase(p)).join(" → ")}
                </div>
              </div>
              <button
                type="button"
                disabled={runMutation.isPending}
                onClick={() => runMutation.mutate(s.id)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-mono border border-accent/50 bg-accent/15 text-accent-hover rounded-sm hover:bg-accent/25 disabled:opacity-40"
              >
                <Play size={12} />
                {runMutation.isPending && runMutation.variables === s.id ? "Running…" : "Run"}
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function ResultPanel({ result, onClose }: { result: SimulationResult; onClose: () => void }) {
  const { coverage } = result;
  const verdictStyle =
    coverage.verdict === "pass"
      ? "border-success/40 bg-success/10 text-success"
      : coverage.verdict === "partial"
      ? "border-warning/40 bg-warning/10 text-warning"
      : "border-accent/40 bg-accent/10 text-accent-hover";

  return (
    <div className="vigil-card p-4 mb-5 border-l-2 border-l-accent">
      <div className="flex items-center justify-between mb-3">
        <div className="text-sm font-mono text-fg">{result.scenario_name}</div>
        <button type="button" onClick={onClose} className="text-fg-faint hover:text-fg">
          <X size={14} />
        </button>
      </div>
      <div className="flex flex-wrap items-center gap-3 mb-3 text-[12px] font-mono">
        <span className="text-fg-muted">
          Injected {result.emitted} events · phases{" "}
          {result.expected_phases.join(", ")}
        </span>
        <span className={`vigil-badge ${verdictStyle} uppercase`}>
          {coverage.verdict} · {coverage.covered}/{coverage.total} covered
        </span>
      </div>
      <div className="text-[10px] uppercase tracking-wider text-fg-faint font-mono mb-2">
        Detection Coverage
      </div>
      <ul className="space-y-1">
        {coverage.results.map((r) => (
          <li key={r.detection_id} className="flex items-center gap-2 text-[12px] font-mono">
            {r.covered ? (
              <Check size={13} className="text-success" />
            ) : (
              <AlertTriangle size={13} className="text-accent-hover" />
            )}
            <span className={r.covered ? "text-fg-muted" : "text-accent-hover"}>
              {r.detection_id}
            </span>
            {!r.covered && <span className="text-[10px] text-fg-faint">coverage gap</span>}
          </li>
        ))}
      </ul>
      <div className="text-[11px] font-mono text-fg-faint mt-3">
        The simulated attack now appears in Active Threats (host PURPLE-TEAM-01).
      </div>
    </div>
  );
}
