import { Check, ChevronRight } from "lucide-react";
import { phaseLabel } from "@/lib/format";
import { PHASE_ORDER } from "@/types/attacks";
import type { MITRETactic, PhaseState } from "@/types/attacks";

interface Props {
  phases: PhaseState[];
  currentPhase: MITRETactic;
  predictedNextPhase?: MITRETactic | null;
}

export function PhaseTimeline({ phases, currentPhase, predictedNextPhase }: Props) {
  const phaseMap = new Map(phases.map((p) => [p.phase, p]));
  // Skip the rare reconnaissance/resource-development phases — too long to render.
  const visible = PHASE_ORDER.slice(2);

  return (
    <div className="vigil-card p-4">
      <h3 className="text-[10px] uppercase tracking-[0.18em] text-fg-faint font-mono mb-3">
        Kill Chain Progression
      </h3>
      <ol className="flex flex-wrap items-stretch gap-1.5">
        {visible.map((phase) => {
          const ps = phaseMap.get(phase);
          const isCurrent = phase === currentPhase;
          const isObserved = ps?.status === "Observed";
          const isConfirmed = ps?.status === "Confirmed";
          const isPredicted = phase === predictedNextPhase;

          let cls = "border-border bg-surface-2 text-fg-faint";
          if (isConfirmed) cls = "border-accent/60 bg-accent/15 text-accent-hover";
          else if (isObserved)
            cls = "border-warning/40 bg-warning/10 text-warning";
          if (isCurrent) cls += " ring-1 ring-accent";
          if (isPredicted && !isCurrent && !isConfirmed && !isObserved) {
            cls = "border-indigo-500/60 bg-indigo-500/10 text-indigo-400 border-dashed";
          }

          return (
            <li
              key={phase}
              className={`flex flex-col gap-1 px-2.5 py-1.5 rounded-sm border min-w-[110px] ${cls}`}
              title={
                ps
                  ? `${ps.status} — ${pct(ps.confidence)}`
                  : isPredicted
                    ? "AI-predicted next phase"
                    : "Not observed"
              }
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-[10px] uppercase tracking-wider opacity-80">
                  {phaseLabel(phase)}
                </span>
                {isConfirmed && <Check size={11} />}
                {isPredicted && !isCurrent && !isConfirmed && !isObserved && (
                  <ChevronRight size={11} />
                )}
              </div>
              <div className="font-mono text-[9px] opacity-70">
                {ps ? ps.status : isPredicted ? "Predicted" : "—"}
              </div>
            </li>
          );
        })}
      </ol>
    </div>
  );
}

function pct(value: number): string {
  return `${Math.round(value * 100)}%`;
}
