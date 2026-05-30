import { Link } from "react-router-dom";
import { ChevronRight } from "lucide-react";
import {
  impactColorClasses,
  phaseColorClasses,
  phaseLabel,
  pct,
  timeAgo,
} from "@/lib/format";
import type { AttackState } from "@/types/attacks";
import { MomentumIndicator } from "./MomentumIndicator";

interface Props {
  attack: AttackState;
}

const MAX_ENTITIES = 3;

function entitySummary(attack: AttackState) {
  const entities = [
    ...(attack.hosts ?? []).map((v) => ({ type: "Host", value: v })),
    ...(attack.users ?? []).map((v) => ({ type: "User", value: v })),
    ...(attack.processes ?? []).map((v) => ({ type: "Proc", value: v })),
  ];
  const shown = entities.slice(0, MAX_ENTITIES);
  const remaining = entities.length - shown.length;
  return { shown, remaining };
}

export function AttackCard({ attack }: Props) {
  const { shown, remaining } = entitySummary(attack);
  const isCritical = attack.confidence >= 0.7;
  const confidenceColor = isCritical
    ? "text-accent-hover"
    : attack.confidence >= 0.5
      ? "text-warning"
      : "text-fg-muted";

  return (
    <Link
      to={`/attacks/${attack.attack_id}`}
      className={`group block bg-surface border border-border rounded hover:border-accent/60 hover:bg-surface-2 transition-colors ${
        isCritical ? "border-l-2 border-l-accent" : ""
      }`}
    >
      <div className="grid grid-cols-[80px_1fr_auto] items-center gap-4 px-4 py-3">
        <div className="text-center">
          <div
            className={`font-mono text-3xl tabular-nums leading-none ${confidenceColor}`}
          >
            {pct(attack.confidence)}
          </div>
          <div className="text-[9px] uppercase tracking-wider text-fg-faint mt-1">
            Confidence
          </div>
        </div>

        <div className="min-w-0">
          <h3 className="font-mono text-sm text-fg truncate mb-1.5">
            {attack.name}
          </h3>
          <div className="flex flex-wrap items-center gap-1">
            <span
              className={`vigil-badge ${phaseColorClasses(attack.current_phase)}`}
            >
              {phaseLabel(attack.current_phase)}
            </span>
            <span className={`vigil-badge ${impactColorClasses(attack.impact)}`}>
              {attack.impact}
            </span>
            <MomentumIndicator momentum={attack.momentum} />
            {shown.map((e) => (
              <span
                key={`${e.type}:${e.value}`}
                className="vigil-badge border-border bg-surface-2 text-fg-muted"
              >
                <span className="text-fg-faint mr-1">{e.type}</span>
                {e.value}
              </span>
            ))}
            {remaining > 0 && (
              <span className="text-[11px] text-fg-faint font-mono">
                +{remaining}
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-4 shrink-0">
          <div className="text-right text-[10px] text-fg-faint font-mono leading-relaxed whitespace-nowrap">
            <div className="text-fg-muted">{timeAgo(attack.last_seen)}</div>
            <div>
              {attack.evidence?.length ?? 0}{" "}
              {(attack.evidence?.length ?? 0) === 1 ? "Signal" : "Signals"}
            </div>
          </div>

          <div className="inline-flex items-center gap-1 text-[11px] font-mono text-fg-muted group-hover:text-accent-hover transition-colors">
            <span>Investigate</span>
            <ChevronRight size={13} />
          </div>
        </div>
      </div>
    </Link>
  );
}
