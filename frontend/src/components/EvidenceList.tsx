import { phaseColorClasses, phaseLabel, timeAgo } from "@/lib/format";
import type { EvidenceItem } from "@/types/attacks";

interface Props {
  evidence: EvidenceItem[];
}

export function EvidenceList({ evidence }: Props) {
  const sorted = [...evidence].sort((a, b) =>
    a.timestamp < b.timestamp ? 1 : -1,
  );

  if (sorted.length === 0) {
    return (
      <div className="vigil-card p-6 text-center text-fg-muted text-sm font-mono">
        No evidence recorded yet.
      </div>
    );
  }

  return (
    <div className="vigil-card divide-y divide-border">
      {sorted.map((item) => (
        <article
          key={item.evidence_id}
          className="px-4 py-3 grid grid-cols-[140px_1fr_auto] gap-4 items-start hover:bg-surface-2 transition-colors"
        >
          <div className="text-[11px] font-mono text-fg-faint">
            {timeAgo(item.timestamp)}
          </div>

          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-1.5 mb-1">
              <span className={`vigil-badge ${phaseColorClasses(item.phase)}`}>
                {phaseLabel(item.phase)}
              </span>
              <span
                className={`vigil-badge ${
                  item.status_contributed === "Confirmed"
                    ? "border-accent/40 bg-accent/10 text-accent-hover"
                    : "border-warning/40 bg-warning/10 text-warning"
                }`}
              >
                {item.status_contributed}
              </span>
              {item.technique_id && (
                <span className="vigil-badge border-border-strong bg-surface-2 text-fg-muted">
                  {item.technique_id}
                </span>
              )}
            </div>
            <div
              className="text-sm font-mono text-fg truncate"
              title={item.raw_reference ?? undefined}
            >
              {item.rule_name ?? item.detection_id ?? "Unknown rule"}
            </div>
            <div className="mt-1 text-[11px] text-fg-faint font-mono space-x-3">
              <span>
                <span className="opacity-60">{item.entity_type}:</span>{" "}
                <span className="text-fg-muted">{item.entity_value}</span>
              </span>
              <span>{item.source_siem}</span>
            </div>
          </div>

          <div className="text-right text-[11px] font-mono text-fg-muted whitespace-nowrap">
            +{Math.round(item.confidence_contribution * 100)}%
          </div>
        </article>
      ))}
    </div>
  );
}
