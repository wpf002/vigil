import { useState } from "react";
import type { ReactNode } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { phaseColorClasses, phaseLabel, timeAgo } from "@/lib/format";
import type { EvidenceItem } from "@/types/attacks";

interface Props {
  evidence: EvidenceItem[];
}

export function EvidenceList({ evidence }: Props) {
  const [open, setOpen] = useState<Set<string>>(new Set());
  const sorted = [...evidence].sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1));

  if (sorted.length === 0) {
    return (
      <div className="vigil-card p-6 text-center text-fg-muted text-sm font-mono">
        No evidence recorded yet.
      </div>
    );
  }

  function toggle(id: string) {
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  return (
    <div className="vigil-card divide-y divide-border">
      {sorted.map((item) => {
        const isOpen = open.has(item.evidence_id);
        return (
          <div key={item.evidence_id}>
            <button
              type="button"
              onClick={() => toggle(item.evidence_id)}
              aria-expanded={isOpen}
              className="w-full text-left px-4 py-3 grid grid-cols-[16px_120px_1fr_auto] gap-3 items-start hover:bg-surface-2 transition-colors"
            >
              <span className="mt-0.5 text-fg-faint">
                {isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              </span>
              <span className="text-[11px] font-mono text-fg-faint">
                {timeAgo(item.timestamp)}
              </span>
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
                  {item.severity && (
                    <span className="vigil-badge border-border-strong bg-surface-2 text-fg-faint uppercase">
                      {item.severity}
                    </span>
                  )}
                </div>
                <div className="text-sm font-mono text-fg truncate">
                  {item.title ?? item.rule_name ?? item.detection_id ?? "Unknown rule"}
                </div>
                <div className="mt-1 text-[11px] text-fg-faint font-mono space-x-3">
                  <span>
                    <span className="opacity-60">{item.entity_type}:</span>{" "}
                    <span className="text-fg-muted">{item.entity_value}</span>
                  </span>
                  <span>{item.source_siem}</span>
                </div>
              </div>
              <span className="text-right text-[11px] font-mono text-fg-muted whitespace-nowrap">
                +{Math.round(item.confidence_contribution * 100)}%
              </span>
            </button>
            {isOpen && <EvidenceDetail item={item} />}
          </div>
        );
      })}
    </div>
  );
}

function EvidenceDetail({ item }: { item: EvidenceItem }) {
  const rows: [string, ReactNode][] = [];
  const add = (label: string, val: unknown) => {
    if (val !== null && val !== undefined && val !== "") rows.push([label, String(val)]);
  };
  add("Host", item.host ?? (item.entity_type === "host" ? item.entity_value : null));
  add("IP", item.ip);
  add("User", item.user);
  add("Process", item.process);
  add("Command line", item.command_line);
  add(
    "Destination",
    item.dest_ip ? `${item.dest_ip}${item.dest_port ? `:${item.dest_port}` : ""}` : null,
  );
  add("Detection", item.detection_id);
  add("Rule", item.rule_name);
  add("Technique", item.technique_id);
  add("Signal ID", item.signal_id);
  add("Raw reference", item.raw_reference);

  const raw = item.raw_event ?? null;

  return (
    <div className="px-4 pb-4 pt-1 bg-surface-2/40">
      {item.description && (
        <div className="text-[12px] font-mono text-fg-muted mb-3">{item.description}</div>
      )}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1">
        {rows.map(([label, val]) => (
          <div key={label} className="flex gap-2 text-[11px] font-mono">
            <span className="text-fg-faint w-28 shrink-0">{label}</span>
            <span className="text-fg-muted break-all">{val}</span>
          </div>
        ))}
      </div>
      {raw && Object.keys(raw).length > 0 && (
        <div className="mt-3">
          <div className="text-[10px] uppercase tracking-wider text-fg-faint font-mono mb-1">
            Raw Event
          </div>
          <pre className="text-[11px] font-mono text-fg-muted bg-bg border border-border rounded-sm p-2 overflow-x-auto">
            {JSON.stringify(raw, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
