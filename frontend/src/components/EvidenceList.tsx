import { useState } from "react";
import type { ReactNode } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { phaseColorClasses, phaseLabel, timeAgo } from "@/lib/format";
import { EnrichableValue } from "@/components/EnrichableValue";
import type { EvidenceItem } from "@/types/attacks";

interface Props {
  evidence: EvidenceItem[];
}

const COLLAPSED_COUNT = 5;

export function EvidenceList({ evidence }: Props) {
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [showAll, setShowAll] = useState(false);
  const sorted = [...evidence].sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1));

  if (sorted.length === 0) {
    return (
      <div className="vigil-card p-6 text-center text-fg-muted text-sm font-mono">
        No evidence recorded yet.
      </div>
    );
  }

  const visible = showAll ? sorted : sorted.slice(0, COLLAPSED_COUNT);
  const hidden = sorted.length - visible.length;

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
      {visible.map((item) => {
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
      {sorted.length > COLLAPSED_COUNT && (
        <button
          type="button"
          onClick={() => setShowAll((v) => !v)}
          className="w-full px-4 py-2 text-[11px] font-mono text-fg-muted hover:text-accent hover:bg-surface-2 transition-colors text-center"
        >
          {showAll
            ? `Show less — latest ${COLLAPSED_COUNT}`
            : `Show all ${sorted.length} signals (${hidden} more)`}
        </button>
      )}
    </div>
  );
}

function EvidenceDetail({ item }: { item: EvidenceItem }) {
  const rows: [string, ReactNode][] = [];
  const add = (label: string, val: unknown) => {
    if (val !== null && val !== undefined && val !== "") rows.push([label, String(val)]);
  };
  // IOC rows are enrichable in place (host/ip/destination → OSINT lookup).
  const addIoc = (label: string, display: unknown, iocValue: unknown) => {
    if (display !== null && display !== undefined && display !== "") {
      rows.push([
        label,
        iocValue ? <EnrichableValue value={String(iocValue)} /> : String(display),
      ]);
    }
  };
  const host = item.host ?? (item.entity_type === "host" ? item.entity_value : null);
  addIoc("Host", host, host);
  addIoc("IP", item.ip, item.ip);
  add("User", item.user);
  add("Process", item.process);
  add("Command line", item.command_line);
  addIoc(
    "Destination",
    item.dest_ip ? `${item.dest_ip}${item.dest_port ? `:${item.dest_port}` : ""}` : null,
    item.dest_ip,
  );
  add("Detection", item.detection_id);
  add("Rule", item.rule_name);
  add("Technique", item.technique_id);
  add("Signal ID", item.signal_id);
  add("Raw reference", item.raw_reference);

  const raw = item.raw_event ?? null;

  // High-level entities the rule keyed on — highlighted in the raw event so an
  // analyst can see exactly which parts of each event matched.
  const matchTerms = [
    item.entity_value,
    item.host,
    item.ip,
    item.user,
    item.process,
    item.dest_ip,
  ].filter((t): t is string => typeof t === "string" && t.length > 0);
  const uniqueTerms = [...new Set(matchTerms)];

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
          <div className="flex flex-wrap items-center gap-2 mb-1">
            <span className="text-[10px] uppercase tracking-wider text-fg-faint font-mono">
              Raw Event
            </span>
            {uniqueTerms.length > 0 && (
              <span className="flex flex-wrap items-center gap-1">
                <span className="text-[10px] font-mono text-fg-faint">matched:</span>
                {uniqueTerms.map((t) => (
                  <span
                    key={t}
                    className="text-[10px] font-mono px-1 rounded-sm bg-accent/20 text-accent-hover"
                  >
                    {t}
                  </span>
                ))}
              </span>
            )}
          </div>
          <pre className="text-[11px] font-mono text-fg-muted bg-bg border border-border rounded-sm p-2 overflow-x-auto">
            {highlightTerms(JSON.stringify(raw, null, 2), uniqueTerms)}
          </pre>
        </div>
      )}
    </div>
  );
}

/** Wrap occurrences of `terms` in the text with a highlight mark. Longer terms
 * match first so a host isn't partially shadowed by a shorter overlapping term. */
function highlightTerms(text: string, terms: string[]): ReactNode[] {
  const uniq = [...new Set(terms.filter(Boolean))].sort((a, b) => b.length - a.length);
  if (uniq.length === 0) return [text];
  const escaped = uniq.map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  const re = new RegExp(`(${escaped.join("|")})`, "g");
  return text.split(re).map((part, i) =>
    uniq.includes(part) ? (
      <mark key={i} className="bg-accent/25 text-accent-hover rounded-sm px-0.5">
        {part}
      </mark>
    ) : (
      <span key={i}>{part}</span>
    ),
  );
}
