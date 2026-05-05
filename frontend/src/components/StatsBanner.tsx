import { useQuery } from "@tanstack/react-query";
import { getStatsSummary } from "@/api/attacks";
import { phaseLabel } from "@/lib/format";

export function StatsBanner() {
  const query = useQuery({
    queryKey: ["attacks", "summary"],
    queryFn: getStatsSummary,
    refetchInterval: 30_000,
  });

  const summary = query.data;
  const total = summary?.total_active ?? 0;
  const dist = summary?.confidence_distribution;
  const critical = (dist?.critical ?? 0) + (dist?.high ?? 0);
  const increasing = summary?.momentum_breakdown?.["Increasing"] ?? 0;
  const phaseEntries = Object.entries(summary?.phase_breakdown ?? {}).sort(
    (a, b) => b[1] - a[1],
  );

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-px bg-border border border-border rounded mb-6 overflow-hidden">
      <Stat label="Active" value={total} />
      <Stat label="Critical" value={critical} accent={critical > 0} />
      <Stat label="Escalating" value={increasing} accent={increasing > 0} />
      <PhaseDistribution entries={phaseEntries} total={total} />
    </div>
  );
}

function Stat({
  label,
  value,
  accent = false,
}: {
  label: string;
  value: number;
  accent?: boolean;
}) {
  return (
    <div className="bg-surface px-5 py-4">
      <div className="text-[10px] uppercase tracking-[0.18em] text-fg-faint font-mono">
        {label}
      </div>
      <div
        className={`text-4xl font-mono tabular-nums mt-1 ${
          accent ? "text-accent-hover" : value === 0 ? "text-fg-faint" : "text-fg"
        }`}
      >
        {value}
      </div>
    </div>
  );
}

function PhaseDistribution({
  entries,
  total,
}: {
  entries: [string, number][];
  total: number;
}) {
  return (
    <div className="bg-surface px-5 py-4">
      <div className="text-[10px] uppercase tracking-[0.18em] text-fg-faint font-mono">
        Top Phases
      </div>
      {entries.length === 0 ? (
        <div className="text-fg-faint font-mono text-2xl mt-1">—</div>
      ) : (
        <div className="flex flex-col gap-1 mt-2">
          {entries.slice(0, 3).map(([phase, n]) => {
            const width = total > 0 ? (n / total) * 100 : 0;
            return (
              <div key={phase} className="text-[11px] font-mono">
                <div className="flex justify-between text-fg-muted mb-0.5">
                  <span className="truncate">
                    {phaseLabel(phase as never)}
                  </span>
                  <span className="text-fg tabular-nums">{n}</span>
                </div>
                <div className="h-0.5 bg-surface-2">
                  <div
                    className="h-full bg-accent/70"
                    style={{ width: `${width}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
