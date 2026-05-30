import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { listAttacks } from "@/api/attacks";
import { AttackCard } from "@/components/AttackCard";
import { StatsBanner } from "@/components/StatsBanner";
import { PHASE_ORDER } from "@/types/attacks";
import type { AttackListFilters, MITRETactic, Momentum } from "@/types/attacks";
import { phaseLabel } from "@/lib/format";

const EMPTY_FILTERS: AttackListFilters = {
  phase: null,
  min_confidence: 0,
  momentum: null,
  limit: 50,
  offset: 0,
};

export function AttackList({ resolved = false }: { resolved?: boolean } = {}) {
  // Filters are local to this view instance so the Active and Resolved lists
  // never share filter state (previously a global store leaked Active filters
  // into the Resolved query, hiding resolved attacks).
  const [filters, setFilters] = useState<AttackListFilters>(EMPTY_FILTERS);
  const setPhaseFilter = (phase: MITRETactic | null) =>
    setFilters((f) => ({ ...f, phase }));
  const setMomentumFilter = (momentum: Momentum | null) =>
    setFilters((f) => ({ ...f, momentum }));
  const setMinConfidence = (value: number) =>
    setFilters((f) => ({ ...f, min_confidence: value }));
  const resetFilters = () => setFilters(EMPTY_FILTERS);

  const filtersActive =
    filters.phase != null ||
    filters.momentum != null ||
    (filters.min_confidence ?? 0) > 0;

  // On the Resolved (history) view, fetch resolved/contained attacks instead
  // of the default active-only set.
  const effectiveFilters = resolved
    ? { ...filters, status: "all", limit: 200 }
    : filters;

  const query = useQuery({
    queryKey: ["attacks", resolved ? "history" : "active", effectiveFilters],
    queryFn: () => listAttacks(effectiveFilters),
    refetchInterval: 30_000,
  });

  const allResults = query.data ?? [];
  const attacks = resolved
    ? allResults.filter((a) => a.status !== "active")
    : allResults;

  return (
    <div className="px-6 py-6 max-w-[1400px] mx-auto">
      <div className="mb-5">
        <h1 className="text-xl font-mono text-fg">
          {resolved ? "Resolved" : "Active Threats"}
        </h1>
      </div>

      {!resolved && <StatsBanner />}

      <div className="mb-3 flex flex-wrap items-center gap-3 px-3 py-2 border border-border rounded bg-surface">
        <select
          aria-label="Filter by attack phase"
          className="vigil-input py-1 text-xs"
          value={filters.phase ?? ""}
          onChange={(e) =>
            setPhaseFilter((e.target.value || null) as MITRETactic | null)
          }
        >
          <option value="">All Phases</option>
          {PHASE_ORDER.map((p) => (
            <option key={p} value={p}>
              {phaseLabel(p)}
            </option>
          ))}
        </select>

        <select
          aria-label="Filter by momentum"
          className="vigil-input py-1 text-xs"
          value={filters.momentum ?? ""}
          onChange={(e) =>
            setMomentumFilter((e.target.value || null) as Momentum | null)
          }
        >
          <option value="">All Momentum</option>
          <option value="Increasing">Increasing</option>
          <option value="Stable">Stable</option>
          <option value="Decreasing">Decreasing</option>
        </select>

        <div className="inline-flex items-center gap-2 text-xs font-mono text-fg-muted">
          <span>Confidence ≥</span>
          <input
            type="range"
            aria-label="Minimum confidence threshold"
            min={0}
            max={1}
            step={0.05}
            value={filters.min_confidence ?? 0}
            onChange={(e) => setMinConfidence(parseFloat(e.target.value))}
            className="accent-accent w-28"
          />
          <span className="text-fg w-9 text-right tabular-nums">
            {Math.round((filters.min_confidence ?? 0) * 100)}%
          </span>
        </div>

        <div className="flex-1" />

        {filtersActive && (
          <button
            type="button"
            onClick={resetFilters}
            className="text-[11px] font-mono text-fg-muted hover:text-accent"
          >
            Clear
          </button>
        )}

        <span className="text-[11px] font-mono text-fg-faint tabular-nums">
          {attacks.length} {attacks.length === 1 ? "Threat" : "Threats"}
        </span>
      </div>

      {query.isLoading ? (
        <SkeletonList />
      ) : query.isError ? (
        <div className="vigil-card p-6 border-accent/40 bg-accent/5 text-accent font-mono text-sm">
          Failed To Load Threats: {(query.error as Error).message}
        </div>
      ) : attacks.length === 0 ? (
        <EmptyState filtersActive={filtersActive} onReset={resetFilters} resolved={resolved} />
      ) : (
        <ol className="space-y-1.5">
          {attacks.map((a) => (
            <li key={a.attack_id}>
              <AttackCard attack={a} />
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

function EmptyState({
  filtersActive,
  onReset,
  resolved = false,
}: {
  filtersActive: boolean;
  onReset: () => void;
  resolved?: boolean;
}) {
  if (filtersActive) {
    return (
      <div className="vigil-card p-12 text-center font-mono">
        <div className="text-fg text-sm">No Threats Match These Filters.</div>
        <button
          type="button"
          onClick={onReset}
          className="mt-3 text-xs text-accent hover:text-accent-hover"
        >
          Clear Filters
        </button>
      </div>
    );
  }
  if (resolved) {
    return (
      <div className="vigil-card p-12 text-center font-mono">
        <div className="text-fg text-sm">No Resolved Attacks Yet.</div>
        <div className="text-fg-muted text-xs mt-2 max-w-md mx-auto">
          Attacks Appear Here Once They Are Contained Or Resolved.
        </div>
      </div>
    );
  }
  return (
    <div className="vigil-card p-12 text-center font-mono">
      <div className="text-fg text-sm">No Active Threats.</div>
      <div className="text-fg-muted text-xs mt-2 max-w-md mx-auto">
        The Correlation Engine Is Listening For Detection Signals.
      </div>
    </div>
  );
}

function SkeletonList() {
  return (
    <div className="space-y-1.5">
      {[0, 1, 2].map((i) => (
        <div
          key={i}
          className="vigil-card p-4 animate-pulse-soft h-[88px]"
          aria-hidden
        />
      ))}
    </div>
  );
}
