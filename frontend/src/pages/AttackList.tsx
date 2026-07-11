import { useState } from "react";
import { useQuery, keepPreviousData } from "@tanstack/react-query";
import { listAttacks, listAttacksPaged } from "@/api/attacks";
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

const PAGE_SIZE = 50;

export function AttackList({ resolved = false }: { resolved?: boolean } = {}) {
  // Filters are local to this view instance so the Active and Resolved lists
  // never share filter state (previously a global store leaked Active filters
  // into the Resolved query, hiding resolved attacks).
  const [filters, setFilters] = useState<AttackListFilters>(EMPTY_FILTERS);
  // Resolved view paginates server-side (the history set can be hundreds deep).
  const [page, setPage] = useState(0);
  const resetPage = () => setPage(0);
  const setPhaseFilter = (phase: MITRETactic | null) => {
    setFilters((f) => ({ ...f, phase }));
    resetPage();
  };
  const setMomentumFilter = (momentum: Momentum | null) => {
    setFilters((f) => ({ ...f, momentum }));
    resetPage();
  };
  const setMinConfidence = (value: number) => {
    setFilters((f) => ({ ...f, min_confidence: value }));
    resetPage();
  };
  const resetFilters = () => {
    setFilters(EMPTY_FILTERS);
    resetPage();
  };

  const filtersActive =
    filters.phase != null ||
    filters.momentum != null ||
    (filters.min_confidence ?? 0) > 0;

  // Resolved view: fetch the "inactive" set (resolved/contained/false-positive)
  // one page at a time, server-side. Active view: default active-only set.
  const pagedFilters = {
    ...filters,
    status: "inactive",
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  };

  const query = useQuery({
    queryKey: [
      "attacks",
      resolved ? "history" : "active",
      resolved ? pagedFilters : filters,
    ],
    queryFn: () =>
      resolved
        ? listAttacksPaged(pagedFilters)
        : listAttacks(filters).then((items) => ({ items, total: items.length })),
    refetchInterval: 30_000,
    placeholderData: resolved ? keepPreviousData : undefined,
  });

  const attacks = query.data?.items ?? [];
  const total = query.data?.total ?? 0;
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="px-6 py-6 max-w-[1400px] mx-auto">
      <div className="mb-5">
        <h1 className="text-xl font-mono text-fg">
          {resolved ? "Resolved" : "Active Threats"}
        </h1>
        {resolved && (
          <p className="text-[12px] font-mono text-fg-muted mt-1 max-w-3xl">
            Attacks that are no longer active. Each row's badge shows how it
            closed — <span className="text-success">Resolved</span> (analyst
            closed it), <span className="text-info">Contained</span> (stopped
            mid-attack), or{" "}
            <span className="text-fg">False Positive</span>. Click any row to open
            the full attack and its historical evidence chain.
          </p>
        )}
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
          {resolved ? total : attacks.length}{" "}
          {(resolved ? total : attacks.length) === 1 ? "Threat" : "Threats"}
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

      {resolved && total > PAGE_SIZE && (
        <div className="mt-4 flex items-center justify-between px-3 py-2 border border-border rounded bg-surface font-mono text-[11px] text-fg-muted">
          <span className="tabular-nums">
            {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, total)} of{" "}
            {total}
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={page === 0}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              className="px-2 py-1 rounded-sm border border-border text-fg-muted hover:text-fg hover:border-accent/40 disabled:opacity-30 disabled:hover:text-fg-muted disabled:hover:border-border"
            >
              Prev
            </button>
            <span className="tabular-nums text-fg-faint">
              Page {page + 1} / {pageCount}
            </span>
            <button
              type="button"
              disabled={page + 1 >= pageCount}
              onClick={() => setPage((p) => p + 1)}
              className="px-2 py-1 rounded-sm border border-border text-fg-muted hover:text-fg hover:border-accent/40 disabled:opacity-30 disabled:hover:text-fg-muted disabled:hover:border-border"
            >
              Next
            </button>
          </div>
        </div>
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
