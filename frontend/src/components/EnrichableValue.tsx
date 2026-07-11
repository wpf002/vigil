import { useEffect, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Search, ExternalLink, Loader2 } from "lucide-react";
import {
  enrich,
  getAutoEnrich,
  type Observation,
  type DeepLink,
} from "@/api/osint";

const TLP_STYLE: Record<string, string> = {
  "TLP:WHITE": "border-border bg-surface-2 text-fg-muted",
  "TLP:GREEN": "border-success/40 bg-success/10 text-success",
  "TLP:AMBER": "border-warning/40 bg-warning/10 text-warning",
  "TLP:RED": "border-accent/40 bg-accent/10 text-accent-hover",
};

interface SourceRollup {
  source: string;
  count: number;
  malicious: number;
  tlp: string;
  maxConfidence: number;
}

function rollup(observations: Observation[]): SourceRollup[] {
  const map = new Map<string, SourceRollup>();
  for (const o of observations) {
    const r =
      map.get(o.source) ??
      { source: o.source, count: 0, malicious: 0, tlp: o.tlp, maxConfidence: 0 };
    r.count += 1;
    if ((o.summary as Record<string, unknown>)?.malicious === true) r.malicious += 1;
    r.maxConfidence = Math.max(r.maxConfidence, o.confidence_score ?? 0);
    map.set(o.source, r);
  }
  return [...map.values()];
}

/**
 * An IOC value that can be enriched in place. Renders the value with a small
 * search affordance; clicking fetches OSINT enrichment (vigil-osint) and shows
 * a compact per-source rollup plus any provider deep-links.
 */
export function EnrichableValue({ value }: { value: string }) {
  const [open, setOpen] = useState(false);
  const mutation = useMutation({ mutationFn: () => enrich(value) });

  // Auto-enrich: if the user enabled it in Settings, fetch + expand on mount.
  useEffect(() => {
    if (getAutoEnrich()) {
      setOpen(true);
      mutation.mutate();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function handleClick() {
    const next = !open;
    setOpen(next);
    if (next && !mutation.data && !mutation.isPending) mutation.mutate();
  }

  const rollups = mutation.data ? rollup(mutation.data.observations) : [];
  const deepLinks: DeepLink[] = mutation.data?.deep_links ?? [];

  return (
    <span className="inline-flex flex-col gap-1 min-w-0">
      <span className="inline-flex items-center gap-1.5 min-w-0">
        <span className="text-fg-muted break-all">{value}</span>
        <button
          type="button"
          onClick={handleClick}
          title={`Enrich ${value}`}
          aria-expanded={open}
          className="shrink-0 text-fg-faint hover:text-accent transition-colors"
        >
          {mutation.isPending ? (
            <Loader2 size={11} className="animate-spin" />
          ) : (
            <Search size={11} />
          )}
        </button>
      </span>

      {open && (
        <span className="block mt-0.5 rounded-sm border border-border bg-bg/60 p-2 text-[10px] font-mono">
          {mutation.isPending ? (
            <span className="text-fg-faint">Enriching…</span>
          ) : mutation.isError ? (
            <span className="text-accent-hover">
              Enrichment failed: {(mutation.error as Error).message}
            </span>
          ) : (
            <span className="flex flex-col gap-1">
              {rollups.length === 0 && deepLinks.length === 0 && (
                <span className="text-fg-faint">No enrichment results.</span>
              )}
              {rollups.map((r) => (
                <span key={r.source} className="inline-flex items-center gap-1.5 flex-wrap">
                  <span className="text-fg">{r.source}</span>
                  <span className="text-fg-faint">
                    {r.count} {r.count === 1 ? "result" : "results"}
                  </span>
                  {r.malicious > 0 ? (
                    <span className="vigil-badge border-accent/40 bg-accent/10 text-accent-hover">
                      {r.malicious} malicious
                    </span>
                  ) : (
                    <span className="vigil-badge border-success/40 bg-success/10 text-success">
                      clean
                    </span>
                  )}
                  <span className={`vigil-badge ${TLP_STYLE[r.tlp] ?? TLP_STYLE["TLP:WHITE"]}`}>
                    {r.tlp}
                  </span>
                </span>
              ))}
              {deepLinks.map((dl) => (
                <a
                  key={dl.connector}
                  href={dl.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-fg-muted hover:text-fg w-fit"
                  title={dl.reason}
                >
                  <ExternalLink size={10} /> Open in {dl.connector}
                </a>
              ))}
            </span>
          )}
        </span>
      )}
    </span>
  );
}
