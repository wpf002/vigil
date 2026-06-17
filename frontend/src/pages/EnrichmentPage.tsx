import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import {
  Search,
  ExternalLink,
  Globe,
  ShieldQuestion,
  AlertTriangle,
} from "lucide-react";
import { enrich, type EnrichResponse, type Observation } from "@/api/osint";

const TLP_STYLE: Record<string, string> = {
  "TLP:WHITE": "border-border bg-surface-2 text-fg-muted",
  "TLP:GREEN": "border-success/40 bg-success/10 text-success",
  "TLP:AMBER": "border-warning/40 bg-warning/10 text-warning",
  "TLP:RED": "border-accent/40 bg-accent/10 text-accent-hover",
};

function confidenceLabel(score: number): string {
  if (score >= 0.8) return "high";
  if (score >= 0.5) return "medium";
  return "low";
}

export function EnrichmentPage() {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<EnrichResponse | null>(null);

  const mutation = useMutation({
    mutationFn: (q: string) => enrich(q),
    onSuccess: (r) => setResult(r),
    onError: (e) => alert(`Enrichment failed: ${e instanceof Error ? e.message : e}`),
  });

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    const q = query.trim();
    if (q) mutation.mutate(q);
  }

  // Group observations by source connector.
  const byConnector = (result?.observations ?? []).reduce<Record<string, Observation[]>>(
    (acc, obs) => {
      (acc[obs.source] ??= []).push(obs);
      return acc;
    },
    {},
  );

  return (
    <div className="px-6 py-6 max-w-[1100px] mx-auto">
      <div className="mb-2 flex items-center gap-2">
        <ShieldQuestion size={18} className="text-fg-muted" />
        <h1 className="text-xl font-mono text-fg">IOC Enrichment</h1>
      </div>
      <p className="text-[12px] font-mono text-fg-muted mb-5 max-w-2xl">
        Look up an indicator — domain, IP, URL, email, or file hash — across OSINT
        sources. Type is auto-detected; you can also force it with a prefix like{" "}
        <span className="text-fg-faint">domain:</span> or{" "}
        <span className="text-fg-faint">ip:</span>.
      </p>

      <form onSubmit={onSubmit} className="mb-5 flex gap-2">
        <div className="relative flex-1">
          <Search
            size={14}
            className="absolute left-3 top-1/2 -translate-y-1/2 text-fg-faint"
          />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="8.8.8.8  ·  domain:example.com  ·  hash:44d88612…"
            className="w-full pl-9 pr-3 py-2 text-[13px] font-mono bg-surface border border-border
                       rounded-sm text-fg placeholder:text-fg-faint focus:outline-none
                       focus:border-accent/50"
          />
        </div>
        <button
          type="submit"
          disabled={mutation.isPending || !query.trim()}
          className="inline-flex items-center gap-1.5 px-4 py-2 text-[12px] font-mono border
                     border-accent/50 bg-accent/15 text-accent-hover rounded-sm
                     hover:bg-accent/25 disabled:opacity-40"
        >
          <Search size={12} />
          {mutation.isPending ? "Enriching…" : "Enrich"}
        </button>
      </form>

      {result && (
        <>
          <div className="mb-4 flex flex-wrap items-center gap-2 text-[12px] font-mono">
            <span className="text-fg-muted">Parsed as</span>
            <span className="vigil-badge border-accent/40 bg-accent/10 text-accent-hover uppercase">
              {result.parsed.type}
            </span>
            <span className="text-fg">{result.parsed.value}</span>
            <span className="text-fg-faint">· {result.observations.length} observations</span>
          </div>

          {result.deep_links.length > 0 && (
            <div className="mb-4 space-y-2">
              {result.deep_links.map((dl) => (
                <div
                  key={dl.connector}
                  className="vigil-card p-3 flex items-center justify-between border-l-2 border-l-warning"
                >
                  <div className="text-[12px] font-mono text-fg-muted">
                    <span className="text-fg">{dl.connector}</span> — automation
                    disabled by policy; open the source directly.
                  </div>
                  <a
                    href={dl.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-mono
                               border border-border bg-surface-2 text-fg-muted rounded-sm
                               hover:text-fg hover:border-accent/40"
                  >
                    <ExternalLink size={12} /> Open in {dl.connector}
                  </a>
                </div>
              ))}
            </div>
          )}

          {result.errors.length > 0 &&
            result.errors.map((err) => (
              <div
                key={err.connector}
                className="vigil-card p-3 mb-2 flex items-center gap-2 border-l-2 border-l-accent text-[12px] font-mono"
              >
                <AlertTriangle size={13} className="text-accent-hover" />
                <span className="text-fg">{err.connector}</span>
                <span className="text-fg-muted">failed: {err.error}</span>
              </div>
            ))}

          {Object.entries(byConnector).map(([connector, observations]) => (
            <div key={connector} className="mb-5">
              <div className="flex items-center gap-2 mb-2">
                <Globe size={13} className="text-fg-faint" />
                <span className="text-[10px] uppercase tracking-wider text-fg-faint font-mono">
                  {connector} · {observations.length}
                </span>
              </div>
              <div className="space-y-2">
                {observations.map((obs, i) => (
                  <ObservationCard key={`${connector}-${i}`} obs={obs} />
                ))}
              </div>
            </div>
          ))}

          {result.observations.length === 0 && result.deep_links.length === 0 && (
            <div className="vigil-card p-6 text-center text-fg-muted font-mono text-sm">
              No observations found for this indicator.
            </div>
          )}
        </>
      )}
    </div>
  );
}

function ObservationCard({ obs }: { obs: Observation }) {
  const tlpStyle = TLP_STYLE[obs.tlp] ?? TLP_STYLE["TLP:WHITE"];
  const s = obs.summary as Record<string, unknown>;
  const malicious = s.malicious === true;

  return (
    <div className={`vigil-card p-4 ${malicious ? "border-l-2 border-l-accent" : ""}`}>
      <div className="flex items-center justify-between gap-3 mb-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-[12px] font-mono text-fg truncate">{obs.source}</span>
          <span className="vigil-badge border-border bg-surface-2 text-fg-muted uppercase">
            {obs.entity_type}
          </span>
          {malicious && (
            <span className="vigil-badge border-accent/40 bg-accent/10 text-accent-hover uppercase">
              malicious
            </span>
          )}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className={`vigil-badge ${tlpStyle}`}>{obs.tlp}</span>
          <span
            className="text-[10px] font-mono text-fg-faint"
            title={`confidence ${obs.confidence_score}`}
          >
            {confidenceLabel(obs.confidence_score)} ({obs.confidence_score.toFixed(2)})
          </span>
        </div>
      </div>

      <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-[12px] font-mono">
        {Object.entries(s)
          .filter(([k]) => k !== "malicious" && k !== "screenshot_url")
          .filter(([, v]) => v != null && v !== "")
          .map(([k, v]) => (
            <div key={k} className="flex gap-2 min-w-0">
              <dt className="text-fg-faint shrink-0">{k}</dt>
              <dd className="text-fg-muted truncate" title={String(v)}>
                {String(v)}
              </dd>
            </div>
          ))}
      </dl>

      <div className="mt-2 flex items-center gap-3 text-[10px] font-mono text-fg-faint">
        {obs.observed_at && <span>observed {obs.observed_at}</span>}
        {obs.deep_link && (
          <a
            href={obs.deep_link}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-fg-muted hover:text-fg"
          >
            <ExternalLink size={11} /> Open in {obs.source}
          </a>
        )}
        {typeof s.screenshot_url === "string" && s.screenshot_url && (
          <a
            href={s.screenshot_url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-fg-muted hover:text-fg"
          >
            <ExternalLink size={11} /> Screenshot
          </a>
        )}
      </div>
    </div>
  );
}
