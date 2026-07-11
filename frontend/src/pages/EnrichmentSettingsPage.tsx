import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Radar, ExternalLink, Check, KeyRound, Link2 } from "lucide-react";
import { listConnectors, getAutoEnrich, setAutoEnrich, type Connector } from "@/api/osint";
import { SettingsTabs } from "@/components/SettingsTabs";
import { titleCase } from "@/lib/format";

export function EnrichmentSettingsPage() {
  const [autoEnrich, setAuto] = useState<boolean>(getAutoEnrich());
  const connectors = useQuery({
    queryKey: ["osint-connectors"],
    queryFn: listConnectors,
  });

  function toggleAuto() {
    const next = !autoEnrich;
    setAuto(next);
    setAutoEnrich(next);
  }

  return (
    <div className="px-6 py-6 max-w-[1100px] mx-auto">
      <div className="mb-5 flex items-center gap-2">
        <Radar size={18} className="text-fg-muted" />
        <h1 className="text-xl font-mono text-fg">Settings</h1>
      </div>

      <SettingsTabs />

      <div className="vigil-card p-4 mb-5 flex items-start justify-between gap-4">
        <div>
          <div className="text-sm font-mono text-fg">Auto-enrich IOCs</div>
          <p className="text-[12px] font-mono text-fg-muted mt-1 max-w-xl">
            When on, indicators in the evidence chain are enriched automatically
            as you open them — no click required. Off by default to keep provider
            calls deliberate.
          </p>
        </div>
        <button
          type="button"
          role="switch"
          aria-checked={autoEnrich}
          onClick={toggleAuto}
          className={`shrink-0 mt-1 relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
            autoEnrich ? "bg-accent" : "bg-surface-2 border border-border"
          }`}
        >
          <span
            className={`inline-block h-3.5 w-3.5 rounded-full bg-fg transition-transform ${
              autoEnrich ? "translate-x-4" : "translate-x-1"
            }`}
          />
        </button>
      </div>

      <div className="text-[10px] uppercase tracking-wider text-fg-faint font-mono mb-2">
        Enrichment Sources
      </div>

      {connectors.isLoading ? (
        <div className="vigil-card p-6 text-center text-fg-muted font-mono text-sm">
          Loading sources…
        </div>
      ) : connectors.isError ? (
        <div className="vigil-card p-6 text-center text-accent font-mono text-sm">
          Failed to load sources: {(connectors.error as Error).message}
        </div>
      ) : (
        <div className="space-y-2">
          {(connectors.data ?? []).map((c) => (
            <SourceCard key={c.name} connector={c} />
          ))}
        </div>
      )}
    </div>
  );
}

function SourceCard({ connector: c }: { connector: Connector }) {
  return (
    <div className="vigil-card p-4 flex items-start gap-3">
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm font-mono text-fg">{c.name}</span>
          <span className="vigil-badge border-border-strong bg-surface-2 text-fg-muted uppercase">
            {c.category.replace(/_/g, " ")}
          </span>
          {c.automatable ? (
            <span className="vigil-badge border-success/40 bg-success/10 text-success inline-flex items-center gap-1">
              <Check size={10} /> Automated
            </span>
          ) : c.requires_key ? (
            <span className="vigil-badge border-warning/40 bg-warning/10 text-warning inline-flex items-center gap-1">
              <KeyRound size={10} /> Needs API key
            </span>
          ) : (
            <span className="vigil-badge border-info/40 bg-info/10 text-info inline-flex items-center gap-1">
              <Link2 size={10} /> Link-only
            </span>
          )}
        </div>
        <div className="text-[11px] font-mono text-fg-faint mt-1">
          Handles {c.capabilities.map((x) => titleCase(x)).join(", ")}
        </div>
        {c.requires_key && !c.automatable && (
          <div className="text-[11px] font-mono text-warning/80 mt-1">
            Set the <span className="text-fg">{c.api_key_env}</span> environment
            variable on the vigil-osint service to enable live lookups.
          </div>
        )}
      </div>
      {c.homepage && (
        <a
          href={c.homepage}
          target="_blank"
          rel="noopener noreferrer"
          className="shrink-0 inline-flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-mono border border-border bg-surface-2 text-fg-muted rounded-sm hover:text-fg hover:border-accent/40"
        >
          <ExternalLink size={12} /> Open {c.name}
        </a>
      )}
    </div>
  );
}
