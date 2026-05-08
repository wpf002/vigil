import { useQuery } from "@tanstack/react-query";
import { Activity, AlertTriangle, Check, X } from "lucide-react";
import { reportingClient } from "@/api/reporting";

interface ServiceStatus {
  name: string;
  port: number;
  ok: boolean;
  status: string;
  version: string | null;
}

interface PipelineStatus {
  services: ServiceStatus[];
  summary: { total: number; healthy: number; unreachable: number };
}

interface Envelope<T> {
  data: T;
  error?: string | null;
}

async function fetchPipelineStatus(): Promise<PipelineStatus> {
  const res = await reportingClient.get<Envelope<PipelineStatus>>("/pipeline/status");
  if (res.data.error) throw new Error(res.data.error);
  return res.data.data;
}

export function PipelinePage() {
  const q = useQuery({
    queryKey: ["pipeline-status"],
    queryFn: fetchPipelineStatus,
    refetchInterval: 10_000,
  });

  const services = q.data?.services ?? [];
  const summary = q.data?.summary;

  return (
    <div className="px-6 py-6 max-w-[1100px] mx-auto">
      <div className="mb-5 flex items-center gap-2">
        <Activity size={18} className="text-fg-muted" />
        <h1 className="text-xl font-mono text-fg">Pipeline</h1>
        {summary && (
          <span className="ml-auto text-[11px] font-mono tabular-nums">
            <span className="text-success">{summary.healthy}</span>
            <span className="text-fg-faint"> / {summary.total} healthy</span>
          </span>
        )}
      </div>

      {q.isLoading ? (
        <div className="vigil-card p-6 text-center text-fg-muted font-mono text-sm">
          Probing services…
        </div>
      ) : (
        <div className="vigil-card overflow-hidden">
          <table className="w-full text-sm font-mono">
            <thead className="border-b border-border bg-surface-2">
              <tr className="text-left text-[11px] uppercase tracking-wider text-fg-faint">
                <th className="px-3 py-2">Service</th>
                <th className="px-3 py-2">Port</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2">Version</th>
              </tr>
            </thead>
            <tbody>
              {services.map((s) => {
                const degraded = !s.ok && s.status !== "unreachable";
                return (
                  <tr key={s.port} className="border-b border-border last:border-0">
                    <td className="px-3 py-2 text-fg">{s.name}</td>
                    <td className="px-3 py-2 text-fg-muted">{s.port}</td>
                    <td className="px-3 py-2">
                      <span
                        className={`vigil-badge inline-flex items-center gap-1 ${
                          s.ok
                            ? "border-success/40 bg-success/10 text-success"
                            : degraded
                              ? "border-warning/40 bg-warning/10 text-warning"
                              : "border-accent/40 bg-accent/10 text-accent"
                        }`}
                      >
                        {s.ok ? (
                          <Check size={9} />
                        ) : degraded ? (
                          <AlertTriangle size={9} />
                        ) : (
                          <X size={9} />
                        )}
                        {s.status.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-fg-faint text-[11px]">
                      {s.version ? `v${s.version}` : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
