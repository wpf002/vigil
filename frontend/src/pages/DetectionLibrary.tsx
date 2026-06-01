import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Radar } from "lucide-react";
import { listDetections } from "@/api/detections";
import { timeAgo, pct, titleCase } from "@/lib/format";
import type { DetectionVersion } from "@/types/detections";

function fpRateClasses(rate: number | null | undefined): string {
  if (rate == null) return "text-fg-faint";
  if (rate < 0.1) return "text-success";
  if (rate < 0.25) return "text-warning";
  return "text-accent-hover";
}

function statusBadgeClasses(status: string): string {
  switch (status) {
    case "active":
      return "border-success/40 bg-success/10 text-success";
    case "deprecated":
      return "border-fg-faint/40 bg-surface-2 text-fg-muted";
    case "rolled_back":
      return "border-warning/40 bg-warning/10 text-warning";
    default:
      return "border-border bg-surface-2 text-fg-muted";
  }
}

export function DetectionLibrary() {
  const navigate = useNavigate();
  const query = useQuery({
    queryKey: ["detections"],
    queryFn: listDetections,
    refetchInterval: 30_000,
  });

  const detections = query.data ?? [];

  return (
    <div className="px-6 py-6 max-w-[1400px] mx-auto">
      <div className="mb-5 flex items-center gap-2">
        <Radar size={18} className="text-fg-muted" />
        <h1 className="text-xl font-mono text-fg">Detection Library</h1>
        <span className="ml-auto text-[11px] font-mono text-fg-faint tabular-nums">
          {detections.length} {detections.length === 1 ? "Detection" : "Detections"}
        </span>
      </div>
      <p className="text-[12px] font-mono text-fg-muted mb-4 -mt-3 max-w-3xl">
        Your active <span className="text-fg">detection rules</span> — the logic
        that fires on incoming telemetry to surface attacks. Get more from the
        Marketplace; automate the response in Playbooks.
      </p>

      {query.isLoading ? (
        <div className="vigil-card p-8 text-center text-fg-muted font-mono text-sm">
          Loading detections...
        </div>
      ) : query.isError ? (
        <div className="vigil-card p-8 text-center text-accent font-mono text-sm">
          Failed to load detections: {query.error?.message ?? "unknown error"}
        </div>
      ) : detections.length === 0 ? (
        <div className="vigil-card p-8 text-center text-fg-muted font-mono text-sm">
          No detections deployed.
        </div>
      ) : (
        <div className="vigil-card overflow-hidden">
          <table className="w-full text-sm font-mono">
            <thead className="border-b border-border bg-surface-2">
              <tr className="text-left text-[11px] uppercase tracking-wider text-fg-faint">
                <th className="px-3 py-2">Detection ID</th>
                <th className="px-3 py-2">Tactic</th>
                <th className="px-3 py-2">Technique</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2 text-right">Fires (30d)</th>
                <th className="px-3 py-2 text-right">FP Rate</th>
                <th className="px-3 py-2">Last Fired</th>
                <th className="px-3 py-2">Version</th>
              </tr>
            </thead>
            <tbody>
              {detections.map((d) => (
                <DetectionRow
                  key={d.detection_id}
                  detection={d}
                  onClick={() =>
                    navigate(`/detections/${encodeURIComponent(d.detection_id)}`)
                  }
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function DetectionRow({
  detection,
  onClick,
}: {
  detection: DetectionVersion;
  onClick: () => void;
}) {
  const perf = detection.performance;
  const lastFired = perf?.computed_at ?? detection.deployed_at;

  return (
    <tr
      onClick={onClick}
      className="border-b border-border last:border-0 hover:bg-surface-2 cursor-pointer transition-colors"
    >
      <td className="px-3 py-2 text-fg">{detection.detection_id}</td>
      <td className="px-3 py-2 text-fg-muted">
        {titleCase(detection.att_ck_tactic)}
      </td>
      <td className="px-3 py-2 text-fg-faint">{detection.att_ck_technique}</td>
      <td className="px-3 py-2">
        <span className={`vigil-badge ${statusBadgeClasses(detection.status)}`}>
          {titleCase(detection.status)}
        </span>
      </td>
      <td className="px-3 py-2 text-right text-fg tabular-nums">
        {perf?.total_fires ?? 0}
      </td>
      <td className={`px-3 py-2 text-right tabular-nums ${fpRateClasses(perf?.fp_rate)}`}>
        {perf?.fp_rate == null ? "—" : pct(perf.fp_rate)}
      </td>
      <td className="px-3 py-2 text-fg-muted">
        {lastFired ? timeAgo(lastFired) : "—"}
      </td>
      <td className="px-3 py-2 text-fg-faint">{detection.version}</td>
    </tr>
  );
}
