import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, RotateCcw } from "lucide-react";
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  getDetection,
  getDetectionHistory,
  getDetectionPerformance,
  markFalsePositive,
  rollbackDetection,
} from "@/api/detections";
import { useAuthStore } from "@/store/authStore";
import { pct, timeAgo, titleCase, yesNo } from "@/lib/format";

type Tab = "overview" | "performance" | "history" | "compiled";

const TABS: { id: Tab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "performance", label: "Performance" },
  { id: "history", label: "History" },
  { id: "compiled", label: "Compiled Queries" },
];

export function DetectionDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const role = useAuthStore((s) => s.user?.role);
  const isAdmin = role === "admin" || role === "vigil_admin";
  const [tab, setTab] = useState<Tab>("overview");

  const detection = useQuery({
    queryKey: ["detection", id],
    queryFn: () => getDetection(id!),
    enabled: !!id,
    refetchInterval: 30_000,
  });

  if (!id) {
    return (
      <div className="px-6 py-12 font-mono text-sm text-fg-muted">
        Missing detection id.
      </div>
    );
  }

  const det = detection.data;

  async function handleRollback() {
    if (!det) return;
    if (!confirm(`Roll back ${det.detection_id} to the previous version?`)) {
      return;
    }
    try {
      await rollbackDetection(det.detection_id);
      await queryClient.invalidateQueries({ queryKey: ["detection", id] });
      await queryClient.invalidateQueries({ queryKey: ["detection-history", id] });
      await queryClient.invalidateQueries({ queryKey: ["detections"] });
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Rollback failed";
      alert(`Rollback failed: ${msg}`);
    }
  }

  return (
    <div className="px-6 py-6 max-w-[1400px] mx-auto">
      <button
        type="button"
        onClick={() => navigate("/detections")}
        className="mb-4 flex items-center gap-1 text-[12px] font-mono text-fg-muted hover:text-fg"
      >
        <ArrowLeft size={13} /> Back to Library
      </button>

      {detection.isLoading ? (
        <div className="vigil-card p-8 text-center text-fg-muted font-mono text-sm">
          Loading...
        </div>
      ) : detection.isError || !det ? (
        <div className="vigil-card p-8 text-center text-accent font-mono text-sm">
          Failed to load detection.
        </div>
      ) : (
        <>
          <div className="vigil-card p-4 mb-4 flex flex-wrap items-start justify-between gap-3">
            <div>
              <div className="text-[11px] font-mono text-fg-faint uppercase tracking-wider">
                {det.att_ck_tactic.replace(/-/g, " ")} • {det.att_ck_technique}
              </div>
              <h1 className="text-xl font-mono text-fg mt-1">{det.detection_id}</h1>
              <div className="text-[11px] font-mono text-fg-muted mt-1">
                v{det.version}
                {det.deployed_at && ` • deployed ${timeAgo(det.deployed_at)}`}
              </div>
            </div>
            <div>
              <span
                className={`vigil-badge ${
                  det.status === "active"
                    ? "border-success/40 bg-success/10 text-success"
                    : det.status === "rolled_back"
                    ? "border-warning/40 bg-warning/10 text-warning"
                    : "border-fg-faint/40 bg-surface-2 text-fg-muted"
                }`}
              >
                {titleCase(det.status)}
              </span>
            </div>
          </div>

          <div className="border-b border-border mb-4">
            <div className="flex gap-1">
              {TABS.map((t) => (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => setTab(t.id)}
                  className={`px-4 py-2 text-[12px] font-mono border-b-2 transition-colors ${
                    tab === t.id
                      ? "border-accent text-fg"
                      : "border-transparent text-fg-muted hover:text-fg"
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>

          {tab === "overview" && <OverviewTab detection={det} />}
          {tab === "performance" && <PerformanceTab detectionId={id} />}
          {tab === "history" && (
            <HistoryTab
              detectionId={id}
              isAdmin={isAdmin}
              onRollback={handleRollback}
            />
          )}
          {tab === "compiled" && <CompiledTab detection={det} />}
        </>
      )}
    </div>
  );
}

function OverviewTab({ detection }: { detection: ReturnType<typeof getDetection> extends Promise<infer T> ? T : never }) {
  const si = detection.state_impact || {};
  return (
    <div className="space-y-3">
      <div className="vigil-card p-4">
        <div className="text-[11px] uppercase font-mono text-fg-faint tracking-wider mb-2">
          State Impact
        </div>
        <dl className="grid grid-cols-2 gap-3 text-sm font-mono">
          <Cell label="Status" value={si.status ?? "—"} />
          <Cell label="Transitions To" value={titleCase(si.transitions_to)} />
          <Cell
            label="Confidence Contribution"
            value={si.confidence_contribution != null ? pct(si.confidence_contribution) : "—"}
          />
          <Cell label="Progression" value={yesNo(si.progression)} />
        </dl>
      </div>

      <div className="vigil-card p-4">
        <div className="text-[11px] uppercase font-mono text-fg-faint tracking-wider mb-2">
          Rule Logic
        </div>
        {(si.conditions ?? []).length === 0 ? (
          <p className="text-[12px] font-mono text-fg-faint">
            No conditions defined — this detection is metadata-only and won't
            match in-transit events. Edit it to add rule logic.
          </p>
        ) : (
          <ul className="space-y-1 text-[12px] font-mono">
            {(si.conditions ?? []).map((c, i) => (
              <li key={i} className="flex items-center gap-2">
                {i > 0 && <span className="text-fg-faint text-[10px]">AND</span>}
                <span className="text-fg">{c.field}</span>
                <span className="text-accent-hover">{c.op}</span>
                {c.op !== "exists" && (
                  <span className="text-fg-muted break-all">{String(c.value)}</span>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>

      {detection.notes && (
        <div className="vigil-card p-4">
          <div className="text-[11px] uppercase font-mono text-fg-faint tracking-wider mb-2">
            Notes
          </div>
          <p className="text-sm font-mono text-fg-muted whitespace-pre-wrap">
            {detection.notes}
          </p>
        </div>
      )}
      {detection.yaml_content && (
        <div className="vigil-card p-4">
          <div className="text-[11px] uppercase font-mono text-fg-faint tracking-wider mb-2">
            YAML Source
          </div>
          <pre className="text-[12px] font-mono text-fg-muted whitespace-pre-wrap bg-surface-2 p-3 rounded-sm border border-border max-h-96 overflow-auto">
            {detection.yaml_content}
          </pre>
        </div>
      )}
    </div>
  );
}

function Cell({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-[11px] text-fg-faint uppercase tracking-wider">{label}</dt>
      <dd className="text-fg mt-0.5">{value}</dd>
    </div>
  );
}

function PerformanceTab({ detectionId }: { detectionId: string }) {
  const queryClient = useQueryClient();
  const perf = useQuery({
    queryKey: ["detection-performance", detectionId],
    queryFn: () => getDetectionPerformance(detectionId, 30),
    refetchInterval: 30_000,
  });
  const [pendingFp, setPendingFp] = useState<string | null>(null);

  async function handleMarkFp(signalId: string) {
    if (pendingFp) return;
    setPendingFp(signalId);
    try {
      await markFalsePositive(detectionId, signalId);
      await queryClient.invalidateQueries({
        queryKey: ["detection-performance", detectionId],
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to mark false positive";
      alert(msg);
    } finally {
      setPendingFp(null);
    }
  }

  if (perf.isLoading) {
    return (
      <div className="vigil-card p-8 text-center text-fg-muted font-mono text-sm">
        Loading performance data...
      </div>
    );
  }
  if (perf.isError || !perf.data) {
    return (
      <div className="vigil-card p-8 text-center text-accent font-mono text-sm">
        Failed to load performance.
      </div>
    );
  }

  const { summary, trend, signals } = perf.data;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Stat label="Total Fires (30d)" value={String(summary?.total_fires ?? 0)} />
        <Stat
          label="FP Rate"
          value={summary?.fp_rate == null ? "—" : pct(summary.fp_rate)}
        />
        <Stat
          label="Avg Confidence"
          value={
            summary?.avg_confidence == null ? "—" : pct(summary.avg_confidence)
          }
        />
        <Stat label="Escalations" value={String(summary?.escalations ?? 0)} />
      </div>

      <div className="vigil-card p-4">
        <div className="text-[11px] uppercase font-mono text-fg-faint tracking-wider mb-3">
          Daily Fires (30d)
        </div>
        <div className="h-64">
          <ResponsiveContainer>
            <LineChart data={trend}>
              <CartesianGrid stroke="#262626" strokeDasharray="3 3" />
              <XAxis
                dataKey="day"
                stroke="#9ca3af"
                fontSize={11}
                tickFormatter={(v) => v.slice(5, 10)}
              />
              <YAxis stroke="#9ca3af" fontSize={11} allowDecimals={false} />
              <Tooltip
                contentStyle={{
                  background: "#121212",
                  border: "1px solid #262626",
                  fontSize: 12,
                  color: "#fff",
                }}
              />
              <Line
                type="monotone"
                dataKey="fires"
                stroke="#dc2626"
                strokeWidth={2}
                dot={false}
              />
              <Line
                type="monotone"
                dataKey="false_positives"
                stroke="#ca8a04"
                strokeWidth={2}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="vigil-card overflow-hidden">
        <div className="px-4 py-2 border-b border-border bg-surface-2 text-[11px] uppercase font-mono text-fg-faint tracking-wider">
          Recent Signals
        </div>
        {signals.length === 0 ? (
          <div className="p-6 text-center text-fg-muted font-mono text-sm">
            No signals fired in the last 30 days.
          </div>
        ) : (
          <table className="w-full text-sm font-mono">
            <thead className="bg-surface-2">
              <tr className="text-left text-[11px] uppercase tracking-wider text-fg-faint">
                <th className="px-3 py-2">Fired</th>
                <th className="px-3 py-2">Phase</th>
                <th className="px-3 py-2">Where</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2 text-right">Confidence</th>
                <th className="px-3 py-2">Outcome</th>
                <th className="px-3 py-2 text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {signals.slice(0, 50).map((s) => (
                <tr key={s.signal_id} className="border-b border-border last:border-0">
                  <td className="px-3 py-2 text-fg-muted">{timeAgo(s.fired_at)}</td>
                  <td className="px-3 py-2 text-fg">{s.phase_contributed ?? "—"}</td>
                  <td className="px-3 py-2">
                    {s.attack_id ? (
                      <Link
                        to={`/attacks/${s.attack_id}`}
                        className="text-accent-hover hover:underline"
                        title="Open the attack where this signal fired"
                      >
                        View attack
                      </Link>
                    ) : (
                      <span className="text-fg-faint">—</span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-fg-muted">
                    {s.status_contributed ?? "—"}
                  </td>
                  <td className="px-3 py-2 text-right tabular-nums text-fg">
                    {s.confidence_contribution != null
                      ? pct(s.confidence_contribution)
                      : "—"}
                  </td>
                  <td className="px-3 py-2">
                    {s.was_false_positive ? (
                      <span className="vigil-badge border-warning/40 bg-warning/10 text-warning">
                        False Positive
                      </span>
                    ) : (
                      <span className="text-fg-muted">{s.closed_as ?? "open"}</span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-right">
                    {s.was_false_positive ? (
                      <span className="text-fg-faint text-[11px]">—</span>
                    ) : (
                      <button
                        type="button"
                        onClick={() => handleMarkFp(s.signal_id)}
                        disabled={pendingFp === s.signal_id}
                        className="text-[11px] font-mono text-fg-muted hover:text-warning disabled:opacity-50"
                        title="Mark as false positive"
                      >
                        {pendingFp === s.signal_id ? "Marking…" : "Mark FP"}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="vigil-stat">
      <span className="text-[11px] uppercase font-mono text-fg-faint tracking-wider">
        {label}
      </span>
      <span className="text-lg font-mono text-fg tabular-nums">{value}</span>
    </div>
  );
}

function HistoryTab({
  detectionId,
  isAdmin,
  onRollback,
}: {
  detectionId: string;
  isAdmin: boolean;
  onRollback: () => void;
}) {
  const history = useQuery({
    queryKey: ["detection-history", detectionId],
    queryFn: () => getDetectionHistory(detectionId),
  });

  if (history.isLoading) {
    return (
      <div className="vigil-card p-8 text-center text-fg-muted font-mono text-sm">
        Loading history...
      </div>
    );
  }
  if (history.isError || !history.data) {
    return (
      <div className="vigil-card p-8 text-center text-accent font-mono text-sm">
        Failed to load history.
      </div>
    );
  }

  return (
    <div className="vigil-card overflow-hidden">
      <table className="w-full text-sm font-mono">
        <thead className="bg-surface-2">
          <tr className="text-left text-[11px] uppercase tracking-wider text-fg-faint">
            <th className="px-3 py-2">Version</th>
            <th className="px-3 py-2">Deployed</th>
            <th className="px-3 py-2">Deployed By</th>
            <th className="px-3 py-2">Status</th>
            <th className="px-3 py-2"></th>
          </tr>
        </thead>
        <tbody>
          {history.data.map((v, idx) => (
            <tr key={v.version_id} className="border-b border-border last:border-0">
              <td className="px-3 py-2 text-fg">{v.version}</td>
              <td className="px-3 py-2 text-fg-muted">
                {v.deployed_at ? timeAgo(v.deployed_at) : "—"}
              </td>
              <td className="px-3 py-2 text-fg-muted">
                {v.deployed_by ?? "VIGIL Platform"}
              </td>
              <td className="px-3 py-2">
                <span
                  className={`vigil-badge ${
                    v.status === "active"
                      ? "border-success/40 bg-success/10 text-success"
                      : v.status === "rolled_back"
                      ? "border-warning/40 bg-warning/10 text-warning"
                      : "border-fg-faint/40 bg-surface-2 text-fg-muted"
                  }`}
                >
                  {titleCase(v.status)}
                </span>
              </td>
              <td className="px-3 py-2 text-right">
                {idx === 0 && v.status === "active" && isAdmin && (
                  <button
                    type="button"
                    onClick={onRollback}
                    className="inline-flex items-center gap-1 text-[12px] font-mono text-fg-muted hover:text-accent"
                  >
                    <RotateCcw size={12} /> Roll back
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CompiledTab({
  detection,
}: {
  detection: ReturnType<typeof getDetection> extends Promise<infer T> ? T : never;
}) {
  return (
    <div className="space-y-3">
      <CompiledBlock label="Splunk SPL" content={detection.compiled_spl} />
      <CompiledBlock label="Sentinel KQL" content={detection.compiled_kql} />
      <CompiledBlock label="Elastic EQL" content={detection.compiled_eql} />
    </div>
  );
}

function CompiledBlock({
  label,
  content,
}: {
  label: string;
  content: string | null | undefined;
}) {
  return (
    <div className="vigil-card p-4">
      <div className="text-[11px] uppercase font-mono text-fg-faint tracking-wider mb-2">
        {label}
      </div>
      {content ? (
        <pre className="text-[12px] font-mono text-fg whitespace-pre-wrap bg-surface-2 p-3 rounded-sm border border-border max-h-72 overflow-auto vigil-syntax">
          {content}
        </pre>
      ) : (
        <p className="text-sm font-mono text-fg-faint">Not available.</p>
      )}
    </div>
  );
}
