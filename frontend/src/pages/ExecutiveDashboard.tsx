import { useQuery } from "@tanstack/react-query";
import { Activity } from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { getExecutiveSummary, getExecutiveTrend } from "@/api/reporting";
import { titleCase } from "@/lib/format";

const ACCENT = "#dc2626";
const ACCENT_DIM = "#7f1d1d";
const FG_FAINT = "#52525b";

export function ExecutiveDashboard() {
  const summary = useQuery({
    queryKey: ["reporting", "summary"],
    queryFn: getExecutiveSummary,
    refetchInterval: 60_000,
  });
  const trend = useQuery({
    queryKey: ["reporting", "trend", 30],
    queryFn: () => getExecutiveTrend(30),
    refetchInterval: 60_000,
  });

  const phases = summary.data?.attacks_by_phase ?? {};
  const phaseData = Object.entries(phases).map(([k, v]) => ({
    name: titleCase(k),
    value: v,
  }));

  return (
    <div className="px-6 py-6 max-w-[1400px] mx-auto">
      <div className="mb-5 flex items-center gap-2">
        <Activity size={18} className="text-fg-muted" />
        <h1 className="text-xl font-mono text-fg">Executive Dashboard</h1>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mb-5">
        <Stat label="Active Attacks" value={summary.data?.active_attacks ?? "—"} />
        <Stat
          label="MTTR (7d)"
          value={
            summary.data?.mttr_seconds_7d == null
              ? "—"
              : formatDuration(summary.data.mttr_seconds_7d)
          }
        />
        <Stat
          label="SLA Breach Rate"
          value={
            summary.data?.sla_breach_rate_7d == null
              ? "—"
              : `${(summary.data.sla_breach_rate_7d * 100).toFixed(1)}%`
          }
        />
        <Stat
          label="Coverage Score"
          value={
            summary.data?.coverage_score == null
              ? "—"
              : `${(summary.data.coverage_score * 100).toFixed(0)}%`
          }
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 mb-3">
        <div className="vigil-card p-4">
          <div className="text-[11px] font-mono text-fg-faint mb-3">
            Attack Volume — 30d
          </div>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={trend.data?.attack_volume ?? []}>
              <CartesianGrid stroke="#27272a" strokeDasharray="2 2" />
              <XAxis dataKey="date" stroke={FG_FAINT} fontSize={10} />
              <YAxis stroke={FG_FAINT} fontSize={10} />
              <Tooltip
                contentStyle={{
                  background: "#121212",
                  border: "1px solid #27272a",
                  fontFamily: "monospace",
                  fontSize: 12,
                }}
              />
              <Line
                type="monotone"
                dataKey="count"
                stroke={ACCENT}
                strokeWidth={2}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="vigil-card p-4">
          <div className="text-[11px] font-mono text-fg-faint mb-3">
            Attacks By Phase
          </div>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
                data={phaseData}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                outerRadius={70}
                innerRadius={40}
                paddingAngle={2}
                stroke="#0a0a0a"
              >
                {phaseData.map((_, i) => (
                  <Cell key={i} fill={i % 2 === 0 ? ACCENT : ACCENT_DIM} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  background: "#121212",
                  border: "1px solid #27272a",
                  fontFamily: "monospace",
                  fontSize: 12,
                }}
                itemStyle={{ color: "#ffffff" }}
                labelStyle={{ color: "#ffffff" }}
                formatter={(value: number, name: string) => [
                  `${value} active ${value === 1 ? "attack" : "attacks"}`,
                  name,
                ]}
              />
              <Legend
                wrapperStyle={{ fontFamily: "monospace", fontSize: 10, color: "#9ca3af" }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        <div className="vigil-card p-4">
          <div className="text-[11px] font-mono text-fg-faint mb-3">
            MTTR Trend — 30d{" "}
            <span className="text-fg-faint">(mean time to resolve, per day)</span>
          </div>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={trend.data?.mttr_seconds ?? []}>
              <CartesianGrid stroke="#27272a" strokeDasharray="2 2" />
              <XAxis dataKey="date" stroke={FG_FAINT} fontSize={10} />
              <YAxis
                stroke={FG_FAINT}
                fontSize={10}
                width={44}
                tickFormatter={(v: number) => formatDuration(v)}
              />
              <Tooltip
                contentStyle={{
                  background: "#121212",
                  border: "1px solid #27272a",
                  fontFamily: "monospace",
                  fontSize: 12,
                }}
                itemStyle={{ color: "#ffffff" }}
                labelStyle={{ color: "#ffffff" }}
                formatter={(value: number) => [
                  formatDuration(value),
                  "Avg time to resolve",
                ]}
              />
              <Bar dataKey="value" fill={ACCENT} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="vigil-card p-4">
          <div className="text-[11px] font-mono text-fg-faint mb-3">
            SLA Breach Rate — 30d{" "}
            <span className="text-fg-faint">(% of attacks past their SLA)</span>
          </div>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={trend.data?.sla_breach_rate ?? []}>
              <CartesianGrid stroke="#27272a" strokeDasharray="2 2" />
              <XAxis dataKey="date" stroke={FG_FAINT} fontSize={10} />
              <YAxis
                stroke={FG_FAINT}
                fontSize={10}
                width={44}
                domain={[0, 1]}
                tickFormatter={(v: number) => `${Math.round(v * 100)}%`}
              />
              <Tooltip
                contentStyle={{
                  background: "#121212",
                  border: "1px solid #27272a",
                  fontFamily: "monospace",
                  fontSize: 12,
                }}
                itemStyle={{ color: "#ffffff" }}
                labelStyle={{ color: "#ffffff" }}
                formatter={(value: number) => [
                  `${(value * 100).toFixed(0)}%`,
                  "SLA breach rate",
                ]}
              />
              <Line
                type="monotone"
                dataKey="value"
                stroke={ACCENT}
                strokeWidth={2}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="vigil-card p-4">
      <div className="text-[11px] font-mono uppercase tracking-wider text-fg-faint">
        {label}
      </div>
      <div className="mt-1 font-mono text-2xl text-fg tabular-nums">{value}</div>
    </div>
  );
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds.toFixed(0)}s`;
  const m = seconds / 60;
  if (m < 60) return `${m.toFixed(0)}m`;
  const h = m / 60;
  if (h < 24) return `${h.toFixed(1)}h`;
  return `${(h / 24).toFixed(1)}d`;
}
