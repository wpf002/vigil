import { Check } from "lucide-react";
import type { ResponseStatus } from "@/types/attacks";
import { timeAgo } from "@/lib/format";

type Step = "containment" | "eradication" | "recovery";

const STEPS: { key: Step; label: string; desc: string }[] = [
  { key: "containment", label: "Contain", desc: "Isolate affected hosts and accounts to stop the spread" },
  { key: "eradication", label: "Eradicate", desc: "Remove the attacker's foothold, persistence, and tooling" },
  { key: "recovery", label: "Recover", desc: "Restore services and confirm the threat is gone" },
];

interface Props {
  status: ResponseStatus;
  onToggle: (step: Step, value: boolean) => void;
  disabled?: boolean;
}

export function TriageChecklist({ status, onToggle, disabled }: Props) {
  const doneCount = STEPS.filter((s) => status[s.key]).length;
  return (
    <div className="vigil-card p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="text-[10px] uppercase tracking-[0.18em] text-fg-faint font-mono">
          Triage
        </div>
        <div className="text-[11px] font-mono text-fg-faint tabular-nums">
          {doneCount}/{STEPS.length}
        </div>
      </div>
      <ol className="space-y-2">
        {STEPS.map((s, i) => {
          const done = status[s.key];
          const atKey = `${s.key}_at` as keyof ResponseStatus;
          const at = status[atKey] as string | null | undefined;
          return (
            <li key={s.key} className="flex items-start gap-3">
              <button
                type="button"
                disabled={disabled}
                onClick={() => onToggle(s.key, !done)}
                aria-label={`Toggle ${s.label}`}
                className={`w-5 h-5 mt-0.5 flex items-center justify-center rounded-sm border text-[10px] font-mono ${
                  done
                    ? "border-success bg-success/10 text-success"
                    : "border-border-strong bg-surface-2 text-fg-faint hover:border-accent/50"
                } disabled:opacity-50`}
              >
                {done ? <Check size={12} /> : i + 1}
              </button>
              <div className="flex-1">
                <div className={`text-sm font-mono ${done ? "text-fg" : "text-fg-muted"}`}>
                  {s.label}
                </div>
                <div className="text-[11px] font-mono text-fg-faint">{s.desc}</div>
                {done && at && (
                  <div className="text-[10px] font-mono text-fg-faint mt-0.5">done {timeAgo(at)}</div>
                )}
              </div>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
