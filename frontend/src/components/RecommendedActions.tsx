import { CheckCircle2, Circle, Clock } from "lucide-react";
import type { ResponseAction } from "@/types/attacks";

interface Props {
  actions: ResponseAction[];
  onComplete: (actionIndex: number) => void;
}

export function RecommendedActions({ actions, onComplete }: Props) {
  const grouped = {
    immediate: [] as { action: ResponseAction; index: number }[],
    follow_up: [] as { action: ResponseAction; index: number }[],
    other: [] as { action: ResponseAction; index: number }[],
  };
  actions.forEach((action, index) => {
    if (action.priority === "immediate") grouped.immediate.push({ action, index });
    else if (action.priority === "follow_up") grouped.follow_up.push({ action, index });
    else grouped.other.push({ action, index });
  });

  if (actions.length === 0) {
    return (
      <div className="vigil-card p-4 text-sm text-fg-muted">
        No recommended actions yet.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {grouped.immediate.length > 0 && (
        <ActionGroup
          title="Immediate"
          accent="text-danger"
          items={grouped.immediate}
          onComplete={onComplete}
        />
      )}
      {grouped.follow_up.length > 0 && (
        <ActionGroup
          title="Follow-up"
          accent="text-warning"
          items={grouped.follow_up}
          onComplete={onComplete}
        />
      )}
      {grouped.other.length > 0 && (
        <ActionGroup
          title="Other"
          accent="text-fg-muted"
          items={grouped.other}
          onComplete={onComplete}
        />
      )}
    </div>
  );
}

function ActionGroup({
  title,
  accent,
  items,
  onComplete,
}: {
  title: string;
  accent: string;
  items: { action: ResponseAction; index: number }[];
  onComplete: (index: number) => void;
}) {
  return (
    <div className="vigil-card p-4">
      <h4
        className={`text-xs uppercase tracking-wider font-mono mb-3 ${accent}`}
      >
        {title}
      </h4>
      <ul className="space-y-2">
        {items.map(({ action, index }) => (
          <li
            key={index}
            className="flex items-start gap-3 text-sm font-mono"
          >
            <button
              type="button"
              onClick={() => !action.completed && onComplete(index)}
              disabled={action.completed}
              className="mt-0.5 text-fg-muted hover:text-accent disabled:opacity-100 disabled:cursor-default"
              aria-label="Mark action complete"
            >
              {action.completed ? (
                <CheckCircle2 size={16} className="text-success" />
              ) : (
                <Circle size={16} />
              )}
            </button>
            <div className="flex-1 min-w-0">
              <div className={action.completed ? "line-through opacity-60" : ""}>
                {action.description}
              </div>
              <div className="text-xs text-fg-muted mt-0.5 flex items-center gap-2">
                <span className="opacity-70">{action.action_type}</span>
                <span className="opacity-50">→</span>
                <span>{action.target_entity}</span>
                {action.automated && (
                  <span className="opacity-70 inline-flex items-center gap-1">
                    <Clock size={10} /> automated
                  </span>
                )}
              </div>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
