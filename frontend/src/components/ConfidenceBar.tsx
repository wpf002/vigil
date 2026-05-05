import { confidenceColor, pct } from "@/lib/format";

interface Props {
  value: number; // 0..1
  showLabel?: boolean;
  height?: "sm" | "md" | "lg";
}

export function ConfidenceBar({ value, showLabel = true, height = "md" }: Props) {
  const clamped = Math.max(0, Math.min(1, value));
  const heightClass =
    height === "sm" ? "h-1.5" : height === "lg" ? "h-3" : "h-2";

  return (
    <div className="w-full">
      <div className="flex items-center justify-between mb-1 text-xs">
        {showLabel && (
          <>
            <span className="text-fg-muted font-mono">Confidence</span>
            <span className="font-mono text-fg">{pct(clamped)}</span>
          </>
        )}
      </div>
      <div
        className={`w-full ${heightClass} bg-surface-2 border border-border rounded overflow-hidden`}
      >
        <div
          className={`${confidenceColor(clamped)} h-full transition-all duration-500 ease-out`}
          style={{ width: `${clamped * 100}%` }}
        />
      </div>
    </div>
  );
}
