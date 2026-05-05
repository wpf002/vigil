import { ArrowUp, Minus, ArrowDown } from "lucide-react";
import type { Momentum } from "@/types/attacks";

interface Props {
  momentum: Momentum;
  size?: "sm" | "md";
}

export function MomentumIndicator({ momentum, size = "sm" }: Props) {
  const iconSize = size === "sm" ? 11 : 14;
  const styles =
    momentum === "Increasing"
      ? "border-accent/40 bg-accent/10 text-accent-hover"
      : momentum === "Decreasing"
        ? "border-border-strong bg-surface-2 text-fg-muted"
        : "border-border-strong bg-surface-2 text-fg-muted";
  const Icon =
    momentum === "Increasing"
      ? ArrowUp
      : momentum === "Decreasing"
        ? ArrowDown
        : Minus;

  return (
    <span className={`vigil-badge ${styles}`}>
      <Icon size={iconSize} className="-ml-0.5 mr-1" />
      {momentum}
    </span>
  );
}
