import { formatDistanceToNow, parseISO } from "date-fns";
import type { ImpactLevel, MITRETactic } from "@/types/attacks";

export function timeAgo(iso: string): string {
  try {
    // date-fns prepends "about" / "almost" / "over" to inexact distances.
    // Strip those for a tighter SOC look.
    return formatDistanceToNow(parseISO(iso), { addSuffix: true }).replace(
      /^(about|almost|over|less than)\s+/,
      "",
    );
  } catch {
    return iso;
  }
}

export function pct(value: number): string {
  return `${Math.round(value * 100)}%`;
}

const HIGH_RISK_PHASES: MITRETactic[] = [
  "lateral-movement",
  "exfiltration",
  "impact",
  "command-and-control",
];
const ELEVATED_RISK_PHASES: MITRETactic[] = [
  "credential-access",
  "privilege-escalation",
  "defense-evasion",
];

// Restrained palette: only the most-dangerous phases get red.
// Everything else is grayscale with subtle differentiation.
export function phaseColorClasses(phase: MITRETactic): string {
  if (HIGH_RISK_PHASES.includes(phase)) {
    return "border-accent/50 bg-accent/15 text-accent-hover";
  }
  if (ELEVATED_RISK_PHASES.includes(phase)) {
    return "border-warning/40 bg-warning/10 text-warning";
  }
  return "border-border-strong bg-surface-2 text-fg-muted";
}

export function impactColorClasses(impact: ImpactLevel): string {
  switch (impact) {
    case "Critical":
      return "border-accent bg-accent/20 text-accent-hover";
    case "High":
      return "border-accent/40 bg-accent/10 text-accent";
    case "Medium":
      return "border-warning/40 bg-warning/10 text-warning";
    case "Low":
      return "border-border-strong bg-surface-2 text-fg-muted";
  }
}

export function confidenceColor(c: number): string {
  if (c < 0.5) return "bg-fg-faint";
  if (c < 0.7) return "bg-warning";
  if (c < 0.85) return "bg-accent";
  return "bg-accent-hover";
}

export function phaseLabel(phase: MITRETactic): string {
  return phase
    .split("-")
    .map((w) => w[0].toUpperCase() + w.slice(1))
    .join(" ");
}

/** Title-case any kebab/snake/space-separated string. Safe for display only. */
export function titleCase(value: string | null | undefined): string {
  if (!value) return "—";
  return value
    .replace(/[-_]/g, " ")
    .split(" ")
    .filter(Boolean)
    .map((w) => w[0].toUpperCase() + w.slice(1).toLowerCase())
    .join(" ");
}

export function yesNo(value: boolean | null | undefined): string {
  if (value === true) return "Yes";
  if (value === false) return "No";
  return "—";
}
