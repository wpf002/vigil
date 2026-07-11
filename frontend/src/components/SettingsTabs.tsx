import { NavLink } from "react-router-dom";

const TABS = [
  { to: "/settings/api-keys", label: "API Keys" },
  { to: "/settings/webhooks", label: "Webhooks" },
  { to: "/settings/enrichment", label: "Enrichment Sources" },
];

/** Shared sub-navigation across the Settings pages. */
export function SettingsTabs() {
  return (
    <div className="mb-5 flex flex-wrap gap-1 border-b border-border">
      {TABS.map((t) => (
        <NavLink
          key={t.to}
          to={t.to}
          className={({ isActive }) =>
            `px-3 py-2 text-[12px] font-mono border-b-2 -mb-px transition-colors ${
              isActive
                ? "border-accent text-fg"
                : "border-transparent text-fg-muted hover:text-fg"
            }`
          }
        >
          {t.label}
        </NavLink>
      ))}
    </div>
  );
}
