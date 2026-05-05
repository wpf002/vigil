import { NavLink } from "react-router-dom";
import { ShieldAlert, ScrollText, Radar, Settings, Activity } from "lucide-react";
import type { ReactNode } from "react";

interface NavItem {
  to: string;
  label: string;
  icon: typeof ShieldAlert;
  active?: boolean;
}

const NAV: NavItem[] = [
  { to: "/attacks", label: "Active Threats", icon: ShieldAlert, active: true },
  { to: "/history", label: "Resolved", icon: ScrollText },
  { to: "/detections", label: "Detections", icon: Radar },
  { to: "/health", label: "Pipeline", icon: Activity },
  { to: "/settings", label: "Settings", icon: Settings },
];

export function AppLayout({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen flex">
      <Sidebar />
      <main className="flex-1 min-w-0 overflow-auto">{children}</main>
    </div>
  );
}

function Sidebar() {
  return (
    <aside className="w-52 shrink-0 border-r border-border bg-surface flex flex-col">
      <div className="h-12 px-4 flex items-center gap-2 border-b border-border">
        <span className="inline-block w-1.5 h-1.5 rounded-sm bg-accent" />
        <span className="font-mono text-[13px] tracking-[0.3em] text-fg">
          VIGIL
        </span>
      </div>

      <nav className="p-2 flex-1 space-y-0.5">
        {NAV.map((item) => (
          <NavItemLink key={item.to} item={item} />
        ))}
      </nav>
    </aside>
  );
}

function NavItemLink({ item }: { item: NavItem }) {
  const Icon = item.icon;

  if (!item.active) {
    return (
      <div
        className="px-3 py-2 flex items-center gap-3 text-[13px] font-mono text-fg-faint cursor-default"
        title="Coming soon"
      >
        <Icon size={14} />
        <span>{item.label}</span>
      </div>
    );
  }

  return (
    <NavLink
      to={item.to}
      className={({ isActive }) =>
        `px-3 py-2 flex items-center gap-3 text-[13px] font-mono rounded-sm border-l-2 transition-colors ${
          isActive
            ? "border-accent bg-accent/10 text-fg"
            : "border-transparent text-fg-muted hover:text-fg hover:bg-surface-2"
        }`
      }
    >
      <Icon size={14} />
      <span>{item.label}</span>
    </NavLink>
  );
}
