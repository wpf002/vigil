import { NavLink, useNavigate } from "react-router-dom";
import {
  ShieldAlert,
  ScrollText,
  Radar,
  Settings,
  Activity,
  LogOut,
  ListChecks,
  BarChart3,
  FileCheck,
  FlaskConical,
  ShieldQuestion,
} from "lucide-react";
import type { ReactNode } from "react";
import { useAuthStore } from "@/store/authStore";
import { logout as apiLogout } from "@/api/auth";

interface NavItem {
  to: string;
  label: string;
  icon: typeof ShieldAlert;
  active?: boolean;
}

const NAV: NavItem[] = [
  { to: "/dashboard", label: "Dashboard", icon: BarChart3, active: true },
  { to: "/attacks", label: "Active Threats", icon: ShieldAlert, active: true },
  { to: "/history", label: "Resolved", icon: ScrollText, active: true },
  { to: "/detections", label: "Detections", icon: Radar, active: true },
  { to: "/enrichment", label: "IOC Enrichment", icon: ShieldQuestion, active: true },
  { to: "/playbooks", label: "Playbooks", icon: ListChecks, active: true },
  { to: "/simulations", label: "Simulation", icon: FlaskConical, active: true },
  { to: "/compliance", label: "Compliance", icon: FileCheck, active: true },
  { to: "/pipeline", label: "Pipeline", icon: Activity, active: true },
  { to: "/settings/api-keys", label: "Settings", icon: Settings, active: true },
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
  const navigate = useNavigate();
  const user = useAuthStore((s) => s.user);
  const accessToken = useAuthStore((s) => s.accessToken);
  const clear = useAuthStore((s) => s.clear);

  async function handleLogout() {
    const refresh = useAuthStore.getState().getRefreshToken();
    try {
      if (accessToken && refresh) await apiLogout(accessToken, refresh);
    } catch {
      // Logout API failure is non-fatal — clear local state regardless.
    }
    clear();
    navigate("/login", { replace: true });
  }

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

      <div className="border-t border-border p-3 space-y-2">
        {user && (
          <div className="text-[11px] font-mono text-fg-muted truncate">
            <div className="text-fg truncate" title={user.email}>{user.email}</div>
            <div className="text-fg-faint">
              {user.role.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}
            </div>
          </div>
        )}
        <button
          type="button"
          onClick={handleLogout}
          className="w-full flex items-center gap-2 px-2 py-1.5 text-[12px] font-mono
                     text-fg-muted hover:text-fg hover:bg-surface-2 rounded-sm transition-colors"
        >
          <LogOut size={13} />
          <span>Sign Out</span>
        </button>
      </div>
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
