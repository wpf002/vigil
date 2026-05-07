import { useEffect, useState, type ReactNode } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useAuthStore } from "@/store/authStore";
import { refresh } from "@/api/auth";

/** Gate every authenticated route. On first paint we may not have an
 *  access_token in memory (e.g. after a hard refresh) — try one silent
 *  refresh from the persisted refresh_token before redirecting.
 */
export function ProtectedRoute({ children }: { children: ReactNode }) {
  const location = useLocation();
  const accessToken = useAuthStore((s) => s.accessToken);
  const setAccessToken = useAuthStore((s) => s.setAccessToken);
  const setRefreshToken = useAuthStore((s) => s.setRefreshToken);
  const clear = useAuthStore((s) => s.clear);

  const [resolving, setResolving] = useState<boolean>(!accessToken);

  useEffect(() => {
    if (accessToken) {
      setResolving(false);
      return;
    }
    const stored = localStorage.getItem("vigil_refresh_token");
    if (!stored) {
      setResolving(false);
      return;
    }
    let cancelled = false;
    refresh(stored)
      .then((res) => {
        if (cancelled) return;
        setAccessToken(res.access_token);
        setRefreshToken(res.refresh_token);
      })
      .catch(() => {
        if (cancelled) return;
        clear();
      })
      .finally(() => {
        if (cancelled) return;
        setResolving(false);
      });
    return () => {
      cancelled = true;
    };
  }, [accessToken, setAccessToken, setRefreshToken, clear]);

  if (resolving) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-bg text-fg-muted font-mono text-sm">
        Restoring session…
      </div>
    );
  }

  if (!useAuthStore.getState().accessToken) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }

  return <>{children}</>;
}
