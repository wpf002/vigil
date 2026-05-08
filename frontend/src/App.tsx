import { useEffect } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { AppLayout } from "@/components/AppLayout";
import { AttackList } from "@/pages/AttackList";
import { AttackDetail } from "@/pages/AttackDetail";
import { DetectionLibrary } from "@/pages/DetectionLibrary";
import { DetectionDetail } from "@/pages/DetectionDetail";
import { PlaybookList } from "@/pages/PlaybookList";
import { PlaybookDetail } from "@/pages/PlaybookDetail";
import { LoginPage } from "@/pages/LoginPage";
import { RegisterPage } from "@/pages/RegisterPage";
import { ProtectedRoute } from "@/components/ProtectedRoute";
import { useAuthStore } from "@/store/authStore";

export function App() {
  const hydrate = useAuthStore((s) => s.hydrate);

  useEffect(() => {
    hydrate();
  }, [hydrate]);

  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />

      <Route
        path="/*"
        element={
          <ProtectedRoute>
            <AppLayout>
              <Routes>
                <Route path="/" element={<Navigate to="/attacks" replace />} />
                <Route path="/attacks" element={<AttackList />} />
                <Route path="/attacks/:id" element={<AttackDetail />} />
                <Route path="/detections" element={<DetectionLibrary />} />
                <Route path="/detections/:id" element={<DetectionDetail />} />
                <Route path="/playbooks" element={<PlaybookList />} />
                <Route path="/playbooks/:id" element={<PlaybookDetail />} />
                <Route
                  path="*"
                  element={
                    <div className="px-6 py-12 font-mono text-sm text-fg-muted">
                      Not found.
                    </div>
                  }
                />
              </Routes>
            </AppLayout>
          </ProtectedRoute>
        }
      />
    </Routes>
  );
}
