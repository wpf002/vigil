import { useEffect } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { AppLayout } from "@/components/AppLayout";
import { AttackList } from "@/pages/AttackList";
import { AttackDetail } from "@/pages/AttackDetail";
import { DetectionLibrary } from "@/pages/DetectionLibrary";
import { DetectionDetail } from "@/pages/DetectionDetail";
import { PlaybookList } from "@/pages/PlaybookList";
import { PlaybookDetail } from "@/pages/PlaybookDetail";
import { PlaybookBuilder } from "@/pages/PlaybookBuilder";
import { LoginPage } from "@/pages/LoginPage";
import { RegisterPage } from "@/pages/RegisterPage";
import { MarketplacePage } from "@/pages/MarketplacePage";
import { ExecutiveDashboard } from "@/pages/ExecutiveDashboard";
import { CompliancePage } from "@/pages/CompliancePage";
import { APIKeysPage } from "@/pages/APIKeysPage";
import { WebhooksPage } from "@/pages/WebhooksPage";
import { OnboardingWizard } from "@/pages/OnboardingWizard";
import { PipelinePage } from "@/pages/PipelinePage";
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
                <Route path="/history" element={<AttackList resolved />} />
                <Route path="/attacks/:id" element={<AttackDetail />} />
                <Route path="/detections" element={<DetectionLibrary />} />
                <Route path="/detections/:id" element={<DetectionDetail />} />
                <Route path="/marketplace" element={<MarketplacePage />} />
                <Route path="/dashboard" element={<ExecutiveDashboard />} />
                <Route path="/compliance" element={<CompliancePage />} />
                <Route path="/settings/api-keys" element={<APIKeysPage />} />
                <Route path="/settings/webhooks" element={<WebhooksPage />} />
                <Route path="/onboarding" element={<OnboardingWizard />} />
                <Route path="/pipeline" element={<PipelinePage />} />
                <Route path="/settings" element={<Navigate to="/settings/api-keys" replace />} />
                <Route path="/playbooks" element={<PlaybookList />} />
                <Route path="/playbooks/build" element={<PlaybookBuilder />} />
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
