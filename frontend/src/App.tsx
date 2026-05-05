import { Navigate, Route, Routes } from "react-router-dom";
import { AppLayout } from "@/components/AppLayout";
import { AttackList } from "@/pages/AttackList";
import { AttackDetail } from "@/pages/AttackDetail";

export function App() {
  return (
    <AppLayout>
      <Routes>
        <Route path="/" element={<Navigate to="/attacks" replace />} />
        <Route path="/attacks" element={<AttackList />} />
        <Route path="/attacks/:id" element={<AttackDetail />} />
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
  );
}
