import { Routes, Route, Navigate, useNavigate } from "react-router-dom";
import { useEffect, useState } from "react";
import { Layout } from "./components/Layout";
import LoginPage from "./pages/LoginPage";
import WorkspacesPage from "./pages/WorkspacesPage";
import TargetsPage from "./pages/TargetsPage";
import JobsPage from "./pages/JobsPage";
import FindingsPage from "./pages/FindingsPage";
import EvidencePage from "./pages/EvidencePage";
import { clearToken, isAuthenticated } from "./lib/auth";

function Protected({ children }: { children: React.ReactNode }) {
  const [authed, setAuthed] = useState(isAuthenticated());
  const navigate = useNavigate();

  useEffect(() => {
    const handler = () => {
      clearToken();
      setAuthed(false);
      navigate("/login");
    };
    window.addEventListener("osint:unauthorized", handler);
    return () => window.removeEventListener("osint:unauthorized", handler);
  }, [navigate]);

  if (!authed) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}

export default function App() {
  const navigate = useNavigate();

  function handleLogout() {
    clearToken();
    navigate("/login");
  }

  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/"
        element={
          <Protected>
            <Layout onLogout={handleLogout} />
          </Protected>
        }
      >
        <Route path="workspaces" element={<WorkspacesPage />} />
        <Route path="targets" element={<TargetsPage />} />
        <Route path="jobs" element={<JobsPage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="evidence" element={<EvidencePage />} />
        <Route index element={<Navigate to="/workspaces" replace />} />
        <Route path="*" element={<Navigate to="/workspaces" replace />} />
      </Route>
    </Routes>
  );
}
