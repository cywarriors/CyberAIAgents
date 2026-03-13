import { Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/layout/Layout";
import IdentityDashboard from "./pages/IdentityDashboard";
import RiskScores from "./pages/RiskScores";
import AlertsView from "./pages/AlertsView";
import SoDViolations from "./pages/SoDViolations";
import UserRiskDetail from "./pages/UserRiskDetail";
import Recommendations from "./pages/Recommendations";
import Administration from "./pages/Administration";

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<IdentityDashboard />} />
        <Route path="/risk-scores" element={<RiskScores />} />
        <Route path="/alerts" element={<AlertsView />} />
        <Route path="/sod-violations" element={<SoDViolations />} />
        <Route path="/users/:id" element={<UserRiskDetail />} />
        <Route path="/recommendations" element={<Recommendations />} />
        <Route path="/admin" element={<Administration />} />
      </Routes>
    </Layout>
  );
}
