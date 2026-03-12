import { Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/layout/Layout";
import TriageDashboard from "./pages/TriageDashboard";
import IncidentQueue from "./pages/IncidentQueue";
import IncidentDetail from "./pages/IncidentDetail";
import CorrelationViewer from "./pages/CorrelationViewer";
import AnalystWorkload from "./pages/AnalystWorkload";
import TriageAnalytics from "./pages/TriageAnalytics";
import PlaybookRecommendations from "./pages/PlaybookRecommendations";
import Administration from "./pages/Administration";

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<TriageDashboard />} />
        <Route path="/incidents" element={<IncidentQueue />} />
        <Route path="/incidents/:id" element={<IncidentDetail />} />
        <Route path="/correlations" element={<CorrelationViewer />} />
        <Route path="/analysts" element={<AnalystWorkload />} />
        <Route path="/analytics" element={<TriageAnalytics />} />
        <Route path="/playbooks" element={<PlaybookRecommendations />} />
        <Route path="/admin" element={<Administration />} />
      </Routes>
    </Layout>
  );
}
