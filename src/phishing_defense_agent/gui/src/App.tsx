import { Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/layout/Layout";
import PhishingDashboard from "./pages/PhishingDashboard";
import QuarantineQueue from "./pages/QuarantineQueue";
import VerdictDetail from "./pages/VerdictDetail";
import CampaignTracker from "./pages/CampaignTracker";
import URLAttachmentAnalyzer from "./pages/URLAttachmentAnalyzer";
import UserAwareness from "./pages/UserAwareness";
import ReportedEmails from "./pages/ReportedEmails";
import Administration from "./pages/Administration";

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<PhishingDashboard />} />
        <Route path="/quarantine" element={<QuarantineQueue />} />
        <Route path="/verdicts/:id" element={<VerdictDetail />} />
        <Route path="/campaigns" element={<CampaignTracker />} />
        <Route path="/analyzer" element={<URLAttachmentAnalyzer />} />
        <Route path="/awareness" element={<UserAwareness />} />
        <Route path="/reported" element={<ReportedEmails />} />
        <Route path="/admin" element={<Administration />} />
      </Routes>
    </Layout>
  );
}
