import { Routes, Route } from 'react-router-dom';
import Layout from './components/layout/Layout';
import IntelDashboard from './pages/IntelDashboard';
import IOCExplorer from './pages/IOCExplorer';
import ThreatBriefViewer from './pages/ThreatBriefViewer';
import ActorDatabase from './pages/ActorDatabase';
import FeedManager from './pages/FeedManager';
import IOCLifecycleManager from './pages/IOCLifecycleManager';
import DetectionMapping from './pages/DetectionMapping';
import Administration from './pages/Administration';

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<IntelDashboard />} />
        <Route path="/iocs" element={<IOCExplorer />} />
        <Route path="/briefs" element={<ThreatBriefViewer />} />
        <Route path="/actors" element={<ActorDatabase />} />
        <Route path="/feeds" element={<FeedManager />} />
        <Route path="/lifecycle" element={<IOCLifecycleManager />} />
        <Route path="/detection" element={<DetectionMapping />} />
        <Route path="/admin" element={<Administration />} />
      </Routes>
    </Layout>
  );
}

export default App;
