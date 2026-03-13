import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import Layout from './components/layout/Layout'
import CloudPostureDashboard from './pages/CloudPostureDashboard'
import FindingBrowser from './pages/FindingBrowser'
import AccountSubscriptionView from './pages/AccountSubscriptionView'
import ComplianceScorecard from './pages/ComplianceScorecard'
import IaCPreDeployGate from './pages/IaCPreDeployGate'
import DriftDetector from './pages/DriftDetector'
import PublicExposureMonitor from './pages/PublicExposureMonitor'
import Administration from './pages/Administration'

function App() {
  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<CloudPostureDashboard />} />
          <Route path="/findings" element={<FindingBrowser />} />
          <Route path="/accounts" element={<AccountSubscriptionView />} />
          <Route path="/compliance" element={<ComplianceScorecard />} />
          <Route path="/iac" element={<IaCPreDeployGate />} />
          <Route path="/drift" element={<DriftDetector />} />
          <Route path="/exposure" element={<PublicExposureMonitor />} />
          <Route path="/admin" element={<Administration />} />
        </Routes>
      </Layout>
    </Router>
  )
}

export default App
