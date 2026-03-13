import { useEffect, useState } from 'react'
import { cspmApi } from '../api/client'
import { Code2, Upload, CheckCircle2, XCircle } from 'lucide-react'

export default function IaCPreDeployGate() {
  const [scans, setScans] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [showScanForm, setShowScanForm] = useState(false)
  const [scanForm, setScanForm] = useState({ template_content: '', template_path: '', framework: 'terraform', repository: '', branch: 'main' })
  const [scanning, setScanning] = useState(false)
  const [scanResult, setScanResult] = useState<any>(null)

  useEffect(() => {
    cspmApi.listIaCScans().then(r => { setScans(r.data); setLoading(false) }).catch(() => setLoading(false))
  }, [])

  const handleScan = async () => {
    if (!scanForm.template_content || !scanForm.template_path) return
    setScanning(true)
    try {
      const res = await cspmApi.triggerIaCScan(scanForm)
      setScanResult(res.data)
      setScans(prev => [res.data, ...prev])
    } catch (e) { console.error(e) }
    finally { setScanning(false) }
  }

  if (loading) return <div className="text-center py-12">Loading IaC scans...</div>

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-gray-900 flex items-center gap-2">
          <Code2 size={24} /> IaC Pre-Deploy Gate
        </h2>
        <button onClick={() => { setShowScanForm(!showScanForm); setScanResult(null) }}
          className="px-4 py-2 bg-cyan-600 text-white rounded-lg text-sm hover:bg-cyan-700 transition flex items-center gap-2">
          <Upload size={16} /> New Scan
        </button>
      </div>

      {/* Scan Form */}
      {showScanForm && (
        <div className="bg-white p-6 rounded-lg shadow-sm space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Template Path</label>
              <input type="text" className="w-full border rounded px-3 py-2 text-sm" placeholder="infra/main.tf"
                value={scanForm.template_path} onChange={e => setScanForm({ ...scanForm, template_path: e.target.value })} />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Framework</label>
              <select className="w-full border rounded px-3 py-2 text-sm" value={scanForm.framework}
                onChange={e => setScanForm({ ...scanForm, framework: e.target.value })}>
                <option value="terraform">Terraform</option>
                <option value="cloudformation">CloudFormation</option>
                <option value="bicep">Bicep</option>
                <option value="pulumi">Pulumi</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Branch</label>
              <input type="text" className="w-full border rounded px-3 py-2 text-sm" placeholder="main"
                value={scanForm.branch} onChange={e => setScanForm({ ...scanForm, branch: e.target.value })} />
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Template Content</label>
            <textarea rows={8} className="w-full border rounded px-3 py-2 text-sm font-mono"
              placeholder="Paste your IaC template content here..."
              value={scanForm.template_content} onChange={e => setScanForm({ ...scanForm, template_content: e.target.value })} />
          </div>
          <button onClick={handleScan} disabled={scanning}
            className="px-6 py-2 bg-cyan-600 text-white rounded-lg text-sm hover:bg-cyan-700 transition disabled:opacity-50">
            {scanning ? 'Scanning...' : 'Run Scan'}
          </button>

          {scanResult && (
            <div className={`p-4 rounded-lg ${scanResult.failed_checks === 0 ? 'bg-green-50 border border-green-200' : 'bg-red-50 border border-red-200'}`}>
              <div className="flex items-center gap-2 font-semibold">
                {scanResult.failed_checks === 0
                  ? <><CheckCircle2 size={20} className="text-green-600" /> Scan Passed &mdash; Deployment Allowed</>
                  : <><XCircle size={20} className="text-red-600" /> {scanResult.failed_checks} Issue(s) Found &mdash; Deployment Blocked</>}
              </div>
              <p className="text-sm text-gray-600 mt-1">{scanResult.passed_checks} checks passed, {scanResult.total_resources} resources scanned in {scanResult.scan_duration_seconds}s</p>
            </div>
          )}
        </div>
      )}

      {/* Scan History */}
      <div className="bg-white rounded-lg shadow-sm">
        <div className="px-6 py-4 border-b"><h3 className="font-semibold">Recent Scans</h3></div>
        <table className="w-full text-sm">
          <thead className="bg-gray-50 border-b"><tr>
            <th className="text-left px-4 py-3">Template</th>
            <th className="text-left px-4 py-3">Framework</th>
            <th className="text-left px-4 py-3">Repository</th>
            <th className="text-left px-4 py-3">Branch</th>
            <th className="text-left px-4 py-3">Result</th>
            <th className="text-left px-4 py-3">Duration</th>
            <th className="text-left px-4 py-3">Scanned</th>
          </tr></thead>
          <tbody>
            {scans.map((s: any) => (
              <tr key={s.scan_id} className="border-b">
                <td className="px-4 py-3 font-mono text-xs">{s.template_path}</td>
                <td className="px-4 py-3 capitalize">{s.framework}</td>
                <td className="px-4 py-3 text-gray-600">{s.repository}</td>
                <td className="px-4 py-3">{s.branch}</td>
                <td className="px-4 py-3">
                  {s.failed_checks === 0
                    ? <span className="text-green-600 font-semibold flex items-center gap-1"><CheckCircle2 size={14} /> Pass</span>
                    : <span className="text-red-600 font-semibold flex items-center gap-1"><XCircle size={14} /> {s.failed_checks} fail</span>}
                </td>
                <td className="px-4 py-3 font-mono text-xs">{s.scan_duration_seconds}s</td>
                <td className="px-4 py-3 text-xs text-gray-500">{new Date(s.scanned_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
