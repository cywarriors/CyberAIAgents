export default function DriftAlerts() {
  return (
    <div>
      <h1 className="text-xl font-bold text-green-400 mb-4">Drift Alerts</h1>
      <p className="text-gray-400 text-sm">Compliance drift alerts are generated when framework scores drop by more than the configured threshold within a 7-day period.</p>
      <div className="mt-4 bg-gray-800 rounded p-4 text-sm text-gray-500">No drift alerts detected in the current assessment cycle.</div>
    </div>
  )
}
