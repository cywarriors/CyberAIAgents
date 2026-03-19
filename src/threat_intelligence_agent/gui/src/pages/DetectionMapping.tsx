import { useQuery } from '@tanstack/react-query';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { Target, Shield, CheckCircle, AlertTriangle } from 'lucide-react';

// Static ATT&CK detection mapping data for demonstration
const ATTCK_COVERAGE_DATA = [
  { technique: 'T1566', name: 'Phishing', tactic: 'Initial Access', rules: 8, coverage: 95, ioc_count: 342 },
  { technique: 'T1059', name: 'Command & Scripting', tactic: 'Execution', rules: 12, coverage: 88, ioc_count: 217 },
  { technique: 'T1071', name: 'App Layer Protocol', tactic: 'C&C', rules: 7, coverage: 82, ioc_count: 196 },
  { technique: 'T1036', name: 'Masquerading', tactic: 'Defense Evasion', rules: 5, coverage: 71, ioc_count: 154 },
  { technique: 'T1055', name: 'Process Injection', tactic: 'Privilege Escalation', rules: 9, coverage: 85, ioc_count: 289 },
  { technique: 'T1027', name: 'Obfuscated Files', tactic: 'Defense Evasion', rules: 6, coverage: 67, ioc_count: 123 },
  { technique: 'T1547', name: 'Boot Autostart', tactic: 'Persistence', rules: 4, coverage: 60, ioc_count: 98 },
  { technique: 'T1086', name: 'PowerShell', tactic: 'Execution', rules: 10, coverage: 91, ioc_count: 387 },
  { technique: 'T1003', name: 'Credential Dumping', tactic: 'Credential Access', rules: 7, coverage: 78, ioc_count: 201 },
  { technique: 'T1082', name: 'System Info Discovery', tactic: 'Discovery', rules: 3, coverage: 45, ioc_count: 67 },
  { technique: 'T1560', name: 'Archive Collected Data', tactic: 'Collection', rules: 4, coverage: 55, ioc_count: 89 },
  { technique: 'T1048', name: 'Exfiltration Over Alt Protocol', tactic: 'Exfiltration', rules: 5, coverage: 70, ioc_count: 134 },
  { technique: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact', rules: 11, coverage: 93, ioc_count: 412 },
  { technique: 'T1190', name: 'Exploit Public-Facing App', tactic: 'Initial Access', rules: 8, coverage: 80, ioc_count: 267 },
  { technique: 'T1021', name: 'Remote Services', tactic: 'Lateral Movement', rules: 6, coverage: 72, ioc_count: 178 },
];

const GAP_TECHNIQUES = [
  { technique: 'T1119', name: 'Automated Collection', tactic: 'Collection', coverage: 0 },
  { technique: 'T1123', name: 'Audio Capture', tactic: 'Collection', coverage: 0 },
  { technique: 'T1176', name: 'Browser Extensions', tactic: 'Persistence', coverage: 20 },
  { technique: 'T1115', name: 'Clipboard Data', tactic: 'Collection', coverage: 15 },
];

const COVERAGE_COLOR = (coverage: number) =>
  coverage >= 80 ? '#10b981' : coverage >= 60 ? '#f59e0b' : '#ef4444';

export default function DetectionMapping() {
  const avgCoverage = Math.round(
    ATTCK_COVERAGE_DATA.reduce((sum, t) => sum + t.coverage, 0) / ATTCK_COVERAGE_DATA.length
  );
  const totalRules = ATTCK_COVERAGE_DATA.reduce((sum, t) => sum + t.rules, 0);
  const wellCovered = ATTCK_COVERAGE_DATA.filter((t) => t.coverage >= 80).length;
  const gaps = GAP_TECHNIQUES.length + ATTCK_COVERAGE_DATA.filter((t) => t.coverage < 50).length;

  // fetchDashboardMetrics is available via other pages — we just use static data here per SRS §12 demo scope
  const { isLoading } = useQuery({
    queryKey: ['detection-mapping-health'],
    queryFn: async () => ({ ok: true }),
    staleTime: Infinity,
  });

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Detection Mapping</h2>
        <p className="text-gray-500 dark:text-gray-400">
          MITRE ATT&CK technique coverage and detection rule gap analysis
        </p>
      </div>

      {/* Summary KPIs */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <div className="rounded-xl bg-white p-4 shadow-sm dark:bg-gray-800">
          <p className="text-sm text-gray-500 dark:text-gray-400">Avg Coverage</p>
          <p className="mt-1 text-2xl font-bold text-blue-600">{avgCoverage}%</p>
          <p className="text-xs text-gray-500 dark:text-gray-400">across {ATTCK_COVERAGE_DATA.length} techniques</p>
        </div>
        <div className="rounded-xl bg-white p-4 shadow-sm dark:bg-gray-800">
          <p className="text-sm text-gray-500 dark:text-gray-400">Detection Rules</p>
          <p className="mt-1 text-2xl font-bold text-green-600">{totalRules}</p>
          <p className="text-xs text-gray-500 dark:text-gray-400">active rules in SIEM/EDR</p>
        </div>
        <div className="rounded-xl bg-white p-4 shadow-sm dark:bg-gray-800">
          <p className="text-sm text-gray-500 dark:text-gray-400">Well Covered</p>
          <p className="mt-1 text-2xl font-bold text-green-600">{wellCovered}</p>
          <p className="text-xs text-gray-500 dark:text-gray-400">techniques ≥80% coverage</p>
        </div>
        <div className="rounded-xl bg-white p-4 shadow-sm dark:bg-gray-800">
          <p className="text-sm text-gray-500 dark:text-gray-400">Coverage Gaps</p>
          <p className="mt-1 text-2xl font-bold text-red-600">{gaps}</p>
          <p className="text-xs text-gray-500 dark:text-gray-400">techniques needing rules</p>
        </div>
      </div>

      {/* Coverage chart */}
      <div className="rounded-xl bg-white p-5 shadow-sm dark:bg-gray-800">
        <h3 className="mb-4 font-semibold text-gray-900 dark:text-white">ATT&CK Technique Coverage Distribution</h3>
        <ResponsiveContainer width="100%" height={280}>
          <BarChart data={ATTCK_COVERAGE_DATA} layout="vertical" margin={{ left: 20 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" opacity={0.3} />
            <XAxis type="number" domain={[0, 100]} tickFormatter={(v) => `${v}%`} tick={{ fontSize: 11, fill: '#9ca3af' }} />
            <YAxis
              dataKey="technique"
              type="category"
              width={60}
              tick={{ fontSize: 11, fill: '#9ca3af', fontFamily: 'monospace' }}
            />
            <Tooltip
              formatter={(value, _name, props) => [
                `${value}% (${props.payload?.rules} rules, ${props.payload?.ioc_count} IOCs)`,
                props.payload?.name,
              ]}
              contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', color: '#fff', fontSize: 12 }}
            />
            <Bar dataKey="coverage" radius={[0, 4, 4, 0]} name="Coverage">
              {ATTCK_COVERAGE_DATA.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={COVERAGE_COLOR(entry.coverage)} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
        <div className="mt-3 flex items-center gap-6 text-xs text-gray-500 dark:text-gray-400">
          <div className="flex items-center gap-1"><div className="h-3 w-3 rounded-sm bg-green-500" /> ≥80% (good)</div>
          <div className="flex items-center gap-1"><div className="h-3 w-3 rounded-sm bg-yellow-500" /> 60-79% (needs improvement)</div>
          <div className="flex items-center gap-1"><div className="h-3 w-3 rounded-sm bg-red-500" /> &lt;60% (gap)</div>
        </div>
      </div>

      {/* Detailed mapping table */}
      <div className="rounded-xl bg-white shadow-sm dark:bg-gray-800">
        <div className="border-b border-gray-200 p-4 dark:border-gray-700">
          <h3 className="font-semibold text-gray-900 dark:text-white">Technique-to-Rule Mapping</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 dark:border-gray-700">
                <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">Technique ID</th>
                <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">Name</th>
                <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">Tactic</th>
                <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">Rules</th>
                <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">IOCs</th>
                <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">Coverage</th>
              </tr>
            </thead>
            <tbody>
              {ATTCK_COVERAGE_DATA.map((tech) => (
                <tr key={tech.technique} className="border-b border-gray-100 hover:bg-gray-50 dark:border-gray-700 dark:hover:bg-gray-750">
                  <td className="px-4 py-3">
                    <span className="rounded bg-red-50 px-2 py-0.5 font-mono text-xs text-red-700 dark:bg-red-900/20 dark:text-red-400">
                      {tech.technique}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-900 dark:text-white">{tech.name}</td>
                  <td className="px-4 py-3 text-gray-500 dark:text-gray-400 text-xs">{tech.tactic}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <Shield className="h-4 w-4 text-blue-500" />
                      <span className="text-gray-900 dark:text-white">{tech.rules}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-gray-900 dark:text-white">{tech.ioc_count}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="h-2 w-24 rounded-full bg-gray-200 dark:bg-gray-700">
                        <div
                          className="h-2 rounded-full transition-all"
                          style={{ width: `${tech.coverage}%`, backgroundColor: COVERAGE_COLOR(tech.coverage) }}
                        />
                      </div>
                      <span className="text-xs text-gray-600 dark:text-gray-400">{tech.coverage}%</span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Coverage gaps */}
      <div className="rounded-xl bg-white p-5 shadow-sm dark:bg-gray-800">
        <h3 className="mb-3 flex items-center gap-2 font-semibold text-gray-900 dark:text-white">
          <AlertTriangle className="h-4 w-4 text-red-500" />
          Coverage Gaps — Recommended Actions
        </h3>
        <div className="space-y-3">
          {GAP_TECHNIQUES.map((tech) => (
            <div
              key={tech.technique}
              className="flex items-center justify-between rounded-lg border border-red-200 bg-red-50 p-3 dark:border-red-800 dark:bg-red-900/10"
            >
              <div className="flex items-center gap-3">
                <Target className="h-4 w-4 text-red-500" />
                <div>
                  <span className="font-mono text-xs font-medium text-red-700 dark:text-red-400">{tech.technique}</span>
                  <span className="mx-2 text-gray-400">·</span>
                  <span className="text-sm text-gray-900 dark:text-white">{tech.name}</span>
                  <span className="mx-2 text-gray-400">·</span>
                  <span className="text-xs text-gray-500 dark:text-gray-400">{tech.tactic}</span>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs text-red-600 dark:text-red-400">{tech.coverage}% coverage</span>
                <button className="rounded-lg bg-red-600 px-3 py-1 text-xs text-white hover:bg-red-700">
                  Create Rule
                </button>
              </div>
            </div>
          ))}
          {ATTCK_COVERAGE_DATA.filter((t) => t.coverage < 50).map((tech) => (
            <div
              key={tech.technique}
              className="flex items-center justify-between rounded-lg border border-yellow-200 bg-yellow-50 p-3 dark:border-yellow-800 dark:bg-yellow-900/10"
            >
              <div className="flex items-center gap-3">
                <AlertTriangle className="h-4 w-4 text-yellow-500" />
                <div>
                  <span className="font-mono text-xs font-medium text-yellow-700 dark:text-yellow-400">{tech.technique}</span>
                  <span className="mx-2 text-gray-400">·</span>
                  <span className="text-sm text-gray-900 dark:text-white">{tech.name}</span>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-yellow-700 dark:text-yellow-400">{tech.coverage}% — needs improvement</span>
                <CheckCircle className="h-4 w-4 text-yellow-500" />
              </div>
            </div>
          ))}
        </div>
      </div>

      {!isLoading && null}
    </div>
  );
}
