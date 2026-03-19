import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { CheckCircle, AlertTriangle, XCircle, Settings, Activity, Info } from 'lucide-react';
import {
  fetchAdminHealth,
  fetchAdminConfig,
  fetchAdminStats,
  fetchAuditLog,
  triggerPipeline,
  type AdminHealth,
  type AdminStats,
} from '../api/client';

type Tab = 'health' | 'config' | 'statistics' | 'audit';

function HealthStatus({ status }: { status: AdminHealth['status'] }) {
  const configs = {
    healthy: { icon: CheckCircle, color: 'text-green-500', label: 'Healthy' },
    degraded: { icon: AlertTriangle, color: 'text-yellow-500', label: 'Degraded' },
    unhealthy: { icon: XCircle, color: 'text-red-500', label: 'Unhealthy' },
  };
  const { icon: Icon, color, label } = configs[status];
  return (
    <div className={`flex items-center gap-2 ${color}`}>
      <Icon className="h-5 w-5" />
      <span className="font-semibold">{label}</span>
    </div>
  );
}

function HealthPanel() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['admin-health'],
    queryFn: fetchAdminHealth,
    refetchInterval: 30_000,
  });

  if (isLoading) return <div className="h-8 w-8 animate-spin rounded-full border-2 border-blue-500 border-t-transparent mx-auto mt-8" />;
  if (error) return <div className="text-red-500 p-4">Failed to load health status</div>;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between rounded-xl bg-gray-50 p-4 dark:bg-gray-700">
        <div>
          <p className="text-sm text-gray-500 dark:text-gray-400">Overall Status</p>
          <HealthStatus status={data!.status} />
        </div>
        <div className="text-right">
          <p className="text-sm text-gray-500 dark:text-gray-400">Uptime</p>
          <p className="font-semibold text-gray-900 dark:text-white">
            {Math.floor(data!.uptime_seconds / 3600)}h {Math.floor((data!.uptime_seconds % 3600) / 60)}m
          </p>
        </div>
        <div className="text-right">
          <p className="text-sm text-gray-500 dark:text-gray-400">Version</p>
          <p className="font-semibold text-gray-900 dark:text-white">{data!.version}</p>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        {data!.components.map((component) => (
          <div
            key={component.name}
            className="flex items-center justify-between rounded-lg border border-gray-200 p-3 dark:border-gray-600"
          >
            <div className="flex items-center gap-2">
              {component.status === 'healthy' ? (
                <CheckCircle className="h-4 w-4 text-green-500" />
              ) : (
                <AlertTriangle className="h-4 w-4 text-yellow-500" />
              )}
              <span className="text-sm text-gray-900 dark:text-white">{component.name}</span>
            </div>
            <span className="text-xs text-gray-500 dark:text-gray-400">{component.latency_ms}ms</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function ConfigPanel() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['admin-config'],
    queryFn: fetchAdminConfig,
  });

  if (isLoading) return <div className="h-8 w-8 animate-spin rounded-full border-2 border-blue-500 border-t-transparent mx-auto mt-8" />;
  if (error) return <div className="text-red-500 p-4">Failed to load config</div>;

  return (
    <div className="space-y-4">
      <div className="rounded-lg bg-blue-50 p-3 text-sm text-blue-800 dark:bg-blue-900/20 dark:text-blue-400 flex items-center gap-2">
        <Info className="h-4 w-4" />
        Sensitive values (API keys, passwords) are redacted for security.
      </div>
      <div className="rounded-xl bg-gray-50 p-4 dark:bg-gray-700">
        <pre className="overflow-auto text-xs text-gray-700 dark:text-gray-300 max-h-96">
          {JSON.stringify(data, null, 2)}
        </pre>
      </div>
    </div>
  );
}

function StatisticsPanel() {
  const { data, isLoading, error } = useQuery<AdminStats>({
    queryKey: ['admin-stats'],
    queryFn: fetchAdminStats,
    refetchInterval: 60_000,
  });

  const [pipelineStatus, setPipelineStatus] = useState<string | null>(null);

  async function handleRunPipeline() {
    setPipelineStatus('running');
    try {
      const result = await triggerPipeline();
      setPipelineStatus(`Started run ${result.run_id}`);
    } catch {
      setPipelineStatus('Error starting pipeline');
    }
  }

  if (isLoading) return <div className="h-8 w-8 animate-spin rounded-full border-2 border-blue-500 border-t-transparent mx-auto mt-8" />;
  if (error) return <div className="text-red-500 p-4">Failed to load statistics</div>;

  const stats = data!;
  const statItems = [
    { label: 'Total IOCs Processed', value: stats.total_iocs_processed.toLocaleString() },
    { label: 'Total Briefs Generated', value: stats.total_briefs_generated.toLocaleString() },
    { label: 'Total IOCs Distributed', value: stats.total_iocs_distributed.toLocaleString() },
    { label: 'Pipeline Runs (24h)', value: stats.pipeline_runs_24h },
    { label: 'Avg Pipeline Duration', value: `${stats.avg_pipeline_duration_ms}ms` },
    { label: 'Error Rate (24h)', value: `${(stats.error_rate_24h * 100).toFixed(2)}%` },
  ];

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4 md:grid-cols-3">
        {statItems.map((item) => (
          <div key={item.label} className="rounded-xl bg-gray-50 p-4 dark:bg-gray-700">
            <p className="text-sm text-gray-500 dark:text-gray-400">{item.label}</p>
            <p className="mt-1 text-xl font-bold text-gray-900 dark:text-white">{item.value}</p>
          </div>
        ))}
      </div>

      <div className="flex items-center gap-4">
        <button
          onClick={handleRunPipeline}
          disabled={pipelineStatus === 'running'}
          className="flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700 disabled:opacity-50"
        >
          <Activity className={`h-4 w-4 ${pipelineStatus === 'running' ? 'animate-spin' : ''}`} />
          Run Pipeline Now
        </button>
        {pipelineStatus && pipelineStatus !== 'running' && (
          <span className="text-sm text-gray-600 dark:text-gray-400">{pipelineStatus}</span>
        )}
      </div>
    </div>
  );
}

function AuditLogPanel() {
  const [page, setPage] = useState(1);
  const { data, isLoading, error } = useQuery({
    queryKey: ['audit-log', page],
    queryFn: () => fetchAuditLog({ page, page_size: 20 }),
    keepPreviousData: true,
  });

  if (isLoading) return <div className="h-8 w-8 animate-spin rounded-full border-2 border-blue-500 border-t-transparent mx-auto mt-8" />;
  if (error) return <div className="text-red-500 p-4">Failed to load audit log</div>;

  return (
    <div className="space-y-3">
      {data?.items.map((entry, index) => (
        <div
          key={index}
          className="flex items-start justify-between rounded-lg border border-gray-200 p-3 text-sm dark:border-gray-700"
        >
          <div>
            <span className="font-medium text-gray-900 dark:text-white">{entry.action}</span>
            <span className="mx-2 text-gray-400">·</span>
            <span className="text-gray-600 dark:text-gray-400">{entry.user}</span>
            {entry.details && (
              <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">{entry.details}</p>
            )}
          </div>
          <span className="text-xs text-gray-500 dark:text-gray-400 flex-shrink-0">
            {new Date(entry.timestamp).toLocaleString()}
          </span>
        </div>
      ))}
      {data?.items.length === 0 && (
        <p className="py-8 text-center text-gray-500 dark:text-gray-400">No audit log entries.</p>
      )}
      {data && data.pages > 1 && (
        <div className="flex justify-center gap-2 pt-2">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page === 1}
            className="rounded-lg border border-gray-300 px-4 py-2 text-sm disabled:opacity-50 dark:border-gray-600"
          >
            Previous
          </button>
          <span className="flex items-center px-3 text-sm text-gray-600 dark:text-gray-400">
            {page} / {data.pages}
          </span>
          <button
            onClick={() => setPage((p) => Math.min(data.pages, p + 1))}
            disabled={page === data.pages}
            className="rounded-lg border border-gray-300 px-4 py-2 text-sm disabled:opacity-50 dark:border-gray-600"
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}

export default function Administration() {
  const [activeTab, setActiveTab] = useState<Tab>('health');

  const tabs: { id: Tab; label: string; icon: React.ElementType }[] = [
    { id: 'health', label: 'Health', icon: CheckCircle },
    { id: 'config', label: 'Configuration', icon: Settings },
    { id: 'statistics', label: 'Statistics', icon: Activity },
    { id: 'audit', label: 'Audit Log', icon: Info },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Administration</h2>
        <p className="text-gray-500 dark:text-gray-400">
          System health, configuration, statistics, and audit trail
        </p>
      </div>

      {/* Tab navigation */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="flex gap-1">
          {tabs.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id)}
              className={`flex items-center gap-2 border-b-2 px-4 py-3 text-sm font-medium transition-colors ${
                activeTab === id
                  ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                  : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300'
              }`}
            >
              <Icon className="h-4 w-4" />
              {label}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab content */}
      <div className="rounded-xl bg-white p-6 shadow-sm dark:bg-gray-800">
        {activeTab === 'health' && <HealthPanel />}
        {activeTab === 'config' && <ConfigPanel />}
        {activeTab === 'statistics' && <StatisticsPanel />}
        {activeTab === 'audit' && <AuditLogPanel />}
      </div>
    </div>
  );
}
