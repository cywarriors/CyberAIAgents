import { useQuery } from '@tanstack/react-query';
import {
  BarChart, Bar, LineChart, Line, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
} from 'recharts';
import { Shield, Activity, Radio, TrendingUp, Users, FileText, RefreshCw } from 'lucide-react';
import { fetchDashboardMetrics } from '../api/client';

const IOC_TYPE_COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4', '#ec4899'];

function KPICard({
  title, value, subtitle, icon: Icon, color,
}: {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: React.ElementType;
  color: string;
}) {
  return (
    <div className="rounded-xl bg-white p-5 shadow-sm dark:bg-gray-800">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-500 dark:text-gray-400">{title}</p>
          <p className="mt-1 text-2xl font-bold text-gray-900 dark:text-white">{value}</p>
          {subtitle && (
            <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">{subtitle}</p>
          )}
        </div>
        <div className={`rounded-xl p-3 ${color}`}>
          <Icon className="h-6 w-6 text-white" />
        </div>
      </div>
    </div>
  );
}

function FeedHealthGrid({ healthyCount, totalCount }: { healthyCount: number; totalCount: number }) {
  const degraded = Math.floor(totalCount * 0.1);
  const healthy = healthyCount - degraded;
  const errored = totalCount - healthyCount;

  return (
    <div className="rounded-xl bg-white p-5 shadow-sm dark:bg-gray-800">
      <h3 className="mb-4 font-semibold text-gray-900 dark:text-white">Feed Source Health</h3>
      <div className="grid grid-cols-3 gap-3">
        <div className="rounded-lg bg-green-50 p-3 text-center dark:bg-green-900/20">
          <p className="text-2xl font-bold text-green-600 dark:text-green-400">{healthy}</p>
          <p className="text-xs text-green-700 dark:text-green-400">Healthy</p>
        </div>
        <div className="rounded-lg bg-yellow-50 p-3 text-center dark:bg-yellow-900/20">
          <p className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">{degraded}</p>
          <p className="text-xs text-yellow-700 dark:text-yellow-400">Degraded</p>
        </div>
        <div className="rounded-lg bg-red-50 p-3 text-center dark:bg-red-900/20">
          <p className="text-2xl font-bold text-red-600 dark:text-red-400">{errored}</p>
          <p className="text-xs text-red-700 dark:text-red-400">Error</p>
        </div>
      </div>
      <div className="mt-3">
        <div className="flex items-center justify-between text-xs text-gray-500 dark:text-gray-400">
          <span>Overall availability</span>
          <span>{totalCount > 0 ? Math.round((healthyCount / totalCount) * 100) : 0}%</span>
        </div>
        <div className="mt-1 h-2 w-full rounded-full bg-gray-200 dark:bg-gray-700">
          <div
            className="h-2 rounded-full bg-green-500"
            style={{ width: `${totalCount > 0 ? (healthyCount / totalCount) * 100 : 0}%` }}
          />
        </div>
      </div>
    </div>
  );
}

export default function IntelDashboard() {
  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ['dashboard-intel'],
    queryFn: fetchDashboardMetrics,
    refetchInterval: 60_000,
  });

  if (isLoading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-blue-500 border-t-transparent" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-xl bg-red-50 p-6 text-red-700 dark:bg-red-900/20 dark:text-red-400">
        <p className="font-semibold">Failed to load dashboard</p>
        <p className="mt-1 text-sm">{String(error)}</p>
      </div>
    );
  }

  const metrics = data!;
  const iocTypeData = Object.entries(metrics.ioc_type_distribution).map(([name, value]) => ({
    name: name.replace('hash_', '').toUpperCase(),
    value,
  }));

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Intelligence Dashboard</h2>
          <p className="text-gray-500 dark:text-gray-400">Real-time threat intelligence overview</p>
        </div>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700"
        >
          <RefreshCw className={`h-4 w-4 ${isFetching ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-3">
        <KPICard
          title="Active IOCs"
          value={metrics.active_iocs.toLocaleString()}
          subtitle={`${metrics.iocs_ingested_24h} ingested today`}
          icon={Shield}
          color="bg-blue-600"
        />
        <KPICard
          title="Distributed 24h"
          value={metrics.iocs_distributed_24h.toLocaleString()}
          subtitle={`${Math.round(metrics.operationalization_rate)}% operationalized`}
          icon={Activity}
          color="bg-green-600"
        />
        <KPICard
          title="Feed Sources"
          value={`${metrics.feeds_healthy}/${metrics.feeds_total}`}
          subtitle="healthy feeds"
          icon={Radio}
          color="bg-yellow-600"
        />
        <KPICard
          title="Avg Confidence"
          value={`${Math.round(metrics.avg_confidence_score)}%`}
          subtitle="across active IOCs"
          icon={TrendingUp}
          color="bg-purple-600"
        />
        <KPICard
          title="Active Actors"
          value={metrics.active_actors}
          subtitle={`${metrics.active_campaigns} active campaigns`}
          icon={Users}
          color="bg-red-600"
        />
        <KPICard
          title="Briefs (7d)"
          value={metrics.briefs_published_7d}
          subtitle="intelligence briefs"
          icon={FileText}
          color="bg-indigo-600"
        />
      </div>

      {/* Charts row 1 */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* IOC Ingestion Timeline */}
        <div className="lg:col-span-2 rounded-xl bg-white p-5 shadow-sm dark:bg-gray-800">
          <h3 className="mb-4 font-semibold text-gray-900 dark:text-white">IOC Ingestion Timeline (24h)</h3>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={metrics.ioc_ingestion_timeline}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" opacity={0.3} />
              <XAxis
                dataKey="timestamp"
                tick={{ fontSize: 11, fill: '#9ca3af' }}
                tickFormatter={(v: string) => v.split('T')[1]?.slice(0, 5) ?? v}
              />
              <YAxis tick={{ fontSize: 11, fill: '#9ca3af' }} />
              <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', color: '#fff' }} />
              <Line type="monotone" dataKey="count" stroke="#3b82f6" strokeWidth={2} dot={false} name="IOCs" />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* IOC Type Distribution */}
        <div className="rounded-xl bg-white p-5 shadow-sm dark:bg-gray-800">
          <h3 className="mb-4 font-semibold text-gray-900 dark:text-white">IOC Type Distribution</h3>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={iocTypeData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={75} labelLine={false}>
                {iocTypeData.map((_entry, index) => (
                  <Cell key={`cell-${index}`} fill={IOC_TYPE_COLORS[index % IOC_TYPE_COLORS.length]} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', color: '#fff' }} />
              <Legend wrapperStyle={{ fontSize: '11px' }} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Charts row 2 */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Top Threat Actors */}
        <div className="lg:col-span-2 rounded-xl bg-white p-5 shadow-sm dark:bg-gray-800">
          <h3 className="mb-4 font-semibold text-gray-900 dark:text-white">Top Threat Actors by IOC Volume</h3>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={metrics.top_threat_actors} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" opacity={0.3} />
              <XAxis type="number" tick={{ fontSize: 11, fill: '#9ca3af' }} />
              <YAxis dataKey="name" type="category" width={110} tick={{ fontSize: 11, fill: '#9ca3af' }} />
              <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', color: '#fff' }} />
              <Bar dataKey="ioc_count" fill="#3b82f6" name="IOCs" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Feed Health */}
        <FeedHealthGrid
          healthyCount={metrics.feeds_healthy}
          totalCount={metrics.feeds_total}
        />
      </div>
    </div>
  );
}
