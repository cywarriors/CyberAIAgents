import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Rss, Plus, CheckCircle, AlertTriangle, XCircle, Trash2, Edit3 } from 'lucide-react';
import { fetchFeeds, createFeed, updateFeed, deleteFeed, fetchFeedHealth, type FeedSource } from '../api/client';

const SOURCE_TYPE_COLORS: Record<string, string> = {
  osint: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
  commercial: 'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-400',
  isac: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
  internal: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300',
};

function QualityBar({ score }: { score: number }) {
  const color =
    score >= 80 ? 'bg-green-500' : score >= 50 ? 'bg-yellow-500' : 'bg-red-500';
  return (
    <div className="flex items-center gap-2">
      <div className="h-2 w-20 rounded-full bg-gray-200 dark:bg-gray-700">
        <div className={`h-2 rounded-full ${color} transition-all`} style={{ width: `${score}%` }} />
      </div>
      <span className="text-xs text-gray-600 dark:text-gray-400">{score}</span>
    </div>
  );
}

function HealthIndicator({ feedId }: { feedId: string }) {
  const { data } = useQuery({
    queryKey: ['feed-health', feedId],
    queryFn: () => fetchFeedHealth(feedId),
    refetchInterval: 30_000,
  });

  if (!data) return <div className="h-2.5 w-2.5 rounded-full bg-gray-300 dark:bg-gray-600" />;

  const colors = {
    healthy: 'bg-green-500',
    degraded: 'bg-yellow-500',
    error: 'bg-red-500',
  };

  const icons = {
    healthy: CheckCircle,
    degraded: AlertTriangle,
    error: XCircle,
  };

  const Icon = icons[data.status];
  const color = data.status === 'healthy' ? 'text-green-500' : data.status === 'degraded' ? 'text-yellow-500' : 'text-red-500';

  return (
    <div className={`flex items-center gap-1 ${color}`}>
      <Icon className="h-4 w-4" />
      <span className="text-xs">{data.status}</span>
    </div>
  );
}

interface AddFeedFormProps {
  onSubmit: (data: Omit<FeedSource, 'id' | 'last_poll' | 'last_success' | 'success_rate' | 'ioc_yield_24h' | 'quality_score' | 'false_positive_rate'>) => void;
  onCancel: () => void;
}

function AddFeedForm({ onSubmit, onCancel }: AddFeedFormProps) {
  const [form, setForm] = useState({
    name: '',
    source_type: 'osint' as FeedSource['source_type'],
    url: '',
    enabled: true,
  });

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!form.name.trim() || !form.url.trim()) return;
    onSubmit(form);
  }

  return (
    <form onSubmit={handleSubmit} className="rounded-xl border border-blue-200 bg-blue-50 p-5 dark:border-blue-800 dark:bg-blue-900/10">
      <h3 className="mb-4 font-semibold text-gray-900 dark:text-white">Add Intelligence Feed</h3>
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Feed Name</label>
          <input
            type="text"
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            placeholder="AlienVault OTX"
            required
            className="mt-1 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm focus:border-blue-500 focus:outline-none dark:border-gray-600 dark:bg-gray-800 dark:text-white"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Source Type</label>
          <select
            value={form.source_type}
            onChange={(e) => setForm({ ...form, source_type: e.target.value as FeedSource['source_type'] })}
            className="mt-1 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm focus:border-blue-500 focus:outline-none dark:border-gray-600 dark:bg-gray-800 dark:text-white"
          >
            <option value="osint">OSINT</option>
            <option value="commercial">Commercial</option>
            <option value="isac">ISAC</option>
            <option value="internal">Internal</option>
          </select>
        </div>
        <div className="col-span-2">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Feed URL</label>
          <input
            type="url"
            value={form.url}
            onChange={(e) => setForm({ ...form, url: e.target.value })}
            placeholder="https://..."
            required
            className="mt-1 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm focus:border-blue-500 focus:outline-none dark:border-gray-600 dark:bg-gray-800 dark:text-white"
          />
        </div>
      </div>
      <div className="mt-4 flex justify-end gap-2">
        <button type="button" onClick={onCancel} className="rounded-lg border border-gray-300 px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 dark:border-gray-600 dark:text-gray-300">
          Cancel
        </button>
        <button type="submit" className="rounded-lg bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700">
          Add Feed
        </button>
      </div>
    </form>
  );
}

export default function FeedManager() {
  const [showAddForm, setShowAddForm] = useState(false);
  const queryClient = useQueryClient();

  const { data: feeds, isLoading, error } = useQuery({
    queryKey: ['feeds'],
    queryFn: fetchFeeds,
    refetchInterval: 60_000,
  });

  const addMutation = useMutation({
    mutationFn: createFeed,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['feeds'] });
      setShowAddForm(false);
    },
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      updateFeed(id, { enabled }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['feeds'] }),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteFeed(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['feeds'] }),
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Feed Manager</h2>
          <p className="text-gray-500 dark:text-gray-400">
            Configure and monitor intelligence feed sources
          </p>
        </div>
        <button
          onClick={() => setShowAddForm(true)}
          className="flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700"
        >
          <Plus className="h-4 w-4" />
          Add Feed
        </button>
      </div>

      {showAddForm && (
        <AddFeedForm
          onSubmit={(data) => addMutation.mutate(data)}
          onCancel={() => setShowAddForm(false)}
        />
      )}

      {isLoading ? (
        <div className="flex h-40 items-center justify-center">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-blue-500 border-t-transparent" />
        </div>
      ) : error ? (
        <div className="rounded-xl bg-red-50 p-4 text-sm text-red-700 dark:bg-red-900/20 dark:text-red-400">
          Failed to load feeds
        </div>
      ) : (
        <div className="rounded-xl bg-white shadow-sm dark:bg-gray-800">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 dark:border-gray-700">
                  <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">Feed</th>
                  <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">Type</th>
                  <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">Health</th>
                  <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">Last Poll</th>
                  <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">Success Rate</th>
                  <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">IOC Yield 24h</th>
                  <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">Quality Score</th>
                  <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">Actions</th>
                </tr>
              </thead>
              <tbody>
                {feeds?.map((feed) => (
                  <tr key={feed.id} className="border-b border-gray-100 hover:bg-gray-50 dark:border-gray-700 dark:hover:bg-gray-750">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <Rss className={`h-4 w-4 ${feed.enabled ? 'text-blue-500' : 'text-gray-400'}`} />
                        <div>
                          <p className="font-medium text-gray-900 dark:text-white">{feed.name}</p>
                          <p className="text-xs text-gray-500 dark:text-gray-400 truncate max-w-xs">{feed.url}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${SOURCE_TYPE_COLORS[feed.source_type]}`}>
                        {feed.source_type.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <HealthIndicator feedId={feed.id} />
                    </td>
                    <td className="px-4 py-3 text-gray-500 dark:text-gray-400 text-xs">
                      {feed.last_poll ? new Date(feed.last_poll).toLocaleString() : '—'}
                    </td>
                    <td className="px-4 py-3 text-gray-900 dark:text-white">
                      {Math.round(feed.success_rate * 100)}%
                    </td>
                    <td className="px-4 py-3 text-gray-900 dark:text-white">
                      {feed.ioc_yield_24h.toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      <QualityBar score={Math.round(feed.quality_score)} />
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => toggleMutation.mutate({ id: feed.id, enabled: !feed.enabled })}
                          className={`flex items-center gap-1 rounded px-2 py-1 text-xs ${
                            feed.enabled
                              ? 'text-yellow-600 hover:bg-yellow-50 dark:hover:bg-yellow-900/20'
                              : 'text-green-600 hover:bg-green-50 dark:hover:bg-green-900/20'
                          }`}
                        >
                          <Edit3 className="h-3 w-3" />
                          {feed.enabled ? 'Disable' : 'Enable'}
                        </button>
                        <button
                          onClick={() => {
                            if (confirm(`Delete feed "${feed.name}"?`)) {
                              deleteMutation.mutate(feed.id);
                            }
                          }}
                          className="flex items-center gap-1 rounded px-2 py-1 text-xs text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20"
                        >
                          <Trash2 className="h-3 w-3" />
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
                {(feeds?.length ?? 0) === 0 && (
                  <tr>
                    <td colSpan={8} className="px-4 py-12 text-center text-gray-500 dark:text-gray-400">
                      No feeds configured. Add your first intelligence feed.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
