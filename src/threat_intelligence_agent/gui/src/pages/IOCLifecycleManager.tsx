import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Clock, ChevronLeft, ChevronRight, RotateCcw } from 'lucide-react';
import { fetchIOCs, updateIOC, type IOC } from '../api/client';

const STATUS_FLOW: Record<string, string> = {
  new: 'active',
  active: 'deprecated',
  deprecated: 'revoked',
  revoked: 'revoked',
};

const STATUS_COLORS: Record<string, string> = {
  new: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
  active: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
  deprecated: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
  revoked: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
};

function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${STATUS_COLORS[status]}`}>
      {status}
    </span>
  );
}

function AgeIndicator({ firstSeen, lastSeen }: { firstSeen: string; lastSeen: string }) {
  const ageMs = Date.now() - new Date(firstSeen).getTime();
  const ageDays = Math.floor(ageMs / (1000 * 60 * 60 * 24));
  const staleDays = Math.floor((Date.now() - new Date(lastSeen).getTime()) / (1000 * 60 * 60 * 24));

  const color =
    staleDays > 90 ? 'text-red-600 dark:text-red-400' :
    staleDays > 30 ? 'text-yellow-600 dark:text-yellow-400' :
    'text-green-600 dark:text-green-400';

  return (
    <div className={`text-xs ${color}`}>
      <span>{ageDays}d old</span>
      {staleDays > 0 && <span className="ml-1 text-gray-400 dark:text-gray-500">({staleDays}d stale)</span>}
    </div>
  );
}

export default function IOCLifecycleManager() {
  const [statusFilter, setStatusFilter] = useState('');
  const [page, setPage] = useState(1);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const queryClient = useQueryClient();

  const { data, isLoading, error } = useQuery({
    queryKey: ['iocs-lifecycle', page, statusFilter],
    queryFn: () => fetchIOCs({ page, page_size: 25, status: statusFilter || undefined }),
    keepPreviousData: true,
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: IOC['status'] }) =>
      updateIOC(id, { status }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['iocs-lifecycle'] });
      queryClient.invalidateQueries({ queryKey: ['iocs'] });
    },
  });

  function toggleSelect(id: string) {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function bulkTransition(targetStatus: IOC['status']) {
    for (const id of selectedIds) {
      updateMutation.mutate({ id, status: targetStatus });
    }
    setSelectedIds(new Set());
  }

  const statusCounts = data?.items.reduce(
    (acc, ioc) => {
      acc[ioc.status] = (acc[ioc.status] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  ) ?? {};

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white">IOC Lifecycle Manager</h2>
          <p className="text-gray-500 dark:text-gray-400">
            Manage IOC aging, deprecation, and re-validation workflow
          </p>
        </div>
      </div>

      {/* Status summary */}
      <div className="grid grid-cols-4 gap-4">
        {(['new', 'active', 'deprecated', 'revoked'] as const).map((status) => (
          <button
            key={status}
            onClick={() => { setStatusFilter(statusFilter === status ? '' : status); setPage(1); }}
            className={`rounded-xl p-4 text-left transition-all ${
              statusFilter === status
                ? 'ring-2 ring-blue-500'
                : ''
            } ${STATUS_COLORS[status].replace('text-', 'bg-')} bg-opacity-10`}
          >
            <p className="text-2xl font-bold text-gray-900 dark:text-white">
              {statusCounts[status] ?? '—'}
            </p>
            <p className={`text-sm font-medium ${STATUS_COLORS[status].split(' ')[1]}`}>
              {status.charAt(0).toUpperCase() + status.slice(1)}
            </p>
          </button>
        ))}
      </div>

      {/* Filters + bulk actions */}
      <div className="flex items-center justify-between">
        <div className="flex gap-2">
          <select
            value={statusFilter}
            onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
            className="rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 focus:border-blue-500 focus:outline-none dark:border-gray-600 dark:bg-gray-800 dark:text-white"
          >
            <option value="">All Status</option>
            <option value="new">New</option>
            <option value="active">Active</option>
            <option value="deprecated">Deprecated</option>
            <option value="revoked">Revoked</option>
          </select>
        </div>

        {selectedIds.size > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-sm text-gray-600 dark:text-gray-400">{selectedIds.size} selected</span>
            <button
              onClick={() => bulkTransition('active')}
              className="rounded-lg bg-green-600 px-3 py-1.5 text-xs text-white hover:bg-green-700"
            >
              Activate
            </button>
            <button
              onClick={() => bulkTransition('deprecated')}
              className="rounded-lg bg-yellow-600 px-3 py-1.5 text-xs text-white hover:bg-yellow-700"
            >
              Deprecate
            </button>
            <button
              onClick={() => bulkTransition('revoked')}
              className="rounded-lg bg-red-600 px-3 py-1.5 text-xs text-white hover:bg-red-700"
            >
              Revoke
            </button>
            <button
              onClick={() => setSelectedIds(new Set())}
              className="rounded-lg border border-gray-300 px-3 py-1.5 text-xs text-gray-700 hover:bg-gray-50 dark:border-gray-600 dark:text-gray-300"
            >
              Clear
            </button>
          </div>
        )}
      </div>

      {/* Table */}
      <div className="rounded-xl bg-white shadow-sm dark:bg-gray-800">
        {isLoading ? (
          <div className="flex h-40 items-center justify-center">
            <div className="h-8 w-8 animate-spin rounded-full border-2 border-blue-500 border-t-transparent" />
          </div>
        ) : error ? (
          <div className="flex h-40 items-center justify-center text-red-500">Failed to load IOCs</div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-200 dark:border-gray-700">
                    <th className="w-10 px-4 py-3">
                      <input
                        type="checkbox"
                        checked={selectedIds.size === data?.items.length && data.items.length > 0}
                        onChange={(e) =>
                          e.target.checked
                            ? setSelectedIds(new Set(data?.items.map((i) => i.id) ?? []))
                            : setSelectedIds(new Set())
                        }
                        className="rounded border-gray-300"
                      />
                    </th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">IOC</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">Status</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">Age</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">Confidence</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">Sources</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {data?.items.map((ioc) => (
                    <tr key={ioc.id} className="border-b border-gray-100 hover:bg-gray-50 dark:border-gray-700">
                      <td className="px-4 py-3">
                        <input
                          type="checkbox"
                          checked={selectedIds.has(ioc.id)}
                          onChange={() => toggleSelect(ioc.id)}
                          className="rounded border-gray-300"
                        />
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <Clock className="h-4 w-4 text-gray-400" />
                          <div>
                            <p className="font-mono text-xs text-gray-900 dark:text-white truncate max-w-xs">
                              {ioc.value}
                            </p>
                            <p className="text-xs text-gray-500 dark:text-gray-400">{ioc.type}</p>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge status={ioc.status} />
                      </td>
                      <td className="px-4 py-3">
                        <AgeIndicator firstSeen={ioc.first_seen} lastSeen={ioc.last_seen} />
                      </td>
                      <td className="px-4 py-3 text-gray-900 dark:text-white">{ioc.confidence_score}%</td>
                      <td className="px-4 py-3 text-gray-500 dark:text-gray-400 text-xs">
                        {ioc.sources.length} source{ioc.sources.length !== 1 ? 's' : ''}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex gap-1">
                          {STATUS_FLOW[ioc.status] !== ioc.status && (
                            <button
                              onClick={() => updateMutation.mutate({ id: ioc.id, status: STATUS_FLOW[ioc.status] as IOC['status'] })}
                              className="rounded px-2 py-1 text-xs text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-900/20"
                            >
                              → {STATUS_FLOW[ioc.status]}
                            </button>
                          )}
                          {ioc.status !== 'new' && ioc.status !== 'revoked' && (
                            <button
                              onClick={() => updateMutation.mutate({ id: ioc.id, status: 'new' })}
                              className="rounded px-2 py-1 text-xs text-gray-600 hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-gray-700"
                            >
                              <RotateCcw className="h-3 w-3" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                  {data?.items.length === 0 && (
                    <tr>
                      <td colSpan={7} className="px-4 py-12 text-center text-gray-500 dark:text-gray-400">
                        No IOCs found.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {data && data.pages > 1 && (
              <div className="flex items-center justify-between border-t border-gray-200 px-4 py-3 dark:border-gray-700">
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  {data.total} total IOCs
                </p>
                <div className="flex gap-2">
                  <button
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    disabled={page === 1}
                    className="rounded-lg p-2 text-gray-500 hover:bg-gray-100 disabled:opacity-50 dark:text-gray-400 dark:hover:bg-gray-700"
                  >
                    <ChevronLeft className="h-4 w-4" />
                  </button>
                  <span className="flex items-center px-2 text-sm text-gray-700 dark:text-gray-300">
                    {page} / {data.pages}
                  </span>
                  <button
                    onClick={() => setPage((p) => Math.min(data.pages, p + 1))}
                    disabled={page === data.pages}
                    className="rounded-lg p-2 text-gray-500 hover:bg-gray-100 disabled:opacity-50 dark:text-gray-400 dark:hover:bg-gray-700"
                  >
                    <ChevronRight className="h-4 w-4" />
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
