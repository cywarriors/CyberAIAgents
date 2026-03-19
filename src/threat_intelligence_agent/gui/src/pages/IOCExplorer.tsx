import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Search, Download, ChevronLeft, ChevronRight, Shield, Globe, Hash, Link, Mail, FileText } from 'lucide-react';
import { fetchIOCs, updateIOC, exportIOCs, type IOC } from '../api/client';

const IOC_TYPE_ICONS: Record<string, React.ElementType> = {
  ip: Globe,
  domain: Globe,
  url: Link,
  hash_md5: Hash,
  hash_sha1: Hash,
  hash_sha256: Hash,
  email: Mail,
};

const IOC_TYPE_COLORS: Record<string, string> = {
  ip: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
  domain: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
  url: 'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-400',
  hash_md5: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300',
  hash_sha1: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300',
  hash_sha256: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300',
  email: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
};

const STATUS_COLORS: Record<string, string> = {
  new: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
  active: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
  deprecated: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
  revoked: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
};

const TLP_COLORS: Record<string, string> = {
  WHITE: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300',
  GREEN: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
  AMBER: 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400',
  RED: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
};

function ConfidenceBadge({ score }: { score: number }) {
  const color =
    score >= 80 ? 'text-green-600 dark:text-green-400' :
    score >= 50 ? 'text-yellow-600 dark:text-yellow-400' :
    'text-red-600 dark:text-red-400';
  return <span className={`font-semibold ${color}`}>{score}%</span>;
}

export default function IOCExplorer() {
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [confidenceMin, setConfidenceMin] = useState(0);
  const [page, setPage] = useState(1);
  const [selectedIOC, setSelectedIOC] = useState<IOC | null>(null);

  const queryClient = useQueryClient();

  const { data, isLoading, error } = useQuery({
    queryKey: ['iocs', page, search, typeFilter, statusFilter, confidenceMin],
    queryFn: () =>
      fetchIOCs({
        page,
        page_size: 20,
        search: search || undefined,
        type: typeFilter || undefined,
        status: statusFilter || undefined,
        confidence_min: confidenceMin > 0 ? confidenceMin : undefined,
      }),
    keepPreviousData: true,
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<IOC> }) => updateIOC(id, data),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['iocs'] }),
  });

  async function handleExport(format: 'stix' | 'csv') {
    const blob = await exportIOCs({ format });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `iocs.${format === 'stix' ? 'json' : 'csv'}`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white">IOC Explorer</h2>
          <p className="text-gray-500 dark:text-gray-400">Search and manage indicators of compromise</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => handleExport('csv')}
            className="flex items-center gap-2 rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-300 dark:hover:bg-gray-700"
          >
            <Download className="h-4 w-4" />
            CSV
          </button>
          <button
            onClick={() => handleExport('stix')}
            className="flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700"
          >
            <Download className="h-4 w-4" />
            STIX 2.1
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="relative flex-1 min-w-48">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search IOC value, description, tags..."
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1); }}
            className="w-full rounded-lg border border-gray-300 bg-white py-2 pl-10 pr-4 text-sm text-gray-900 focus:border-blue-500 focus:outline-none dark:border-gray-600 dark:bg-gray-800 dark:text-white"
          />
        </div>
        <select
          value={typeFilter}
          onChange={(e) => { setTypeFilter(e.target.value); setPage(1); }}
          className="rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 focus:border-blue-500 focus:outline-none dark:border-gray-600 dark:bg-gray-800 dark:text-white"
        >
          <option value="">All Types</option>
          <option value="ip">IP</option>
          <option value="domain">Domain</option>
          <option value="url">URL</option>
          <option value="hash_sha256">SHA-256</option>
          <option value="hash_md5">MD5</option>
          <option value="email">Email</option>
        </select>
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
        <select
          value={confidenceMin}
          onChange={(e) => { setConfidenceMin(Number(e.target.value)); setPage(1); }}
          className="rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 focus:border-blue-500 focus:outline-none dark:border-gray-600 dark:bg-gray-800 dark:text-white"
        >
          <option value={0}>Any Confidence</option>
          <option value={50}>≥50%</option>
          <option value={70}>≥70%</option>
          <option value={90}>≥90%</option>
        </select>
      </div>

      {/* Table */}
      <div className="rounded-xl bg-white shadow-sm dark:bg-gray-800">
        {isLoading ? (
          <div className="flex h-40 items-center justify-center">
            <div className="h-8 w-8 animate-spin rounded-full border-2 border-blue-500 border-t-transparent" />
          </div>
        ) : error ? (
          <div className="flex h-40 items-center justify-center text-red-500">
            Failed to load IOCs
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-200 dark:border-gray-700">
                    <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">Type</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">Value</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">Confidence</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">TLP</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">Status</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">Sources</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">Last Seen</th>
                    <th className="px-4 py-3 text-left font-medium text-gray-500 dark:text-gray-400">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {data?.items.map((ioc) => {
                    const Icon = IOC_TYPE_ICONS[ioc.type] ?? Shield;
                    return (
                      <tr
                        key={ioc.id}
                        className="border-b border-gray-100 hover:bg-gray-50 dark:border-gray-700 dark:hover:bg-gray-750 cursor-pointer"
                        onClick={() => setSelectedIOC(selectedIOC?.id === ioc.id ? null : ioc)}
                      >
                        <td className="px-4 py-3">
                          <span className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium ${IOC_TYPE_COLORS[ioc.type]}`}>
                            <Icon className="h-3 w-3" />
                            {ioc.type.replace('hash_', '').toUpperCase()}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="font-mono text-xs text-gray-900 dark:text-white max-w-xs truncate block">
                            {ioc.value}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <ConfidenceBadge score={ioc.confidence_score} />
                        </td>
                        <td className="px-4 py-3">
                          <span className={`rounded px-2 py-0.5 text-xs font-medium ${TLP_COLORS[ioc.tlp_level]}`}>
                            TLP:{ioc.tlp_level}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${STATUS_COLORS[ioc.status]}`}>
                            {ioc.status}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-gray-500 dark:text-gray-400">
                          {ioc.sources.slice(0, 2).join(', ')}
                          {ioc.sources.length > 2 && ` +${ioc.sources.length - 2}`}
                        </td>
                        <td className="px-4 py-3 text-xs text-gray-500 dark:text-gray-400">
                          {new Date(ioc.last_seen).toLocaleDateString()}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex gap-1">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                updateMutation.mutate({ id: ioc.id, data: { status: 'deprecated' } });
                              }}
                              className="rounded px-2 py-1 text-xs text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20"
                            >
                              Deprecate
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                  {data?.items.length === 0 && (
                    <tr>
                      <td colSpan={8} className="px-4 py-12 text-center text-gray-500 dark:text-gray-400">
                        No IOCs found matching your filters.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {/* Detail panel */}
            {selectedIOC && (
              <div className="border-t border-gray-200 p-4 dark:border-gray-700">
                <h4 className="font-semibold text-gray-900 dark:text-white mb-3">IOC Detail</h4>
                <div className="grid grid-cols-2 gap-4 text-sm md:grid-cols-4">
                  <div><span className="text-gray-500 dark:text-gray-400">Associated Actors:</span> <span className="text-gray-900 dark:text-white">{selectedIOC.associated_actors.join(', ') || '—'}</span></div>
                  <div><span className="text-gray-500 dark:text-gray-400">Campaigns:</span> <span className="text-gray-900 dark:text-white">{selectedIOC.associated_campaigns.join(', ') || '—'}</span></div>
                  <div><span className="text-gray-500 dark:text-gray-400">Relevance:</span> <span className="text-gray-900 dark:text-white">{selectedIOC.relevance_score}%</span></div>
                  <div><span className="text-gray-500 dark:text-gray-400">Tags:</span> <span className="text-gray-900 dark:text-white">{selectedIOC.tags.join(', ') || '—'}</span></div>
                  {selectedIOC.description && (
                    <div className="col-span-4"><span className="text-gray-500 dark:text-gray-400">Description:</span> <span className="text-gray-900 dark:text-white">{selectedIOC.description}</span></div>
                  )}
                </div>
              </div>
            )}

            {/* Pagination */}
            {data && data.pages > 1 && (
              <div className="flex items-center justify-between border-t border-gray-200 px-4 py-3 dark:border-gray-700">
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  {(page - 1) * 20 + 1}–{Math.min(page * 20, data.total)} of {data.total}
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
