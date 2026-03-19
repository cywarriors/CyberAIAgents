import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Search, Users, MapPin, Target, ChevronDown, ChevronRight } from 'lucide-react';
import { fetchActors, fetchActorById, type ThreatActor } from '../api/client';

function ActorCard({
  actor,
  isExpanded,
  onToggle,
}: {
  actor: ThreatActor;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const { data: detail } = useQuery({
    queryKey: ['actor', actor.id],
    queryFn: () => fetchActorById(actor.id),
    enabled: isExpanded,
  });

  const confidenceColor =
    actor.attribution_confidence >= 80
      ? 'text-green-600 dark:text-green-400'
      : actor.attribution_confidence >= 50
      ? 'text-yellow-600 dark:text-yellow-400'
      : 'text-red-600 dark:text-red-400';

  return (
    <div className="rounded-xl border border-gray-200 bg-white dark:border-gray-700 dark:bg-gray-800">
      {/* Card header */}
      <div
        className="flex cursor-pointer items-start justify-between p-5"
        onClick={onToggle}
      >
        <div className="flex items-start gap-4">
          <div className="flex h-12 w-12 items-center justify-center rounded-full bg-red-100 dark:bg-red-900/30">
            <Users className="h-6 w-6 text-red-600 dark:text-red-400" />
          </div>
          <div>
            <h3 className="font-bold text-gray-900 dark:text-white">{actor.name}</h3>
            {actor.aliases.length > 0 && (
              <p className="text-sm text-gray-500 dark:text-gray-400">
                aka {actor.aliases.slice(0, 3).join(', ')}
                {actor.aliases.length > 3 && ` +${actor.aliases.length - 3}`}
              </p>
            )}
            <p className="mt-1 text-sm text-gray-600 dark:text-gray-400 line-clamp-1">
              {actor.description}
            </p>
          </div>
        </div>
        <div className="flex flex-col items-end gap-2">
          <span className={`text-sm font-semibold ${confidenceColor}`}>
            {actor.attribution_confidence}% confidence
          </span>
          {isExpanded ? (
            <ChevronDown className="h-5 w-5 text-gray-400" />
          ) : (
            <ChevronRight className="h-5 w-5 text-gray-400" />
          )}
        </div>
      </div>

      {/* Summary badges */}
      <div className="border-t border-gray-100 px-5 py-3 dark:border-gray-700 flex flex-wrap gap-2">
        {actor.targeted_sectors.slice(0, 4).map((sector) => (
          <span
            key={sector}
            className="rounded-full bg-blue-50 px-2.5 py-0.5 text-xs text-blue-700 dark:bg-blue-900/20 dark:text-blue-400"
          >
            {sector}
          </span>
        ))}
        <div className="ml-auto flex items-center gap-1 text-xs text-gray-500 dark:text-gray-400">
          <MapPin className="h-3 w-3" />
          {actor.targeted_regions.slice(0, 2).join(', ')}
        </div>
      </div>

      {/* Expanded detail */}
      {isExpanded && detail && (
        <div className="border-t border-gray-200 p-5 dark:border-gray-700 space-y-4">
          {/* TTPs */}
          {detail.ttps.length > 0 && (
            <div>
              <h4 className="flex items-center gap-1.5 text-sm font-semibold text-gray-900 dark:text-white">
                <Target className="h-4 w-4 text-red-500" />
                MITRE ATT&CK TTPs
              </h4>
              <div className="mt-2 grid grid-cols-2 gap-2 md:grid-cols-3">
                {detail.ttps.map((ttp) => (
                  <div
                    key={ttp.technique_id}
                    className="rounded-lg bg-gray-50 p-2.5 dark:bg-gray-900"
                  >
                    <p className="font-mono text-xs font-medium text-red-600 dark:text-red-400">
                      {ttp.technique_id}
                    </p>
                    <p className="text-xs text-gray-700 dark:text-gray-300">{ttp.technique_name}</p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">{ttp.tactic}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Campaigns */}
          {detail.associated_campaigns.length > 0 && (
            <div>
              <h4 className="text-sm font-semibold text-gray-900 dark:text-white">Associated Campaigns</h4>
              <div className="mt-2 flex flex-wrap gap-2">
                {detail.associated_campaigns.map((c) => (
                  <span
                    key={c}
                    className="rounded bg-purple-50 px-2.5 py-1 text-xs text-purple-700 dark:bg-purple-900/20 dark:text-purple-400"
                  >
                    {c}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Activity timeline */}
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-gray-500 dark:text-gray-400">First observed: </span>
              <span className="text-gray-900 dark:text-white">{new Date(detail.first_seen).toLocaleDateString()}</span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-gray-400">Last activity: </span>
              <span className="text-gray-900 dark:text-white">{new Date(detail.last_seen).toLocaleDateString()}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function ActorDatabase() {
  const [search, setSearch] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [page, setPage] = useState(1);

  const { data, isLoading, error } = useQuery({
    queryKey: ['actors', page, search],
    queryFn: () => fetchActors({ page, page_size: 12, search: search || undefined }),
    keepPreviousData: true,
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Actor Database</h2>
          <p className="text-gray-500 dark:text-gray-400">
            Threat actor profiles with TTPs, campaigns, and targeting data
          </p>
        </div>
        {data && (
          <span className="rounded-full bg-gray-100 px-3 py-1 text-sm text-gray-700 dark:bg-gray-700 dark:text-gray-300">
            {data.total} actors
          </span>
        )}
      </div>

      {/* Search */}
      <div className="relative max-w-sm">
        <Search className="absolute left-3 top-2.5 h-4 w-4 text-gray-400" />
        <input
          type="text"
          placeholder="Search actors, aliases..."
          value={search}
          onChange={(e) => { setSearch(e.target.value); setPage(1); }}
          className="w-full rounded-lg border border-gray-300 bg-white py-2 pl-10 pr-4 text-sm text-gray-900 focus:border-blue-500 focus:outline-none dark:border-gray-600 dark:bg-gray-800 dark:text-white"
        />
      </div>

      {/* Actor list */}
      {isLoading ? (
        <div className="flex h-40 items-center justify-center">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-blue-500 border-t-transparent" />
        </div>
      ) : error ? (
        <div className="rounded-xl bg-red-50 p-4 text-sm text-red-700 dark:bg-red-900/20 dark:text-red-400">
          Failed to load actors
        </div>
      ) : data?.items.length === 0 ? (
        <div className="rounded-xl bg-gray-50 p-8 text-center text-gray-500 dark:bg-gray-800 dark:text-gray-400">
          No threat actors found.
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {data?.items.map((actor) => (
            <ActorCard
              key={actor.id}
              actor={actor}
              isExpanded={expandedId === actor.id}
              onToggle={() => setExpandedId(expandedId === actor.id ? null : actor.id)}
            />
          ))}
        </div>
      )}

      {/* Pagination */}
      {data && data.pages > 1 && (
        <div className="flex justify-center gap-2">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page === 1}
            className="rounded-lg border border-gray-300 px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50 dark:border-gray-600 dark:text-gray-300 dark:hover:bg-gray-800"
          >
            Previous
          </button>
          <span className="flex items-center px-4 text-sm text-gray-700 dark:text-gray-300">
            Page {page} of {data.pages}
          </span>
          <button
            onClick={() => setPage((p) => Math.min(data.pages, p + 1))}
            disabled={page === data.pages}
            className="rounded-lg border border-gray-300 px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50 dark:border-gray-600 dark:text-gray-300 dark:hover:bg-gray-800"
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}
