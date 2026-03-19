import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { FileText, ChevronRight, Shield, Target, CheckCircle } from 'lucide-react';
import { fetchBriefs, fetchBriefById, type IntelBrief } from '../api/client';

const LEVEL_COLORS: Record<string, string> = {
  strategic: 'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-400',
  operational: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
  tactical: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
};

const TLP_COLORS: Record<string, string> = {
  WHITE: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300',
  GREEN: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
  AMBER: 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400',
  RED: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
};

function BriefCard({ brief, isSelected, onClick }: { brief: IntelBrief; isSelected: boolean; onClick: () => void }) {
  return (
    <div
      onClick={onClick}
      className={`cursor-pointer rounded-xl border p-4 transition-all ${
        isSelected
          ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20'
          : 'border-gray-200 bg-white hover:border-blue-300 dark:border-gray-700 dark:bg-gray-800'
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3">
          <FileText className="mt-0.5 h-5 w-5 flex-shrink-0 text-blue-500" />
          <div>
            <h3 className="font-semibold text-gray-900 dark:text-white">{brief.title}</h3>
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400 line-clamp-2">
              {brief.executive_summary}
            </p>
          </div>
        </div>
        <ChevronRight className={`h-5 w-5 flex-shrink-0 text-gray-400 transition-transform ${isSelected ? 'rotate-90' : ''}`} />
      </div>
      <div className="mt-3 flex items-center gap-2 flex-wrap">
        <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${LEVEL_COLORS[brief.level]}`}>
          {brief.level.charAt(0).toUpperCase() + brief.level.slice(1)}
        </span>
        <span className={`rounded px-2 py-0.5 text-xs font-medium ${TLP_COLORS[brief.tlp_level]}`}>
          TLP:{brief.tlp_level}
        </span>
        <span className="text-xs text-gray-500 dark:text-gray-400 ml-auto">
          {new Date(brief.created_at).toLocaleDateString()} · {brief.read_count} reads
        </span>
      </div>
    </div>
  );
}

function BriefDetail({ briefId }: { briefId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ['brief', briefId],
    queryFn: () => fetchBriefById(briefId),
  });

  if (isLoading) {
    return (
      <div className="flex h-40 items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-blue-500 border-t-transparent" />
      </div>
    );
  }

  if (!data) return null;

  return (
    <div className="rounded-xl bg-white p-6 shadow-sm dark:bg-gray-800">
      <div className="flex items-start justify-between mb-4">
        <div>
          <h2 className="text-xl font-bold text-gray-900 dark:text-white">{data.title}</h2>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
            By {data.author} · {new Date(data.created_at).toLocaleDateString()}
          </p>
        </div>
        <div className="flex gap-2">
          <span className={`rounded-full px-3 py-1 text-xs font-medium ${LEVEL_COLORS[data.level]}`}>
            {data.level.charAt(0).toUpperCase() + data.level.slice(1)}
          </span>
          <span className={`rounded px-3 py-1 text-xs font-medium ${TLP_COLORS[data.tlp_level]}`}>
            TLP:{data.tlp_level}
          </span>
        </div>
      </div>

      <div className="space-y-6">
        {/* Executive Summary */}
        <section>
          <h3 className="flex items-center gap-2 font-semibold text-gray-900 dark:text-white">
            <FileText className="h-4 w-4 text-blue-500" />
            Executive Summary
          </h3>
          <p className="mt-2 text-sm text-gray-700 dark:text-gray-300 leading-relaxed">
            {data.executive_summary}
          </p>
        </section>

        {/* Technical Analysis */}
        <section>
          <h3 className="flex items-center gap-2 font-semibold text-gray-900 dark:text-white">
            <Shield className="h-4 w-4 text-purple-500" />
            Technical Analysis
          </h3>
          <p className="mt-2 text-sm text-gray-700 dark:text-gray-300 leading-relaxed">
            {data.technical_analysis}
          </p>
        </section>

        {/* ATT&CK Techniques */}
        {data.attck_techniques.length > 0 && (
          <section>
            <h3 className="flex items-center gap-2 font-semibold text-gray-900 dark:text-white">
              <Target className="h-4 w-4 text-red-500" />
              MITRE ATT&CK Techniques
            </h3>
            <div className="mt-2 flex flex-wrap gap-2">
              {data.attck_techniques.map((tech) => (
                <span
                  key={tech}
                  className="rounded bg-red-50 px-2.5 py-1 font-mono text-xs text-red-700 dark:bg-red-900/20 dark:text-red-400"
                >
                  {tech}
                </span>
              ))}
            </div>
          </section>
        )}

        {/* Recommendations */}
        {data.recommendations.length > 0 && (
          <section>
            <h3 className="flex items-center gap-2 font-semibold text-gray-900 dark:text-white">
              <CheckCircle className="h-4 w-4 text-green-500" />
              Recommended Actions
            </h3>
            <ul className="mt-2 space-y-2">
              {data.recommendations.map((rec, i) => (
                <li key={i} className="flex items-start gap-2 text-sm text-gray-700 dark:text-gray-300">
                  <span className="mt-0.5 h-5 w-5 flex-shrink-0 rounded-full bg-green-100 text-center text-xs leading-5 text-green-700 dark:bg-green-900/30 dark:text-green-400">
                    {i + 1}
                  </span>
                  {rec}
                </li>
              ))}
            </ul>
          </section>
        )}

        {/* IOC Appendix */}
        {data.ioc_appendix.length > 0 && (
          <section>
            <h3 className="font-semibold text-gray-900 dark:text-white">IOC Appendix</h3>
            <div className="mt-2 max-h-40 overflow-y-auto rounded-lg bg-gray-50 p-3 font-mono text-xs dark:bg-gray-900">
              {data.ioc_appendix.map((ioc, i) => (
                <div key={i} className="text-gray-700 dark:text-gray-300">{ioc}</div>
              ))}
            </div>
          </section>
        )}
      </div>
    </div>
  );
}

export default function ThreatBriefViewer() {
  const [levelFilter, setLevelFilter] = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ['briefs', levelFilter],
    queryFn: () => fetchBriefs({ level: levelFilter || undefined, page_size: 50 }),
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Threat Brief Viewer</h2>
          <p className="text-gray-500 dark:text-gray-400">Curated intelligence briefs with ATT&CK mapping</p>
        </div>
        <div className="flex gap-2">
          {['', 'strategic', 'operational', 'tactical'].map((level) => (
            <button
              key={level}
              onClick={() => setLevelFilter(level)}
              className={`rounded-lg px-4 py-2 text-sm font-medium transition-colors ${
                levelFilter === level
                  ? 'bg-blue-600 text-white'
                  : 'bg-white text-gray-700 hover:bg-gray-50 dark:bg-gray-800 dark:text-gray-300 dark:hover:bg-gray-700'
              }`}
            >
              {level === '' ? 'All' : level.charAt(0).toUpperCase() + level.slice(1)}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Brief list */}
        <div className="space-y-3">
          {isLoading ? (
            <div className="flex h-40 items-center justify-center">
              <div className="h-8 w-8 animate-spin rounded-full border-2 border-blue-500 border-t-transparent" />
            </div>
          ) : error ? (
            <div className="rounded-xl bg-red-50 p-4 text-sm text-red-700 dark:bg-red-900/20 dark:text-red-400">
              Failed to load briefs
            </div>
          ) : data?.items.length === 0 ? (
            <div className="rounded-xl bg-gray-50 p-8 text-center text-gray-500 dark:bg-gray-800 dark:text-gray-400">
              No briefs found for the selected filter.
            </div>
          ) : (
            data?.items.map((brief) => (
              <BriefCard
                key={brief.id}
                brief={brief}
                isSelected={selectedId === brief.id}
                onClick={() => setSelectedId(selectedId === brief.id ? null : brief.id)}
              />
            ))
          )}
        </div>

        {/* Brief detail */}
        <div>
          {selectedId ? (
            <BriefDetail briefId={selectedId} />
          ) : (
            <div className="flex h-64 items-center justify-center rounded-xl border-2 border-dashed border-gray-300 text-gray-500 dark:border-gray-600 dark:text-gray-400">
              Select a brief to view its contents
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
