import { useState } from 'react';
import { FilterBar } from '../components/FilterBar';
import { JsonViewer } from '../components/JsonViewer';
import { useApi } from '../hooks/useApi';

type Audit = {
  id: string;
  timestamp: string;
  actor_username: string;
  action: string;
  entity_type: string;
  entity_id?: string;
  new_value?: Record<string, unknown>;
};

export function AuditTrailPage() {
  const [query, setQuery] = useState('');
  const { data, loading, error } = useApi<Audit[]>('/api/audit', [], []);
  const filtered = data.filter((row) => `${row.actor_username} ${row.action} ${row.entity_type}`.toLowerCase().includes(query.toLowerCase()));
  return (
    <div className="space-y-4">
      <div><h1 className="text-xl font-semibold">Audit Trail</h1><p className="text-sm text-slate-400">{loading ? 'Loading audit events' : error || `${filtered.length} entries`}</p></div>
      <FilterBar query={query} setQuery={setQuery} />
      <div className="scrollbar overflow-auto rounded-lg border border-slate-800">
        <table className="min-w-full divide-y divide-slate-800 text-sm">
          <thead className="bg-base-850 text-left text-xs uppercase text-slate-400"><tr><th className="px-3 py-3">Time</th><th className="px-3 py-3">Actor</th><th className="px-3 py-3">Action</th><th className="px-3 py-3">Entity</th><th className="px-3 py-3">Value</th></tr></thead>
          <tbody className="divide-y divide-slate-800 bg-base-900">
            {filtered.map((row) => (
              <tr key={row.id} className="align-top hover:bg-base-800/80">
                <td className="whitespace-nowrap px-3 py-3 font-mono text-xs text-slate-400">{row.timestamp.slice(0, 19)}</td>
                <td className="px-3 py-3 text-slate-300">{row.actor_username}</td>
                <td className="px-3 py-3 text-slate-100">{row.action}</td>
                <td className="px-3 py-3 text-slate-300">{row.entity_type}</td>
                <td className="px-3 py-3"><JsonViewer value={row.new_value || { entity_id: row.entity_id }} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
