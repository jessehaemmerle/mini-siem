import { Plus } from 'lucide-react';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import { SeverityBadge, StatusBadge } from '../components/Badges';
import { useApi } from '../hooks/useApi';
import type { Incident } from '../types';

export function IncidentsPage() {
  const { data, setData, loading, error } = useApi<Incident[]>('/api/incidents', [], []);
  async function create() {
    const incident = await api<Incident>('/api/incidents', { method: 'POST', body: JSON.stringify({ title: 'Manual triage incident', severity: 'medium', description: 'Created from SOC console' }) });
    setData([incident, ...data]);
  }
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Incidents</h1>
          <p className="text-sm text-slate-400">{loading ? 'Loading incidents' : error || `${data.length} incidents`}</p>
        </div>
        <button onClick={create} className="focus-ring rounded-md border border-slate-700 bg-base-900 p-2 text-slate-300 hover:text-cyan-200" title="Create incident"><Plus size={18} /></button>
      </div>
      <div className="scrollbar overflow-auto rounded-lg border border-slate-800">
        <table className="min-w-full divide-y divide-slate-800 text-sm">
          <thead className="bg-base-850 text-left text-xs uppercase text-slate-400"><tr><th className="px-3 py-3">Incident</th><th className="px-3 py-3">Severity</th><th className="px-3 py-3">Status</th><th className="px-3 py-3">Updated</th></tr></thead>
          <tbody className="divide-y divide-slate-800 bg-base-900">
            {data.map((incident) => (
              <tr key={incident.id} className="hover:bg-base-800/80">
                <td className="px-3 py-3"><Link to={`/incidents/${incident.id}`} className="font-medium hover:text-cyan-300">{incident.title}</Link></td>
                <td className="px-3 py-3"><SeverityBadge severity={incident.severity} /></td>
                <td className="px-3 py-3"><StatusBadge status={incident.status} /></td>
                <td className="px-3 py-3 font-mono text-xs text-slate-400">{incident.updated_at?.slice(0, 19)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
