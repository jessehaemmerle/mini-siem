import { Plus } from 'lucide-react';
import { api } from '../api/client';
import { SeverityBadge } from '../components/Badges';
import { useApi } from '../hooks/useApi';
import type { IOC } from '../types';

export function ThreatIntelPage() {
  const { data, setData, loading, error } = useApi<IOC[]>('/api/iocs', [], []);
  async function create() {
    const ioc = await api<IOC>('/api/iocs', { method: 'POST', body: JSON.stringify({ value: `198.51.100.${data.length + 20}`, type: 'ip', source: 'Manual', confidence: 70, severity: 'medium', description: 'Manual IOC' }) });
    setData([ioc, ...data]);
  }
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div><h1 className="text-xl font-semibold">Threat Intelligence</h1><p className="text-sm text-slate-400">{loading ? 'Loading IOCs' : error || `${data.length} indicators`}</p></div>
        <button onClick={create} className="focus-ring rounded-md border border-slate-700 bg-base-900 p-2 text-slate-300 hover:text-cyan-200" title="Create IOC"><Plus size={18} /></button>
      </div>
      <div className="scrollbar overflow-auto rounded-lg border border-slate-800">
        <table className="min-w-full divide-y divide-slate-800 text-sm">
          <thead className="bg-base-850 text-left text-xs uppercase text-slate-400"><tr><th className="px-3 py-3">Value</th><th className="px-3 py-3">Type</th><th className="px-3 py-3">Severity</th><th className="px-3 py-3">Confidence</th><th className="px-3 py-3">Source</th></tr></thead>
          <tbody className="divide-y divide-slate-800 bg-base-900">
            {data.map((ioc) => (
              <tr key={ioc.id} className="hover:bg-base-800/80">
                <td className="px-3 py-3 font-mono text-slate-100">{ioc.value}</td>
                <td className="px-3 py-3 text-slate-300">{ioc.type}</td>
                <td className="px-3 py-3"><SeverityBadge severity={ioc.severity} /></td>
                <td className="px-3 py-3 text-slate-300">{ioc.confidence}</td>
                <td className="px-3 py-3 text-slate-300">{ioc.source}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
