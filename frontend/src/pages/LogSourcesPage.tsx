import { KeyRound, Plus } from 'lucide-react';
import { api } from '../api/client';
import { StatusBadge } from '../components/Badges';
import { useApi } from '../hooks/useApi';
import type { LogSource } from '../types';
import { useState } from 'react';

export function LogSourcesPage() {
  const { data, setData, loading, error } = useApi<LogSource[]>('/api/log-sources', [], []);
  const [message, setMessage] = useState('');
  async function create() {
    const response = await api<{ source: LogSource; api_key: string }>('/api/log-sources', { method: 'POST', body: JSON.stringify({ name: `Custom Source ${data.length + 1}`, source_type: 'custom', description: 'Created from SOC console' }) });
    setData([response.source, ...data]);
    setMessage(`API key: ${response.api_key}`);
  }
  async function rotate(source: LogSource) {
    const response = await api<{ api_key: string }>(`/api/log-sources/${source.id}/rotate-key`, { method: 'POST' });
    setMessage(`New API key: ${response.api_key}`);
  }
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div><h1 className="text-xl font-semibold">Log Sources</h1><p className="text-sm text-slate-400">{loading ? 'Loading sources' : error || `${data.length} sources`}</p></div>
        <button onClick={create} className="focus-ring rounded-md border border-slate-700 bg-base-900 p-2 text-slate-300 hover:text-cyan-200" title="Create source"><Plus size={18} /></button>
      </div>
      {message && <div className="rounded-lg border border-cyan-500/30 bg-cyan-950/50 p-3 font-mono text-xs text-cyan-100">{message}</div>}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {data.map((source) => (
          <article key={source.id} className="rounded-lg border border-slate-800 bg-base-900 p-4">
            <div className="flex items-start justify-between gap-3">
              <div><h2 className="font-semibold">{source.name}</h2><p className="text-sm text-slate-400">{source.hostname || source.ip_address}</p></div>
              <StatusBadge status={source.status} />
            </div>
            <div className="mt-4 grid grid-cols-2 gap-3 text-sm">
              <p><span className="block text-xs uppercase text-slate-500">Type</span>{source.source_type}</p>
              <p><span className="block text-xs uppercase text-slate-500">Events 24h</span>{source.events_last_24h}</p>
              <p className="col-span-2"><span className="block text-xs uppercase text-slate-500">Last Seen</span>{source.last_seen?.slice(0, 19) || 'never'}</p>
            </div>
            <button onClick={() => rotate(source)} className="focus-ring mt-4 rounded-md border border-slate-700 bg-base-950 p-2 text-slate-300 hover:text-cyan-200" title="Rotate key"><KeyRound size={18} /></button>
          </article>
        ))}
      </div>
    </div>
  );
}
