import { Download, Save, ShieldPlus } from 'lucide-react';
import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { api } from '../api/client';
import { FilterBar } from '../components/FilterBar';
import { JsonViewer } from '../components/JsonViewer';
import { LogTable } from '../components/LogTable';
import { TimeRangePicker } from '../components/TimeRangePicker';
import { useApi } from '../hooks/useApi';

type SearchResponse = { total: number; items: Record<string, unknown>[]; aggregations: Record<string, unknown> };

export function LogExplorerPage() {
  const { eventId } = useParams();
  const [query, setQuery] = useState('');
  const [range, setRange] = useState('24h');
  const [severity, setSeverity] = useState('');
  const path = eventId ? `/api/logs/${eventId}` : `/api/logs/search?q=${encodeURIComponent(query)}&severity=${severity}&size=100`;
  const { data, loading, error } = useApi<SearchResponse | Record<string, unknown>>(path, eventId ? {} : { total: 0, items: [], aggregations: {} }, [path]);
  const items = eventId ? [] : ((data as SearchResponse).items || []);
  async function exportLogs(format: string) {
    const result = await api<string>(`/api/logs/export?format=${format}`, { method: 'POST' });
    const blob = new Blob([result], { type: format === 'json' ? 'application/json' : 'text/csv' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `logs.${format}`;
    anchor.click();
    URL.revokeObjectURL(url);
  }
  if (eventId) {
    return (
      <div className="space-y-4">
        <h1 className="text-xl font-semibold">Log Detail</h1>
        <JsonViewer value={data} />
      </div>
    );
  }
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-slate-50">Log Explorer</h1>
          <p className="text-sm text-slate-400">{loading ? 'Loading events' : error || `${(data as SearchResponse).total} events`}</p>
        </div>
        <div className="flex gap-2">
          <button className="focus-ring rounded-md border border-slate-700 bg-base-900 p-2 text-slate-300 hover:text-cyan-200" title="Export CSV" onClick={() => exportLogs('csv')}><Download size={18} /></button>
          <button className="focus-ring rounded-md border border-slate-700 bg-base-900 p-2 text-slate-300 hover:text-cyan-200" title="Save search"><Save size={18} /></button>
          <button className="focus-ring rounded-md border border-slate-700 bg-base-900 p-2 text-slate-300 hover:text-cyan-200" title="Create rule"><ShieldPlus size={18} /></button>
        </div>
      </div>
      <FilterBar query={query} setQuery={setQuery}>
        <TimeRangePicker value={range} onChange={setRange} />
        <select className="focus-ring rounded-md border border-slate-700 bg-base-950 px-3 py-2 text-sm text-slate-100" value={severity} onChange={(event) => setSeverity(event.target.value)}>
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </FilterBar>
      <LogTable items={items} />
    </div>
  );
}
