import { useState } from 'react';
import { FilterBar } from '../components/FilterBar';
import { AlertTable } from '../components/AlertTable';
import { useApi } from '../hooks/useApi';
import type { Alert } from '../types';

export function AlertsPage() {
  const [query, setQuery] = useState('');
  const { data, loading, error } = useApi<Alert[]>('/api/alerts', [], []);
  const filtered = data.filter((alert) => alert.title.toLowerCase().includes(query.toLowerCase()));
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold text-slate-50">Alerts</h1>
        <p className="text-sm text-slate-400">{loading ? 'Loading alerts' : error || `${filtered.length} alerts`}</p>
      </div>
      <FilterBar query={query} setQuery={setQuery} />
      <AlertTable alerts={filtered} />
    </div>
  );
}
