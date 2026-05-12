import { JsonViewer } from '../components/JsonViewer';
import { useApi } from '../hooks/useApi';

export function SettingsPage() {
  const { data, loading, error } = useApi<Record<string, unknown>>('/api/settings', {}, []);
  return (
    <div className="space-y-4">
      <div><h1 className="text-xl font-semibold">Settings</h1><p className="text-sm text-slate-400">{loading ? 'Loading settings' : error || 'Runtime configuration'}</p></div>
      <JsonViewer value={data} />
    </div>
  );
}
