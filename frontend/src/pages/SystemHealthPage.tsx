import { CheckCircle2, XCircle } from 'lucide-react';
import { useApi } from '../hooks/useApi';

type Health = { status: string; components: Record<string, string> };

export function SystemHealthPage() {
  const { data, loading, error } = useApi<Health>('/api/health/deep', { status: 'unknown', components: {} }, []);
  return (
    <div className="space-y-4">
      <div><h1 className="text-xl font-semibold">System Health</h1><p className="text-sm text-slate-400">{loading ? 'Checking components' : error || data.status}</p></div>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {Object.entries(data.components).map(([name, status]) => {
          const ok = status === 'ok' || status === 'scheduled' || /^\d+/.test(status);
          return (
            <article key={name} className="rounded-lg border border-slate-800 bg-base-900 p-4">
              <div className="flex items-center justify-between gap-3">
                <h2 className="font-semibold capitalize">{name.replace('_', ' ')}</h2>
                {ok ? <CheckCircle2 className="text-emerald-300" size={20} /> : <XCircle className="text-red-300" size={20} />}
              </div>
              <p className={`mt-3 text-sm ${ok ? 'text-emerald-200' : 'text-red-200'}`}>{status}</p>
            </article>
          );
        })}
      </div>
    </div>
  );
}
