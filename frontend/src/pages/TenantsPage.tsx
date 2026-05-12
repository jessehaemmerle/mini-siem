import { Plus } from 'lucide-react';
import { api } from '../api/client';
import { StatusBadge } from '../components/Badges';
import { useApi } from '../hooks/useApi';
import type { Tenant } from '../types';

export function TenantsPage() {
  const { data, setData, loading, error } = useApi<Tenant[]>('/api/tenants', [], []);
  async function create() {
    const tenant = await api<Tenant>('/api/tenants', { method: 'POST', body: JSON.stringify({ name: `Tenant ${data.length + 1}`, description: 'Managed tenant', retention_days: 90, contact_person: 'soc@example.com', allowed_log_sources: ['windows', 'linux', 'firewall'] }) });
    setData([tenant, ...data]);
  }
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div><h1 className="text-xl font-semibold">Tenants</h1><p className="text-sm text-slate-400">{loading ? 'Loading tenants' : error || `${data.length} tenants`}</p></div>
        <button onClick={create} className="focus-ring rounded-md border border-slate-700 bg-base-900 p-2 text-slate-300 hover:text-cyan-200" title="Create tenant"><Plus size={18} /></button>
      </div>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {data.map((tenant) => (
          <article key={tenant.id} className="rounded-lg border border-slate-800 bg-base-900 p-4">
            <div className="flex items-start justify-between gap-3">
              <div><h2 className="font-semibold">{tenant.name}</h2><p className="text-sm text-slate-400">{tenant.contact_person}</p></div>
              <StatusBadge status={tenant.status} />
            </div>
            <p className="mt-4 text-sm text-slate-300">{tenant.description}</p>
            <p className="mt-3 text-xs uppercase text-slate-500">Retention {tenant.retention_days} days</p>
          </article>
        ))}
      </div>
    </div>
  );
}
