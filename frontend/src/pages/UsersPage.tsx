import { Plus } from 'lucide-react';
import { api } from '../api/client';
import { StatusBadge } from '../components/Badges';
import { useApi } from '../hooks/useApi';
import type { User } from '../types';

export function UsersPage() {
  const { data, setData, loading, error } = useApi<User[]>('/api/users', [], []);
  async function create() {
    const suffix = data.length + 1;
    const user = await api<User>('/api/users', { method: 'POST', body: JSON.stringify({ email: `analyst${suffix}@example.com`, full_name: `Analyst ${suffix}`, password: 'Analyst123!', role: 'security_analyst', is_active: true }) });
    setData([user, ...data]);
  }
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div><h1 className="text-xl font-semibold">Users & Roles</h1><p className="text-sm text-slate-400">{loading ? 'Loading users' : error || `${data.length} users`}</p></div>
        <button onClick={create} className="focus-ring rounded-md border border-slate-700 bg-base-900 p-2 text-slate-300 hover:text-cyan-200" title="Create user"><Plus size={18} /></button>
      </div>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {data.map((user) => (
          <article key={user.id} className="rounded-lg border border-slate-800 bg-base-900 p-4">
            <div className="flex items-start justify-between gap-3">
              <div><h2 className="font-semibold">{user.full_name}</h2><p className="text-sm text-slate-400">{user.email}</p></div>
              <StatusBadge status={user.is_active ? 'active' : 'inactive'} />
            </div>
            <div className="mt-4 text-sm text-slate-300">
              <p><span className="text-xs uppercase text-slate-500">Role</span> {user.role.replace('_', ' ')}</p>
              <p><span className="text-xs uppercase text-slate-500">MFA</span> {user.mfa_enabled ? 'enabled' : 'prepared'}</p>
            </div>
          </article>
        ))}
      </div>
    </div>
  );
}
