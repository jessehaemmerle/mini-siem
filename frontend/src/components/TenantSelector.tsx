import { useEffect, useState } from 'react';
import { getTenantId, setTenantId } from '../api/client';
import { useApi } from '../hooks/useApi';
import type { Tenant } from '../types';

export function TenantSelector() {
  const { data } = useApi<Tenant[]>('/api/tenants', [], []);
  const [selected, setSelected] = useState(getTenantId());

  useEffect(() => {
    if (!selected && data[0]) {
      setSelected(data[0].id);
      setTenantId(data[0].id);
    }
  }, [data, selected]);

  return (
    <select
      className="focus-ring max-w-56 rounded-md border border-slate-700 bg-base-950 px-3 py-2 text-sm text-slate-100"
      value={selected}
      onChange={(event) => {
        setSelected(event.target.value);
        setTenantId(event.target.value);
        window.location.reload();
      }}
    >
      {data.map((tenant) => (
        <option key={tenant.id} value={tenant.id}>
          {tenant.name}
        </option>
      ))}
    </select>
  );
}
