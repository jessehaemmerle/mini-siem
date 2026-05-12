import { CheckCircle2, Plus } from 'lucide-react';
import { useParams } from 'react-router-dom';
import { api } from '../api/client';
import { JsonViewer } from '../components/JsonViewer';
import { SeverityBadge, StatusBadge } from '../components/Badges';
import { useApi } from '../hooks/useApi';
import type { Incident } from '../types';

export function IncidentDetailPage() {
  const { incidentId } = useParams();
  const { data, setData } = useApi<Incident & { alerts?: string[]; timeline?: unknown[] }>(`/api/incidents/${incidentId}`, {} as Incident, [incidentId]);
  async function close() {
    await api(`/api/incidents/${incidentId}/close`, { method: 'POST', body: JSON.stringify({ message: 'Closed from SOC console' }) });
    setData({ ...data, status: 'closed' });
  }
  async function note() {
    await api(`/api/incidents/${incidentId}/timeline`, { method: 'POST', body: JSON.stringify({ entry_type: 'note', message: 'Analyst review updated' }) });
    window.location.reload();
  }
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">{data.title}</h1>
          <p className="text-sm text-slate-400">{data.id}</p>
        </div>
        <div className="flex gap-2">
          <button className="focus-ring rounded-md border border-slate-700 bg-base-900 p-2 text-slate-300 hover:text-cyan-200" title="Add note" onClick={note}><Plus size={18} /></button>
          <button className="focus-ring rounded-md border border-slate-700 bg-base-900 p-2 text-slate-300 hover:text-emerald-200" title="Close" onClick={close}><CheckCircle2 size={18} /></button>
        </div>
      </div>
      <section className="grid gap-4 md:grid-cols-3">
        <div className="rounded-lg border border-slate-800 bg-base-900 p-4"><p className="text-xs uppercase text-slate-500">Severity</p><p className="mt-2"><SeverityBadge severity={data.severity || 'medium'} /></p></div>
        <div className="rounded-lg border border-slate-800 bg-base-900 p-4"><p className="text-xs uppercase text-slate-500">Status</p><p className="mt-2"><StatusBadge status={data.status || 'open'} /></p></div>
        <div className="rounded-lg border border-slate-800 bg-base-900 p-4"><p className="text-xs uppercase text-slate-500">Alerts</p><p className="mt-2 text-lg font-semibold">{data.alerts?.length || 0}</p></div>
      </section>
      <JsonViewer value={data.timeline || []} />
    </div>
  );
}
