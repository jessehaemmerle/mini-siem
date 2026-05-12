import { CheckCircle2, MessageSquare, ShieldX } from 'lucide-react';
import { useParams } from 'react-router-dom';
import { api } from '../api/client';
import { RiskScore, SeverityBadge, StatusBadge } from '../components/Badges';
import { JsonViewer } from '../components/JsonViewer';
import { useApi } from '../hooks/useApi';
import type { Alert } from '../types';

export function AlertDetailPage() {
  const { alertId } = useParams();
  const { data, setData } = useApi<Alert & { comments?: unknown[] }>(`/api/alerts/${alertId}`, {} as Alert, [alertId]);
  async function action(path: string) {
    const updated = await api<Alert>(`/api/alerts/${alertId}/${path}`, { method: 'POST', body: JSON.stringify({ resolution_comment: 'Updated from SOC console' }) });
    setData({ ...data, ...updated });
  }
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-slate-50">{data.title}</h1>
          <p className="text-sm text-slate-400">{data.id}</p>
        </div>
        <div className="flex gap-2">
          <button className="focus-ring rounded-md border border-slate-700 bg-base-900 p-2 text-slate-300 hover:text-cyan-200" title="Acknowledge" onClick={() => action('acknowledge')}><MessageSquare size={18} /></button>
          <button className="focus-ring rounded-md border border-slate-700 bg-base-900 p-2 text-slate-300 hover:text-emerald-200" title="Resolve" onClick={() => action('resolve')}><CheckCircle2 size={18} /></button>
          <button className="focus-ring rounded-md border border-slate-700 bg-base-900 p-2 text-slate-300 hover:text-amber-200" title="False positive" onClick={() => action('false-positive')}><ShieldX size={18} /></button>
        </div>
      </div>
      <section className="grid gap-4 md:grid-cols-4">
        <div className="rounded-lg border border-slate-800 bg-base-900 p-4"><p className="text-xs uppercase text-slate-500">Severity</p><p className="mt-2"><SeverityBadge severity={data.severity || 'informational'} /></p></div>
        <div className="rounded-lg border border-slate-800 bg-base-900 p-4"><p className="text-xs uppercase text-slate-500">Status</p><p className="mt-2"><StatusBadge status={data.status || 'new'} /></p></div>
        <div className="rounded-lg border border-slate-800 bg-base-900 p-4"><p className="text-xs uppercase text-slate-500">Risk</p><p className="mt-2"><RiskScore value={data.risk_score || 0} /></p></div>
        <div className="rounded-lg border border-slate-800 bg-base-900 p-4"><p className="text-xs uppercase text-slate-500">MITRE</p><p className="mt-2 text-sm">{data.mitre_technique_id || data.mitre_tactic}</p></div>
      </section>
      <section className="rounded-lg border border-slate-800 bg-base-900 p-4">
        <h2 className="mb-2 text-sm font-semibold">Response</h2>
        <p className="text-sm text-slate-300">{data.response_recommendation || data.description}</p>
      </section>
      <JsonViewer value={data.matched_events || []} />
    </div>
  );
}
