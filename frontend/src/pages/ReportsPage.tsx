import { Download, FilePlus } from 'lucide-react';
import { api } from '../api/client';
import { JsonViewer } from '../components/JsonViewer';
import { useApi } from '../hooks/useApi';
import type { Report } from '../types';

export function ReportsPage() {
  const { data, setData, loading, error } = useApi<Report[]>('/api/reports', [], []);
  async function generate(report_type: string) {
    const report = await api<Report>('/api/reports/generate', { method: 'POST', body: JSON.stringify({ report_type, title: report_type.replaceAll('_', ' '), file_type: 'json' }) });
    setData([report, ...data]);
  }
  async function download(report: Report) {
    const result = await api<Record<string, unknown>>(`/api/reports/${report.id}/download`);
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `${report.id}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div><h1 className="text-xl font-semibold">Reports</h1><p className="text-sm text-slate-400">{loading ? 'Loading reports' : error || `${data.length} reports`}</p></div>
        <div className="flex gap-2">
          {['daily_security_report', 'weekly_management_report', 'monthly_compliance_report', 'alert_summary'].map((type) => (
            <button key={type} onClick={() => generate(type)} className="focus-ring rounded-md border border-slate-700 bg-base-900 p-2 text-slate-300 hover:text-cyan-200" title={type.replaceAll('_', ' ')}><FilePlus size={18} /></button>
          ))}
        </div>
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        {data.map((report) => (
          <article key={report.id} className="rounded-lg border border-slate-800 bg-base-900 p-4">
            <div className="mb-3 flex items-start justify-between gap-3">
              <div><h2 className="font-semibold">{report.title}</h2><p className="text-sm text-slate-400">{report.report_type} · {report.created_at.slice(0, 19)}</p></div>
              <button onClick={() => download(report)} className="focus-ring rounded-md border border-slate-700 bg-base-950 p-2 text-slate-300 hover:text-cyan-200" title="Download"><Download size={18} /></button>
            </div>
            <JsonViewer value={report.content} />
          </article>
        ))}
      </div>
    </div>
  );
}
