import { AlertTriangle, Database, RadioTower, ShieldAlert } from 'lucide-react';
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { ChartCard } from '../components/ChartCard';
import { MetricCard } from '../components/MetricCard';
import { useApi } from '../hooks/useApi';

type Overview = {
  metrics: { events_24h: number; open_alerts: number; critical_alerts: number; new_alerts: number };
  alerts_by_severity: Record<string, number>;
  log_aggregations: Record<string, any>;
  system_health: Record<string, string>;
};

function buckets(aggs: any, name: string) {
  return aggs?.[name]?.buckets?.map((item: any) => ({ name: item.key_as_string || item.key || 'unknown', value: item.doc_count })) || [];
}

export function DashboardPage() {
  const { data, loading, error } = useApi<Overview>('/api/dashboard/overview', { metrics: { events_24h: 0, open_alerts: 0, critical_alerts: 0, new_alerts: 0 }, alerts_by_severity: {}, log_aggregations: {}, system_health: {} }, []);
  const severity = Object.entries(data.alerts_by_severity || {}).map(([name, value]) => ({ name, value }));
  const events = buckets(data.log_aggregations, 'events_over_time');
  const hosts = buckets(data.log_aggregations, 'top_hosts');
  const ips = buckets(data.log_aggregations, 'top_source_ips');
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-slate-50">Security Overview</h1>
          <p className="text-sm text-slate-400">{loading ? 'Loading telemetry' : error || 'Live tenant telemetry'}</p>
        </div>
      </div>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard title="Events 24h" value={data.metrics.events_24h} icon={Database} tone="cyan" />
        <MetricCard title="Open Alerts" value={data.metrics.open_alerts} icon={ShieldAlert} tone="amber" />
        <MetricCard title="Critical Alerts" value={data.metrics.critical_alerts} icon={AlertTriangle} tone="red" />
        <MetricCard title="Health" value={Object.values(data.system_health || {}).every((v) => v === 'ok') ? 'OK' : 'Check'} icon={RadioTower} tone="emerald" />
      </div>
      <div className="grid gap-4 xl:grid-cols-3">
        <ChartCard title="Events Per Hour">
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={events}>
                <CartesianGrid stroke="#1f2937" />
                <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} />
                <Tooltip contentStyle={{ background: '#0d111c', border: '1px solid #334155' }} />
                <Area type="monotone" dataKey="value" stroke="#22d3ee" fill="#0891b233" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </ChartCard>
        <ChartCard title="Alerts By Severity">
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={severity} dataKey="value" nameKey="name" outerRadius={92} label>
                  {severity.map((entry) => (
                    <Cell key={entry.name} fill={{ critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#10b981', informational: '#64748b' }[entry.name] || '#38bdf8'} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: '#0d111c', border: '1px solid #334155' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </ChartCard>
        <ChartCard title="Top Source IPs">
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={ips.length ? ips : hosts}>
                <CartesianGrid stroke="#1f2937" />
                <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} />
                <Tooltip contentStyle={{ background: '#0d111c', border: '1px solid #334155' }} />
                <Bar dataKey="value" fill="#a78bfa" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </ChartCard>
      </div>
    </div>
  );
}
