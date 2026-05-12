import { Link } from 'react-router-dom';
import type { Alert } from '../types';
import { RiskScore, SeverityBadge, StatusBadge } from './Badges';

export function AlertTable({ alerts }: { alerts: Alert[] }) {
  return (
    <div className="scrollbar overflow-auto rounded-lg border border-slate-800">
      <table className="min-w-full divide-y divide-slate-800 text-sm">
        <thead className="bg-base-850 text-left text-xs uppercase text-slate-400">
          <tr>
            <th className="px-3 py-3">Alert</th>
            <th className="px-3 py-3">Severity</th>
            <th className="px-3 py-3">Status</th>
            <th className="px-3 py-3">Risk</th>
            <th className="px-3 py-3">MITRE</th>
            <th className="px-3 py-3">Created</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800 bg-base-900">
          {alerts.map((alert) => (
            <tr key={alert.id} className="hover:bg-base-800/80">
              <td className="max-w-md truncate px-3 py-3">
                <Link to={`/alerts/${alert.id}`} className="font-medium text-slate-100 hover:text-cyan-300">{alert.title}</Link>
              </td>
              <td className="px-3 py-3"><SeverityBadge severity={alert.severity} /></td>
              <td className="px-3 py-3"><StatusBadge status={alert.status} /></td>
              <td className="px-3 py-3"><RiskScore value={alert.risk_score} /></td>
              <td className="whitespace-nowrap px-3 py-3 text-slate-300">{alert.mitre_technique_id || alert.mitre_tactic}</td>
              <td className="whitespace-nowrap px-3 py-3 font-mono text-xs text-slate-400">{alert.created_at.slice(0, 19)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
