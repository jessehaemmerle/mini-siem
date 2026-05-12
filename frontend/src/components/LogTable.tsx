import { Link } from 'react-router-dom';
import { SeverityBadge } from './Badges';

export function LogTable({ items }: { items: Record<string, unknown>[] }) {
  return (
    <div className="scrollbar overflow-auto rounded-lg border border-slate-800">
      <table className="min-w-full divide-y divide-slate-800 text-sm">
        <thead className="bg-base-850 text-left text-xs uppercase text-slate-400">
          <tr>
            <th className="px-3 py-3">Time</th>
            <th className="px-3 py-3">Severity</th>
            <th className="px-3 py-3">Host</th>
            <th className="px-3 py-3">User</th>
            <th className="px-3 py-3">Source</th>
            <th className="px-3 py-3">Message</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800 bg-base-900">
          {items.map((item) => (
            <tr key={String(item.id)} className="hover:bg-base-800/80">
              <td className="whitespace-nowrap px-3 py-3 font-mono text-xs text-slate-400">{String(item.timestamp || '').slice(0, 19)}</td>
              <td className="px-3 py-3"><SeverityBadge severity={String(item.severity || 'informational')} /></td>
              <td className="whitespace-nowrap px-3 py-3 text-slate-200">{String(item.hostname || '')}</td>
              <td className="whitespace-nowrap px-3 py-3 text-slate-300">{String(item.user_name || '')}</td>
              <td className="whitespace-nowrap px-3 py-3 text-slate-300">{String(item.source_type || '')}</td>
              <td className="max-w-xl truncate px-3 py-3 text-slate-200">
                <Link to={`/logs/${item.id}`} className="hover:text-cyan-300">{String(item.message || '')}</Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
