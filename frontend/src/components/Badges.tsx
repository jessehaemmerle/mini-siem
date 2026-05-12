import type { Severity } from '../types';

const severityClasses: Record<Severity | string, string> = {
  informational: 'bg-slate-700 text-slate-100 ring-slate-500/40',
  low: 'bg-emerald-950 text-emerald-200 ring-emerald-500/40',
  medium: 'bg-amber-950 text-amber-200 ring-amber-500/40',
  high: 'bg-orange-950 text-orange-200 ring-orange-500/40',
  critical: 'bg-red-950 text-red-200 ring-red-500/50',
};

const statusClasses: Record<string, string> = {
  new: 'bg-cyan-950 text-cyan-200 ring-cyan-500/40',
  acknowledged: 'bg-blue-950 text-blue-200 ring-blue-500/40',
  investigating: 'bg-violet-950 text-violet-200 ring-violet-500/40',
  resolved: 'bg-emerald-950 text-emerald-200 ring-emerald-500/40',
  false_positive: 'bg-slate-800 text-slate-200 ring-slate-500/40',
  suppressed: 'bg-zinc-800 text-zinc-200 ring-zinc-500/40',
  active: 'bg-emerald-950 text-emerald-200 ring-emerald-500/40',
  inactive: 'bg-slate-800 text-slate-300 ring-slate-600/40',
  disabled: 'bg-red-950 text-red-200 ring-red-500/40',
};

export function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`inline-flex rounded px-2 py-1 text-xs font-semibold ring-1 ${severityClasses[severity] || severityClasses.informational}`}>{severity}</span>;
}

export function StatusBadge({ status }: { status: string }) {
  return <span className={`inline-flex rounded px-2 py-1 text-xs font-semibold ring-1 ${statusClasses[status] || statusClasses.inactive}`}>{status.replace('_', ' ')}</span>;
}

export function RiskScore({ value }: { value: number }) {
  const color = value >= 85 ? 'text-red-300' : value >= 65 ? 'text-orange-300' : value >= 40 ? 'text-amber-300' : 'text-emerald-300';
  return <span className={`font-mono text-sm font-semibold ${color}`}>{value}</span>;
}
