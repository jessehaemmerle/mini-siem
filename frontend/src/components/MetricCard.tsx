import type { LucideIcon } from 'lucide-react';

export function MetricCard({ title, value, icon: Icon, tone = 'cyan' }: { title: string; value: string | number; icon: LucideIcon; tone?: 'cyan' | 'red' | 'amber' | 'emerald' | 'violet' }) {
  const tones = {
    cyan: 'text-cyan-300 bg-cyan-500/10 ring-cyan-500/20',
    red: 'text-red-300 bg-red-500/10 ring-red-500/20',
    amber: 'text-amber-300 bg-amber-500/10 ring-amber-500/20',
    emerald: 'text-emerald-300 bg-emerald-500/10 ring-emerald-500/20',
    violet: 'text-violet-300 bg-violet-500/10 ring-violet-500/20',
  };
  return (
    <div className="rounded-lg border border-slate-800 bg-base-900 p-4 shadow-glow">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-xs uppercase text-slate-400">{title}</p>
          <p className="mt-2 text-2xl font-semibold text-slate-50">{value}</p>
        </div>
        <span className={`rounded-lg p-2 ring-1 ${tones[tone]}`}>
          <Icon size={20} />
        </span>
      </div>
    </div>
  );
}
