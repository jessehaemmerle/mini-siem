import type React from 'react';

export function ChartCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-lg border border-slate-800 bg-base-900 p-4 shadow-glow">
      <h2 className="mb-4 text-sm font-semibold text-slate-100">{title}</h2>
      {children}
    </section>
  );
}
