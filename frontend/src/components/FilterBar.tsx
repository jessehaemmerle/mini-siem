import type React from 'react';
import { Search } from 'lucide-react';

export function FilterBar({ query, setQuery, children }: { query: string; setQuery: (value: string) => void; children?: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-3 rounded-lg border border-slate-800 bg-base-900 p-3 md:flex-row md:items-center">
      <label className="relative flex-1">
        <Search className="pointer-events-none absolute left-3 top-2.5 text-slate-500" size={18} />
        <input className="focus-ring w-full rounded-md border border-slate-700 bg-base-950 py-2 pl-10 pr-3 text-sm text-slate-100" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search" />
      </label>
      {children}
    </div>
  );
}
