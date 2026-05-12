export function JsonViewer({ value }: { value: unknown }) {
  return <pre className="scrollbar max-h-96 overflow-auto rounded-lg bg-base-950 p-4 text-xs leading-relaxed text-slate-200 ring-1 ring-slate-800">{JSON.stringify(value, null, 2)}</pre>;
}
