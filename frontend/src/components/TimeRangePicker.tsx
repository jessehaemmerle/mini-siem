export function TimeRangePicker({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  return (
    <select className="focus-ring rounded-md border border-slate-700 bg-base-950 px-3 py-2 text-sm text-slate-100" value={value} onChange={(event) => onChange(event.target.value)}>
      <option value="1h">Last hour</option>
      <option value="24h">Last 24h</option>
      <option value="7d">Last 7d</option>
      <option value="30d">Last 30d</option>
    </select>
  );
}
