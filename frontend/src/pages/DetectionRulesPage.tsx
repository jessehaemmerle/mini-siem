import { Play, Plus, ToggleLeft, ToggleRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import { RiskScore, SeverityBadge } from '../components/Badges';
import { useApi } from '../hooks/useApi';
import type { DetectionRule } from '../types';

export function DetectionRulesPage() {
  const { data, setData, loading, error } = useApi<DetectionRule[]>('/api/detection-rules', [], []);
  async function toggle(rule: DetectionRule) {
    const updated = await api<DetectionRule>(`/api/detection-rules/${rule.id}/${rule.enabled ? 'disable' : 'enable'}`, { method: 'POST' });
    setData(data.map((item) => (item.id === rule.id ? updated : item)));
  }
  async function test(rule: DetectionRule) {
    await api(`/api/detection-rules/${rule.id}/test`, { method: 'POST' });
  }
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div><h1 className="text-xl font-semibold">Detection Rules</h1><p className="text-sm text-slate-400">{loading ? 'Loading rules' : error || `${data.length} rules`}</p></div>
        <Link to="/rules/new" className="focus-ring rounded-md border border-slate-700 bg-base-900 p-2 text-slate-300 hover:text-cyan-200" title="Create rule"><Plus size={18} /></Link>
      </div>
      <div className="scrollbar overflow-auto rounded-lg border border-slate-800">
        <table className="min-w-full divide-y divide-slate-800 text-sm">
          <thead className="bg-base-850 text-left text-xs uppercase text-slate-400"><tr><th className="px-3 py-3">Rule</th><th className="px-3 py-3">Type</th><th className="px-3 py-3">Severity</th><th className="px-3 py-3">Risk</th><th className="px-3 py-3">MITRE</th><th className="px-3 py-3">Actions</th></tr></thead>
          <tbody className="divide-y divide-slate-800 bg-base-900">
            {data.map((rule) => (
              <tr key={rule.id} className="hover:bg-base-800/80">
                <td className="px-3 py-3"><Link to={`/rules/${rule.id}`} className="font-medium hover:text-cyan-300">{rule.name}</Link></td>
                <td className="px-3 py-3 text-slate-300">{rule.condition_type}</td>
                <td className="px-3 py-3"><SeverityBadge severity={rule.severity} /></td>
                <td className="px-3 py-3"><RiskScore value={rule.risk_score} /></td>
                <td className="px-3 py-3 text-slate-300">{rule.mitre_technique_id}</td>
                <td className="flex gap-2 px-3 py-3">
                  <button onClick={() => toggle(rule)} className="text-slate-300 hover:text-cyan-300" title="Toggle">{rule.enabled ? <ToggleRight size={18} /> : <ToggleLeft size={18} />}</button>
                  <button onClick={() => test(rule)} className="text-slate-300 hover:text-emerald-300" title="Test"><Play size={18} /></button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
