import { Save } from 'lucide-react';
import { FormEvent, useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { api } from '../api/client';
import { JsonViewer } from '../components/JsonViewer';
import type { DetectionRule, Severity } from '../types';

type RuleDraft = {
  name: string;
  description: string;
  enabled: boolean;
  condition_type: string;
  severity: Severity;
  risk_score: number;
  timeframe_minutes: number;
  threshold: number;
  group_by: string[];
  query_definition: Record<string, unknown>;
  mitre_tactic: string;
  mitre_technique: string;
  mitre_technique_id: string;
  false_positive_notes: string;
  response_recommendation: string;
};

type EditableRule = DetectionRule | RuleDraft;

const emptyRule: RuleDraft = {
  name: '',
  description: '',
  enabled: true,
  condition_type: 'match',
  severity: 'medium',
  risk_score: 50,
  timeframe_minutes: 5,
  threshold: 1,
  group_by: [],
  query_definition: { fields: { event_action: 'login_failed' } },
  mitre_tactic: '',
  mitre_technique: '',
  mitre_technique_id: '',
  false_positive_notes: '',
  response_recommendation: '',
};

export function RuleEditorPage() {
  const { ruleId } = useParams();
  const navigate = useNavigate();
  const isNew = ruleId === 'new';
  const [json, setJson] = useState(JSON.stringify(emptyRule, null, 2));
  const [data, setData] = useState<EditableRule>(emptyRule);
  useEffect(() => {
    if (isNew) {
      setData(emptyRule);
      setJson(JSON.stringify(emptyRule, null, 2));
      return;
    }
    api<DetectionRule>(`/api/detection-rules/${ruleId}`).then((rule) => {
      setData(rule);
      setJson(JSON.stringify(rule, null, 2));
    });
  }, [isNew, ruleId]);
  async function submit(event: FormEvent) {
    event.preventDefault();
    const payload = JSON.parse(json || JSON.stringify(data));
    const rule = await api<DetectionRule>(isNew ? '/api/detection-rules' : `/api/detection-rules/${ruleId}`, { method: isNew ? 'POST' : 'PUT', body: JSON.stringify(payload) });
    navigate(`/rules/${rule.id}`);
  }
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_420px]">
      <form onSubmit={submit} className="rounded-lg border border-slate-800 bg-base-900 p-4">
        <div className="mb-4 flex items-center justify-between">
          <h1 className="text-xl font-semibold">{isNew ? 'New Detection Rule' : 'Detection Rule Editor'}</h1>
          <button className="focus-ring rounded-md border border-slate-700 bg-base-950 p-2 text-slate-300 hover:text-cyan-200" title="Save"><Save size={18} /></button>
        </div>
        <textarea className="focus-ring min-h-[520px] w-full rounded-md border border-slate-700 bg-base-950 p-3 font-mono text-xs text-slate-100" value={json} onChange={(event) => setJson(event.target.value)} />
      </form>
      <JsonViewer value={data} />
    </div>
  );
}
