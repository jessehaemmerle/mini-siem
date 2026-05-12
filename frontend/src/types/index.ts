export type Severity = 'informational' | 'low' | 'medium' | 'high' | 'critical';

export type User = {
  id: string;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
  tenant_ids: string[];
  mfa_enabled: boolean;
};

export type Tenant = {
  id: string;
  name: string;
  description: string;
  status: string;
  retention_days: number;
  contact_person: string;
  allowed_log_sources: string[];
};

export type Alert = {
  id: string;
  tenant_id: string;
  title: string;
  description: string;
  severity: Severity;
  status: string;
  risk_score: number;
  rule_id?: string;
  matched_events: Record<string, unknown>[];
  assigned_to?: string;
  created_at: string;
  updated_at: string;
  mitre_tactic: string;
  mitre_technique: string;
  mitre_technique_id?: string;
  response_recommendation: string;
};

export type Incident = {
  id: string;
  tenant_id: string;
  title: string;
  description: string;
  severity: Severity;
  status: string;
  owner?: string;
  created_at: string;
  updated_at: string;
};

export type DetectionRule = {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  enabled: boolean;
  severity: Severity;
  risk_score: number;
  condition_type: string;
  timeframe_minutes: number;
  threshold: number;
  group_by: string[];
  query_definition: Record<string, unknown>;
  mitre_tactic: string;
  mitre_technique: string;
  mitre_technique_id: string;
};

export type LogSource = {
  id: string;
  tenant_id: string;
  name: string;
  source_type: string;
  hostname: string;
  ip_address: string;
  status: string;
  last_seen?: string;
  events_last_24h: number;
  description: string;
};

export type IOC = {
  id: string;
  tenant_id: string;
  value: string;
  type: string;
  source: string;
  confidence: number;
  severity: Severity;
  description: string;
};

export type Report = {
  id: string;
  tenant_id: string;
  report_type: string;
  title: string;
  status: string;
  parameters: Record<string, unknown>;
  content: Record<string, unknown>;
  file_type: string;
  created_at: string;
};
