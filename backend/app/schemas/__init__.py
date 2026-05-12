from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field

Severity = Literal["informational", "low", "medium", "high", "critical"]


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: "UserRead"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)


class TenantBase(BaseModel):
    name: str
    description: str = ""
    status: str = "active"
    retention_days: int = 90
    contact_person: str = ""
    allowed_log_sources: list[str] = Field(default_factory=list)


class TenantCreate(TenantBase):
    pass


class TenantUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    status: str | None = None
    retention_days: int | None = None
    contact_person: str | None = None
    allowed_log_sources: list[str] | None = None


class TenantRead(TenantBase):
    id: str
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


class UserBase(BaseModel):
    email: EmailStr
    full_name: str
    role: str = "viewer"
    is_active: bool = True
    mfa_enabled: bool = False


class UserCreate(UserBase):
    password: str = Field(min_length=8)
    tenant_ids: list[str] = Field(default_factory=list)


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    full_name: str | None = None
    role: str | None = None
    is_active: bool | None = None
    mfa_enabled: bool | None = None
    password: str | None = Field(default=None, min_length=8)
    tenant_ids: list[str] | None = None


class UserRead(UserBase):
    id: str
    tenant_ids: list[str] = Field(default_factory=list)
    created_at: datetime | None = None
    updated_at: datetime | None = None
    last_login_at: datetime | None = None
    model_config = ConfigDict(from_attributes=True)


class ApiKeyRead(BaseModel):
    id: str
    name: str
    key_prefix: str
    active: bool
    last_used_at: datetime | None = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class LogSourceBase(BaseModel):
    name: str
    source_type: str
    hostname: str = ""
    ip_address: str = ""
    status: str = "active"
    description: str = ""


class LogSourceCreate(LogSourceBase):
    tenant_id: str | None = None


class LogSourceUpdate(BaseModel):
    name: str | None = None
    source_type: str | None = None
    hostname: str | None = None
    ip_address: str | None = None
    status: str | None = None
    description: str | None = None


class LogSourceRead(LogSourceBase):
    id: str
    tenant_id: str
    last_seen: datetime | None = None
    events_last_24h: int
    created_at: datetime
    api_keys: list[ApiKeyRead] = Field(default_factory=list)
    model_config = ConfigDict(from_attributes=True)


class LogSourceCreateResponse(BaseModel):
    source: LogSourceRead
    api_key: str


class IngestEventIn(BaseModel):
    tenant_id: str | None = None
    source_type: str | None = None
    source_name: str | None = None
    hostname: str | None = None
    ip_address: str | None = None
    timestamp: datetime | str | None = None
    severity: str | int | None = None
    event_id: str | int | None = None
    message: str | None = None
    raw_log: str | None = None
    user: str | None = None
    user_name: str | None = None
    process_name: str | None = None
    command_line: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    action: str | None = None
    geo_country: str | None = None
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IngestResponse(BaseModel):
    accepted: int
    rejected: int = 0
    alerts_created: int = 0
    ids: list[str] = Field(default_factory=list)


class SyslogIngestRequest(BaseModel):
    line: str
    source_name: str = "syslog"


class LogSearchResponse(BaseModel):
    total: int
    page: int
    size: int
    items: list[dict[str, Any]]
    aggregations: dict[str, Any] = Field(default_factory=dict)


class DetectionRuleBase(BaseModel):
    name: str
    description: str = ""
    enabled: bool = True
    severity: Severity = "medium"
    risk_score: int = Field(default=50, ge=0, le=100)
    query_definition: dict[str, Any] = Field(default_factory=dict)
    condition_type: str = "match"
    timeframe_minutes: int = 5
    threshold: int = 1
    group_by: list[str] = Field(default_factory=list)
    mitre_tactic: str = ""
    mitre_technique: str = ""
    mitre_technique_id: str = ""
    false_positive_notes: str = ""
    response_recommendation: str = ""


class DetectionRuleCreate(DetectionRuleBase):
    tenant_id: str | None = None


class DetectionRuleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    enabled: bool | None = None
    severity: Severity | None = None
    risk_score: int | None = Field(default=None, ge=0, le=100)
    query_definition: dict[str, Any] | None = None
    condition_type: str | None = None
    timeframe_minutes: int | None = None
    threshold: int | None = None
    group_by: list[str] | None = None
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    mitre_technique_id: str | None = None
    false_positive_notes: str | None = None
    response_recommendation: str | None = None


class DetectionRuleRead(DetectionRuleBase):
    id: str
    tenant_id: str
    created_by: str | None = None
    updated_by: str | None = None
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


class AlertRead(BaseModel):
    id: str
    tenant_id: str
    title: str
    description: str
    severity: str
    status: str
    risk_score: int
    rule_id: str | None = None
    matched_events: list[dict[str, Any]] = Field(default_factory=list)
    assigned_to: str | None = None
    created_at: datetime
    updated_at: datetime
    acknowledged_at: datetime | None = None
    resolved_at: datetime | None = None
    resolution_comment: str
    false_positive: bool
    mitre_tactic: str
    mitre_technique: str
    mitre_technique_id: str = ""
    response_recommendation: str
    model_config = ConfigDict(from_attributes=True)


class AlertUpdate(BaseModel):
    status: str | None = None
    severity: Severity | None = None
    risk_score: int | None = Field(default=None, ge=0, le=100)
    assigned_to: str | None = None
    resolution_comment: str | None = None
    false_positive: bool | None = None


class AlertCommentCreate(BaseModel):
    comment: str


class IncidentCreate(BaseModel):
    tenant_id: str | None = None
    title: str
    description: str = ""
    severity: Severity = "medium"
    owner: str | None = None
    alert_ids: list[str] = Field(default_factory=list)


class IncidentUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    severity: Severity | None = None
    status: str | None = None
    owner: str | None = None


class IncidentRead(BaseModel):
    id: str
    tenant_id: str
    title: str
    description: str
    severity: str
    status: str
    owner: str | None = None
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None = None
    model_config = ConfigDict(from_attributes=True)


class IncidentAddAlert(BaseModel):
    alert_id: str


class TimelineCreate(BaseModel):
    entry_type: str = "note"
    message: str


class ReportGenerateRequest(BaseModel):
    tenant_id: str | None = None
    report_type: str
    title: str | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    file_type: str = "json"


class ReportRead(BaseModel):
    id: str
    tenant_id: str
    report_type: str
    title: str
    status: str
    parameters: dict[str, Any]
    content: dict[str, Any]
    file_type: str
    created_by: str | None = None
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


class IOCBase(BaseModel):
    value: str
    type: Literal["ip", "domain", "url", "hash", "email"]
    source: str = ""
    confidence: int = Field(default=70, ge=0, le=100)
    severity: Severity = "medium"
    description: str = ""
    expires_at: datetime | None = None


class IOCCreate(IOCBase):
    tenant_id: str | None = None


class IOCUpdate(BaseModel):
    value: str | None = None
    type: Literal["ip", "domain", "url", "hash", "email"] | None = None
    source: str | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    severity: Severity | None = None
    description: str | None = None
    expires_at: datetime | None = None


class IOCRead(IOCBase):
    id: str
    tenant_id: str
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


class AuditRead(BaseModel):
    id: str
    tenant_id: str | None = None
    timestamp: datetime
    actor_user_id: str | None = None
    actor_username: str
    action: str
    entity_type: str
    entity_id: str | None = None
    old_value: dict[str, Any] | None = None
    new_value: dict[str, Any] | None = None
    ip_address: str
    user_agent: str
    model_config = ConfigDict(from_attributes=True)


class HealthResponse(BaseModel):
    status: str
    components: dict[str, Any]


TokenResponse.model_rebuild()
