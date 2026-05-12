from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.types import JSON

from app.db.base import Base

JSONType = JSON().with_variant(JSONB, "postgresql")


def uuid_str() -> str:
    return str(uuid.uuid4())


def now_utc() -> datetime:
    return datetime.now(UTC)


class TimestampMixin:
    created_at = Column(DateTime(timezone=True), default=now_utc, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc, nullable=False)


class Tenant(Base, TimestampMixin):
    __tablename__ = "tenants"

    id = Column(String(36), primary_key=True, default=uuid_str)
    name = Column(String(255), nullable=False, unique=True, index=True)
    description = Column(Text, default="")
    status = Column(String(32), default="active", nullable=False)
    retention_days = Column(Integer, default=90, nullable=False)
    contact_person = Column(String(255), default="")
    allowed_log_sources = Column(JSONType, default=list, nullable=False)

    memberships = relationship("UserTenantMembership", back_populates="tenant", cascade="all, delete-orphan")


class Role(Base, TimestampMixin):
    __tablename__ = "roles"

    id = Column(String(36), primary_key=True, default=uuid_str)
    name = Column(String(64), nullable=False, unique=True)
    description = Column(Text, default="")
    permissions = Column(JSONType, default=list, nullable=False)


class Permission(Base):
    __tablename__ = "permissions"

    id = Column(String(36), primary_key=True, default=uuid_str)
    name = Column(String(128), nullable=False, unique=True)
    description = Column(Text, default="")


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=uuid_str)
    email = Column(String(255), nullable=False, unique=True, index=True)
    full_name = Column(String(255), nullable=False)
    password_hash = Column(Text, nullable=False)
    role = Column(String(64), nullable=False, default="viewer")
    is_active = Column(Boolean, default=True, nullable=False)
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_secret = Column(Text, nullable=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)

    memberships = relationship("UserTenantMembership", back_populates="user", cascade="all, delete-orphan")


class UserTenantMembership(Base, TimestampMixin):
    __tablename__ = "user_tenant_memberships"
    __table_args__ = (UniqueConstraint("user_id", "tenant_id", name="uq_user_tenant"),)

    id = Column(String(36), primary_key=True, default=uuid_str)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    role = Column(String(64), nullable=False, default="viewer")

    user = relationship("User", back_populates="memberships")
    tenant = relationship("Tenant", back_populates="memberships")


class LogSource(Base, TimestampMixin):
    __tablename__ = "log_sources"

    id = Column(String(36), primary_key=True, default=uuid_str)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    source_type = Column(String(64), nullable=False)
    hostname = Column(String(255), default="")
    ip_address = Column(String(64), default="")
    status = Column(String(32), default="active", nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    events_last_24h = Column(Integer, default=0, nullable=False)
    description = Column(Text, default="")

    api_keys = relationship("ApiKey", back_populates="source", cascade="all, delete-orphan")


class ApiKey(Base, TimestampMixin):
    __tablename__ = "api_keys"

    id = Column(String(36), primary_key=True, default=uuid_str)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    source_id = Column(String(36), ForeignKey("log_sources.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    key_hash = Column(String(128), nullable=False, unique=True, index=True)
    key_prefix = Column(String(24), nullable=False)
    active = Column(Boolean, default=True, nullable=False)
    last_used_at = Column(DateTime(timezone=True), nullable=True)

    source = relationship("LogSource", back_populates="api_keys")


class DetectionRule(Base, TimestampMixin):
    __tablename__ = "detection_rules"

    id = Column(String(36), primary_key=True, default=uuid_str)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, default="")
    enabled = Column(Boolean, default=True, nullable=False)
    severity = Column(String(32), default="medium", nullable=False)
    risk_score = Column(Integer, default=50, nullable=False)
    query_definition = Column(JSONType, default=dict, nullable=False)
    condition_type = Column(String(32), nullable=False, default="match")
    timeframe_minutes = Column(Integer, default=5, nullable=False)
    threshold = Column(Integer, default=1, nullable=False)
    group_by = Column(JSONType, default=list, nullable=False)
    mitre_tactic = Column(String(255), default="")
    mitre_technique = Column(String(255), default="")
    mitre_technique_id = Column(String(64), default="")
    false_positive_notes = Column(Text, default="")
    response_recommendation = Column(Text, default="")
    created_by = Column(String(36), nullable=True)
    updated_by = Column(String(36), nullable=True)


class Alert(Base, TimestampMixin):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alert_tenant_status_created", "tenant_id", "status", "created_at"),
        UniqueConstraint("dedup_key", name="uq_alert_dedup_key"),
    )

    id = Column(String(36), primary_key=True, default=uuid_str)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(512), nullable=False)
    description = Column(Text, default="")
    severity = Column(String(32), default="medium", nullable=False)
    status = Column(String(32), default="new", nullable=False)
    risk_score = Column(Integer, default=50, nullable=False)
    rule_id = Column(String(36), ForeignKey("detection_rules.id", ondelete="SET NULL"), nullable=True)
    matched_events = Column(JSONType, default=list, nullable=False)
    assigned_to = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolution_comment = Column(Text, default="")
    false_positive = Column(Boolean, default=False, nullable=False)
    mitre_tactic = Column(String(255), default="")
    mitre_technique = Column(String(255), default="")
    mitre_technique_id = Column(String(64), default="")
    response_recommendation = Column(Text, default="")
    dedup_key = Column(String(512), nullable=False)

    comments = relationship("AlertComment", back_populates="alert", cascade="all, delete-orphan")


class AlertComment(Base, TimestampMixin):
    __tablename__ = "alert_comments"

    id = Column(String(36), primary_key=True, default=uuid_str)
    alert_id = Column(String(36), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    comment = Column(Text, nullable=False)

    alert = relationship("Alert", back_populates="comments")


class Incident(Base, TimestampMixin):
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=uuid_str)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(512), nullable=False)
    description = Column(Text, default="")
    severity = Column(String(32), default="medium", nullable=False)
    status = Column(String(32), default="open", nullable=False)
    owner = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    closed_at = Column(DateTime(timezone=True), nullable=True)

    timeline = relationship("IncidentTimelineEntry", back_populates="incident", cascade="all, delete-orphan")


class IncidentAlert(Base, TimestampMixin):
    __tablename__ = "incident_alerts"
    __table_args__ = (UniqueConstraint("incident_id", "alert_id", name="uq_incident_alert"),)

    id = Column(String(36), primary_key=True, default=uuid_str)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    alert_id = Column(String(36), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True)


class IncidentTimelineEntry(Base, TimestampMixin):
    __tablename__ = "incident_timeline_entries"

    id = Column(String(36), primary_key=True, default=uuid_str)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    entry_type = Column(String(64), default="note", nullable=False)
    message = Column(Text, nullable=False)

    incident = relationship("Incident", back_populates="timeline")


class Report(Base, TimestampMixin):
    __tablename__ = "reports"

    id = Column(String(36), primary_key=True, default=uuid_str)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    report_type = Column(String(128), nullable=False)
    title = Column(String(512), nullable=False)
    status = Column(String(32), default="generated", nullable=False)
    parameters = Column(JSONType, default=dict, nullable=False)
    content = Column(JSONType, default=dict, nullable=False)
    file_type = Column(String(32), default="json", nullable=False)
    created_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_tenant_timestamp", "tenant_id", "timestamp"),)

    id = Column(String(36), primary_key=True, default=uuid_str)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True, index=True)
    timestamp = Column(DateTime(timezone=True), default=now_utc, nullable=False)
    actor_user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    actor_username = Column(String(255), default="")
    action = Column(String(255), nullable=False)
    entity_type = Column(String(128), nullable=False)
    entity_id = Column(String(36), nullable=True)
    old_value = Column(JSONType, nullable=True)
    new_value = Column(JSONType, nullable=True)
    ip_address = Column(String(64), default="")
    user_agent = Column(Text, default="")


class NotificationRule(Base, TimestampMixin):
    __tablename__ = "notification_rules"

    id = Column(String(36), primary_key=True, default=uuid_str)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    channel = Column(String(64), default="demo", nullable=False)
    target = Column(Text, default="")
    severity_min = Column(String(32), default="high")
    filters = Column(JSONType, default=dict, nullable=False)
    outside_business_hours = Column(Boolean, default=False, nullable=False)


class NotificationDelivery(Base, TimestampMixin):
    __tablename__ = "notification_deliveries"

    id = Column(String(36), primary_key=True, default=uuid_str)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    alert_id = Column(String(36), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=True)
    rule_id = Column(String(36), ForeignKey("notification_rules.id", ondelete="SET NULL"), nullable=True)
    channel = Column(String(64), nullable=False)
    target = Column(Text, default="")
    status = Column(String(64), default="pending", nullable=False)
    attempts = Column(Integer, default=0, nullable=False)
    last_error = Column(Text, default="")
    response = Column(Text, default="")


class IOC(Base, TimestampMixin):
    __tablename__ = "iocs"
    __table_args__ = (UniqueConstraint("tenant_id", "value", "type", name="uq_ioc_value_type"),)

    id = Column(String(36), primary_key=True, default=uuid_str)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    value = Column(String(512), nullable=False, index=True)
    type = Column(String(32), nullable=False)
    source = Column(String(255), default="")
    confidence = Column(Integer, default=70, nullable=False)
    severity = Column(String(32), default="medium", nullable=False)
    description = Column(Text, default="")
    expires_at = Column(DateTime(timezone=True), nullable=True)


class SavedSearch(Base, TimestampMixin):
    __tablename__ = "saved_searches"

    id = Column(String(36), primary_key=True, default=uuid_str)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    query = Column(JSONType, default=dict, nullable=False)
    created_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)


class SystemSetting(Base, TimestampMixin):
    __tablename__ = "system_settings"

    id = Column(String(36), primary_key=True, default=uuid_str)
    key = Column(String(255), nullable=False, unique=True)
    value = Column(JSONType, default=dict, nullable=False)
    description = Column(Text, default="")


class RetentionPolicy(Base, TimestampMixin):
    __tablename__ = "retention_policies"

    id = Column(String(36), primary_key=True, default=uuid_str)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, unique=True)
    online_days = Column(Integer, default=90, nullable=False)
    archive_enabled = Column(Boolean, default=False, nullable=False)
    archive_location = Column(Text, default="")
    last_run_at = Column(DateTime(timezone=True), nullable=True)
    last_status = Column(String(64), default="not_run")


class LogEventMeta(Base):
    __tablename__ = "log_event_meta"
    __table_args__ = (
        Index("ix_log_meta_tenant_timestamp", "tenant_id", "timestamp"),
        Index("ix_log_meta_tenant_severity", "tenant_id", "severity"),
    )

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    opensearch_index = Column(String(255), nullable=False)
    timestamp = Column(DateTime(timezone=True), nullable=False)
    received_at = Column(DateTime(timezone=True), default=now_utc, nullable=False)
    source_type = Column(String(64), default="")
    source_name = Column(String(255), default="")
    hostname = Column(String(255), default="")
    severity = Column(String(32), default="informational")
    event_category = Column(String(64), default="application")
    event_action = Column(String(128), default="")
    user_name = Column(String(255), default="")
    src_ip = Column(String(64), default="")
    dst_ip = Column(String(64), default="")
    message = Column(Text, default="")
