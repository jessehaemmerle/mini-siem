from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from sqlalchemy import select

from app.core.permissions import ROLE_LABELS, ROLE_PERMISSIONS
from app.core.security import api_key_prefix, hash_api_key, hash_password
from app.db.init_db import init_db
from app.db.session import SessionLocal
from app.models import ApiKey, DetectionRule, IOC, LogSource, NotificationRule, Permission, RetentionPolicy, Role, SystemSetting, Tenant, User, UserTenantMembership
from scripts.demo_content import DEMO_API_KEY, DEMO_TENANT_NAME, DETECTION_RULES, IOCS, SOURCES, USERS


def seed() -> dict:
    init_db()
    db = SessionLocal()
    try:
        tenant = db.scalar(select(Tenant).where(Tenant.name == DEMO_TENANT_NAME))
        if not tenant:
            tenant = Tenant(
                name=DEMO_TENANT_NAME,
                description="Demo tenant with realistic SOC telemetry.",
                status="active",
                retention_days=90,
                contact_person="soc@example.com",
                allowed_log_sources=["windows", "linux", "firewall", "vpn", "edr", "antivirus", "syslog", "custom"],
            )
            db.add(tenant)
            db.flush()
            db.add(RetentionPolicy(tenant_id=tenant.id, online_days=90, archive_enabled=False))

        for permission in sorted({p for values in ROLE_PERMISSIONS.values() for p in values if p != "*"} | {"*"}):
            if not db.scalar(select(Permission).where(Permission.name == permission)):
                db.add(Permission(name=permission, description=f"Allows {permission}"))
        for role, label in ROLE_LABELS.items():
            row = db.scalar(select(Role).where(Role.name == role))
            if not row:
                db.add(Role(name=role, description=label, permissions=sorted(ROLE_PERMISSIONS[role])))

        created_users = []
        for email, full_name, password, role in USERS:
            user = db.scalar(select(User).where(User.email == email))
            if not user:
                user = User(email=email, full_name=full_name, password_hash=hash_password(password), role=role, is_active=True)
                db.add(user)
                db.flush()
            if not db.scalar(select(UserTenantMembership).where(UserTenantMembership.user_id == user.id, UserTenantMembership.tenant_id == tenant.id)):
                db.add(UserTenantMembership(user_id=user.id, tenant_id=tenant.id, role=role))
            created_users.append(user)

        source_rows = []
        for name, source_type, hostname, ip_address in SOURCES:
            source = db.scalar(select(LogSource).where(LogSource.tenant_id == tenant.id, LogSource.name == name))
            if not source:
                source = LogSource(tenant_id=tenant.id, name=name, source_type=source_type, hostname=hostname, ip_address=ip_address, status="active", description=f"Demo {source_type} source")
                db.add(source)
                db.flush()
            source_rows.append(source)

        first_source = source_rows[0]
        if not db.scalar(select(ApiKey).where(ApiKey.key_hash == hash_api_key(DEMO_API_KEY))):
            db.add(ApiKey(tenant_id=tenant.id, source_id=first_source.id, name="Demo ingestion key", key_hash=hash_api_key(DEMO_API_KEY), key_prefix=api_key_prefix(DEMO_API_KEY), active=True))

        for rule_data in DETECTION_RULES:
            rule = db.scalar(select(DetectionRule).where(DetectionRule.tenant_id == tenant.id, DetectionRule.name == rule_data["name"]))
            if not rule:
                db.add(DetectionRule(tenant_id=tenant.id, created_by=created_users[0].id, updated_by=created_users[0].id, **rule_data))

        for ioc_data in IOCS:
            if not db.scalar(select(IOC).where(IOC.tenant_id == tenant.id, IOC.value == ioc_data["value"], IOC.type == ioc_data["type"])):
                db.add(IOC(tenant_id=tenant.id, **ioc_data))

        if not db.scalar(select(NotificationRule).where(NotificationRule.tenant_id == tenant.id, NotificationRule.name == "Demo critical console notification")):
            db.add(NotificationRule(tenant_id=tenant.id, name="Demo critical console notification", channel="demo", target="stdout", severity_min="high", enabled=True))

        if not db.scalar(select(SystemSetting).where(SystemSetting.key == "business_hours")):
            db.add(SystemSetting(key="business_hours", value={"timezone": "Europe/Vienna", "start": "08:00", "end": "18:00"}, description="Used by demo detections and reports."))

        db.commit()
        return {"tenant_id": tenant.id, "demo_api_key": DEMO_API_KEY}
    finally:
        db.close()


if __name__ == "__main__":
    result = seed()
    print(f"Seeded tenant {result['tenant_id']}")
    print(f"Demo ingestion API key: {result['demo_api_key']}")
