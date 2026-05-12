SUPER_ADMIN = "super_admin"
TENANT_ADMIN = "tenant_admin"
SECURITY_ANALYST = "security_analyst"
AUDITOR = "auditor"
VIEWER = "viewer"

ROLE_LABELS = {
    SUPER_ADMIN: "Super Admin",
    TENANT_ADMIN: "Tenant Admin",
    SECURITY_ANALYST: "Security Analyst",
    AUDITOR: "Auditor",
    VIEWER: "Viewer",
}

ROLE_PERMISSIONS: dict[str, set[str]] = {
    SUPER_ADMIN: {"*"},
    TENANT_ADMIN: {
        "dashboards:read",
        "tenants:read",
        "tenants:write",
        "users:read",
        "users:write",
        "logs:read",
        "logs:write",
        "alerts:read",
        "alerts:write",
        "incidents:read",
        "incidents:write",
        "rules:read",
        "rules:write",
        "sources:read",
        "sources:write",
        "reports:read",
        "reports:write",
        "audit:read",
        "iocs:read",
        "iocs:write",
        "settings:write",
    },
    SECURITY_ANALYST: {
        "dashboards:read",
        "logs:read",
        "alerts:read",
        "alerts:write",
        "incidents:read",
        "incidents:write",
        "rules:read",
        "rules:write",
        "sources:read",
        "reports:read",
        "iocs:read",
        "iocs:write",
    },
    AUDITOR: {"dashboards:read", "logs:read", "alerts:read", "incidents:read", "reports:read", "audit:read", "rules:read"},
    VIEWER: {"dashboards:read", "tenants:read"},
}


def has_permission(role: str, permission: str) -> bool:
    permissions = ROLE_PERMISSIONS.get(role, set())
    return "*" in permissions or permission in permissions
