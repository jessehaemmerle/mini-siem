"""Aufbereitung von Microsoft-365-Ereignissen.

Drei Arten von Datensätzen kommen vom Connector (``siem.m365``):

* ``audit``  – Einträge aus dem einheitlichen Überwachungsprotokoll
  (Office 365 Management Activity API: Entra ID, SharePoint/OneDrive, Teams …)
* ``signin`` – Anmeldungen aus Microsoft Graph (``auditLogs/signIns``, Entra ID P1)
* ``alert``  – Warnungen aus Microsoft Defender (Graph ``security/alerts_v2``)

Alle Events bekommen ``input = m365`` und ``host = microsoft365``. Anmeldungen
aus Graph verwenden dieselben ``event_id``-Werte wie das Überwachungsprotokoll
(``UserLoggedIn`` / ``UserLoginFailed``), damit die Erkennungsregeln für beide
Wege funktionieren.
"""

from __future__ import annotations

import ipaddress
import json

from . import parsers

HOST = "microsoft365"

WORKLOAD_APP = {
    "AzureActiveDirectory": "entra-id",
    "SharePoint": "sharepoint",
    "OneDrive": "onedrive",
    "MicrosoftTeams": "teams",
    "Exchange": "exchange",
    "SecurityComplianceCenter": "security-compliance",
    "ThreatIntelligence": "defender-office",
    "MicrosoftForms": "forms",
    "PowerBI": "powerbi",
    "PowerApps": "powerapps",
    "MicrosoftFlow": "power-automate",
    "Yammer": "viva-engage",
    "MicrosoftStream": "stream",
    "Planner": "planner",
    "Copilot": "copilot",
}

# Vorgänge, die sehr häufig und für die Sicherheit kaum aussagekräftig sind
NOISY_OPERATIONS = frozenset({
    "PageViewed", "PageViewedExtended", "PagePrefetched", "ClientViewSignaled", "SearchQueryPerformed",
    "ListViewed", "ListItemViewed", "FolderViewed",
    "Update StsRefreshTokenValidFrom Timestamp.", "TeamsSessionStarted", "MeetingParticipantDetail",
    "MeetingDetail", "ViewedSearchExported", "FileSyncDownloadedPartial", "FileSyncUploadedPartial",
    "FilePreviewed", "SignInEvent",
})

# Entra-Fehlercodes, die keine echte Fehlanmeldung sind, sondern eine
# Zwischenabfrage (MFA, „Angemeldet bleiben?", Gerätenachweis, Sitzung abgelaufen …)
INTERRUPT_CODES = frozenset({
    16000, 16001, 16002, 16003, 50058, 50072, 50074, 50076, 50079, 50089, 50097, 50125, 50127, 50129,
    50132, 50133, 50140, 50143, 50158, 50199, 52004, 54005, 65001, 70043, 70044, 81010, 81012, 90095,
    700082, 9002341,
})

ERROR_TEXT = {
    50034: "Benutzer existiert nicht",
    50053: "Konto gesperrt (Smart Lockout) oder IP-Adresse blockiert",
    50055: "Kennwort abgelaufen",
    50056: "Kein Kennwort hinterlegt",
    50057: "Konto deaktiviert",
    50064: "Anmeldedaten ungültig",
    50126: "Benutzername oder Kennwort falsch",
    50144: "Kennwort des Active Directory abgelaufen",
    53003: "Durch bedingten Zugriff blockiert",
    500121: "MFA fehlgeschlagen oder abgelehnt",
    530032: "Durch Sicherheitsrichtlinie blockiert",
    50074: "MFA erforderlich",
    50076: "MFA erforderlich",
    50140: "Abfrage „Angemeldet bleiben?“",
    50158: "Externe Sicherheitsabfrage",
}

# Operation -> (Bezeichnung, Kategorie, Aktion, Schweregrad)
OPERATIONS: dict[str, tuple[str, str, str | None, int]] = {
    # Entra ID: Konten, Rollen, Gruppen
    "Add user.": ("Benutzer angelegt", "account", "created", 5),
    "Delete user.": ("Benutzer gelöscht", "account", "deleted", 5),
    "Hard Delete user.": ("Benutzer endgültig gelöscht", "account", "deleted", 5),
    "Restore user.": ("Benutzer wiederhergestellt", "account", "restored", 5),
    "Update user.": ("Benutzer geändert", "account", "modified", 6),
    "Disable account.": ("Konto deaktiviert", "account", "disabled", 5),
    "Enable account.": ("Konto aktiviert", "account", "enabled", 5),
    "Reset user password.": ("Kennwort zurückgesetzt", "account", "password_reset", 5),
    "Change user password.": ("Kennwort geändert", "account", "password_change", 6),
    "Set force change user password.": ("Kennwortänderung erzwungen", "account", "password_reset", 6),
    "Change user license.": ("Lizenz geändert", "account", "modified", 7),
    "Update user credentials.": ("Anmeldedaten geändert", "account", "modified", 6),
    "Add member to role.": ("Mitglied zu Administratorrolle hinzugefügt", "role", "added", 4),
    "Add eligible member to role.": ("Berechtigt für Administratorrolle (PIM)", "role", "added", 4),
    "Remove member from role.": ("Mitglied aus Administratorrolle entfernt", "role", "removed", 5),
    "Remove eligible member from role.": ("PIM-Berechtigung für Rolle entfernt", "role", "removed", 5),
    "Add group.": ("Gruppe angelegt", "group", "created", 6),
    "Delete group.": ("Gruppe gelöscht", "group", "deleted", 5),
    "Update group.": ("Gruppe geändert", "group", "modified", 6),
    "Add member to group.": ("Mitglied zu Gruppe hinzugefügt", "group", "added", 6),
    "Remove member from group.": ("Mitglied aus Gruppe entfernt", "group", "removed", 6),
    "Add owner to group.": ("Besitzer zu Gruppe hinzugefügt", "group", "added", 6),
    # Entra ID: Anwendungen
    "Consent to application.": ("Zustimmung zu einer Anwendung erteilt", "application", "consent", 4),
    "Add delegated permission grant.": ("Delegierte Berechtigung erteilt", "application", "permission", 4),
    "Add app role assignment to service principal.": ("Anwendungsberechtigung erteilt", "application",
                                                      "permission", 4),
    "Add app role assignment grant to user.": ("Anwendung einem Benutzer zugewiesen", "application",
                                               "permission", 6),
    "Add application.": ("Anwendung registriert", "application", "created", 5),
    "Delete application.": ("Anwendung gelöscht", "application", "deleted", 5),
    "Add service principal.": ("Dienstprinzipal angelegt", "application", "created", 6),
    "Remove service principal.": ("Dienstprinzipal entfernt", "application", "deleted", 6),
    "Add service principal credentials.": ("Geheimnis/Zertifikat zu Dienstprinzipal hinzugefügt",
                                           "application", "credential", 4),
    "Update application – Certificates and secrets management ": ("Geheimnis/Zertifikat einer Anwendung "
                                                                   "geändert", "application", "credential", 4),
    "Add owner to application.": ("Besitzer zu Anwendung hinzugefügt", "application", "added", 5),
    "Add owner to service principal.": ("Besitzer zu Dienstprinzipal hinzugefügt", "application", "added", 5),
    # Entra ID: Mandant, Domänen, Richtlinien
    "Set Company Information.": ("Mandanteneinstellungen geändert", "tenant", "modified", 5),
    "Add domain to company.": ("Domäne hinzugefügt", "tenant", "added", 4),
    "Remove domain from company.": ("Domäne entfernt", "tenant", "removed", 4),
    "Verify domain.": ("Domäne bestätigt", "tenant", "modified", 5),
    "Set domain authentication.": ("Domänen-Authentifizierung geändert", "tenant", "federation", 3),
    "Set federation settings on domain.": ("Verbundeinstellungen der Domäne geändert", "tenant", "federation", 3),
    "Add partner to company.": ("Partner hinzugefügt", "tenant", "added", 4),
    "Add policy.": ("Richtlinie angelegt", "policy", "created", 5),
    "Update policy.": ("Richtlinie geändert", "policy", "modified", 5),
    "Delete policy.": ("Richtlinie gelöscht", "policy", "deleted", 4),
    "Add conditional access policy": ("Richtlinie für bedingten Zugriff angelegt", "policy", "created", 5),
    "Update conditional access policy": ("Richtlinie für bedingten Zugriff geändert", "policy", "modified", 5),
    "Delete conditional access policy": ("Richtlinie für bedingten Zugriff gelöscht", "policy", "deleted", 4),
    # Entra ID: MFA / Sicherheitsinformationen
    "Disable Strong Authentication.": ("MFA für Benutzer deaktiviert", "mfa", "disabled", 4),
    "User registered security info": ("Sicherheitsinformationen registriert (MFA-Methode)", "mfa", "added", 5),
    "User deleted security info": ("Sicherheitsinformationen gelöscht (MFA-Methode)", "mfa", "removed", 4),
    "User changed default security info": ("Standard-MFA-Methode geändert", "mfa", "modified", 5),
    "Admin registered security info": ("Admin hat MFA-Methode registriert", "mfa", "added", 4),
    "Admin deleted security info": ("Admin hat MFA-Methode gelöscht", "mfa", "removed", 4),
    "User registered all required security info": ("Alle Sicherheitsinformationen registriert", "mfa", "added", 6),
    # SharePoint / OneDrive: Dateien
    "FileAccessed": ("Datei geöffnet", "file", "accessed", 6),
    "FileAccessedExtended": ("Datei geöffnet", "file", "accessed", 7),
    "FileDownloaded": ("Datei heruntergeladen", "file", "downloaded", 6),
    "FileSyncDownloadedFull": ("Datei per Synchronisierung heruntergeladen", "file", "downloaded", 6),
    "FileUploaded": ("Datei hochgeladen", "file", "uploaded", 6),
    "FileSyncUploadedFull": ("Datei per Synchronisierung hochgeladen", "file", "uploaded", 6),
    "FileModified": ("Datei geändert", "file", "modified", 6),
    "FileModifiedExtended": ("Datei geändert", "file", "modified", 7),
    "FileCopied": ("Datei kopiert", "file", "copied", 6),
    "FileMoved": ("Datei verschoben", "file", "moved", 6),
    "FileRenamed": ("Datei umbenannt", "file", "renamed", 6),
    "FileRestored": ("Datei wiederhergestellt", "file", "restored", 6),
    "FileDeleted": ("Datei gelöscht", "file", "deleted", 6),
    "FileRecycled": ("Datei in den Papierkorb verschoben", "file", "deleted", 6),
    "FileDeletedFirstStageRecycleBin": ("Datei aus dem Papierkorb gelöscht", "file", "deleted", 5),
    "FileDeletedSecondStageRecycleBin": ("Datei endgültig gelöscht", "file", "deleted", 5),
    "FileVersionsAllDeleted": ("Alle Versionen einer Datei gelöscht", "file", "deleted", 5),
    "FolderCreated": ("Ordner angelegt", "file", "created", 7),
    "FolderDeleted": ("Ordner gelöscht", "file", "deleted", 6),
    "FolderRecycled": ("Ordner in den Papierkorb verschoben", "file", "deleted", 6),
    "FolderDeletedFirstStageRecycleBin": ("Ordner aus dem Papierkorb gelöscht", "file", "deleted", 5),
    "FolderDeletedSecondStageRecycleBin": ("Ordner endgültig gelöscht", "file", "deleted", 5),
    "FolderMoved": ("Ordner verschoben", "file", "moved", 6),
    "FolderRenamed": ("Ordner umbenannt", "file", "renamed", 6),
    "FileMalwareDetected": ("Schadsoftware in einer Datei erkannt", "malware", "detected", 3),
    "FileSensitivityLabelRemoved": ("Vertraulichkeitsbezeichnung entfernt", "file", "modified", 5),
    # SharePoint / OneDrive: Freigaben
    "AnonymousLinkCreated": ("Anonymer Freigabelink erstellt (jeder mit dem Link)", "sharing", "anonymous_link", 4),
    "AnonymousLinkUpdated": ("Anonymer Freigabelink geändert", "sharing", "anonymous_link", 5),
    "AnonymousLinkUsed": ("Anonymer Freigabelink verwendet", "sharing", "anonymous_access", 5),
    "AnonymousLinkRemoved": ("Anonymer Freigabelink entfernt", "sharing", "removed", 6),
    "CompanyLinkCreated": ("Freigabelink für die Organisation erstellt", "sharing", "link", 6),
    "CompanyLinkUsed": ("Freigabelink der Organisation verwendet", "sharing", "accessed", 7),
    "SecureLinkCreated": ("Freigabelink für bestimmte Personen erstellt", "sharing", "link", 6),
    "AddedToSecureLink": ("Person zu Freigabelink hinzugefügt", "sharing", "added", 6),
    "SecureLinkUsed": ("Freigabelink verwendet", "sharing", "accessed", 7),
    "SharingInvitationCreated": ("Freigabe-Einladung versendet", "sharing", "invite", 6),
    "SharingInvitationAccepted": ("Freigabe-Einladung angenommen", "sharing", "accepted", 6),
    "SharingSet": ("Freigabe/Berechtigung erteilt", "sharing", "granted", 6),
    "SharingRevoked": ("Freigabe entzogen", "sharing", "removed", 6),
    "SharingInheritanceBroken": ("Berechtigungsvererbung unterbrochen", "sharing", "modified", 6),
    "SharingPolicyChanged": ("Freigaberichtlinie geändert", "policy", "modified", 4),
    "SiteCollectionAdminAdded": ("Websitesammlungsadministrator hinzugefügt", "role", "added", 4),
    "SiteCollectionAdminRemoved": ("Websitesammlungsadministrator entfernt", "role", "removed", 5),
    "SiteDeleted": ("Website gelöscht", "site", "deleted", 4),
    "SiteCollectionCreated": ("Websitesammlung angelegt", "site", "created", 6),
    "AddedToGroup": ("Benutzer zu SharePoint-Gruppe hinzugefügt", "group", "added", 6),
    # Teams
    "TeamCreated": ("Team erstellt", "team", "created", 6),
    "TeamDeleted": ("Team gelöscht", "team", "deleted", 4),
    "TeamSettingChanged": ("Team-Einstellung geändert", "team", "modified", 6),
    "MemberAdded": ("Mitglied zu Team hinzugefügt", "team", "added", 6),
    "MemberRemoved": ("Mitglied aus Team entfernt", "team", "removed", 6),
    "MemberRoleChanged": ("Rolle im Team geändert", "team", "modified", 6),
    "ChannelAdded": ("Kanal hinzugefügt", "team", "created", 7),
    "ChannelDeleted": ("Kanal gelöscht", "team", "deleted", 6),
    "AppInstalled": ("App in Teams installiert", "application", "installed", 5),
    "BotAddedToTeam": ("Bot zu Team hinzugefügt", "application", "installed", 5),
    "ConnectorAdded": ("Connector/Webhook zu Kanal hinzugefügt", "application", "installed", 5),
    "TeamsAdminAction": ("Teams-Verwaltungsaktion", "tenant", "modified", 5),
    # Sicherheit & Compliance (Warnungen aus Warnungsrichtlinien)
    "AlertTriggered": ("Warnung der Sicherheitsrichtlinie ausgelöst", "alert", "alert", 4),
    "AlertEntityGenerated": ("Warnung der Sicherheitsrichtlinie (Detail)", "alert", "alert", 6),
}

CATEGORY_BY_WORKLOAD = {
    "AzureActiveDirectory": "account",
    "SharePoint": "file",
    "OneDrive": "file",
    "MicrosoftTeams": "team",
}

DEFENDER_SEVERITY = {"high": 3, "medium": 4, "low": 5, "informational": 6, "unknown": 5}
DEFENDER_SEVERITY_LABEL = {"high": "hoch", "medium": "mittel", "low": "niedrig", "informational": "Information"}
DEFENDER_SOURCES = {
    "microsoftDefenderForEndpoint": "Defender for Endpoint",
    "microsoftDefenderForIdentity": "Defender for Identity",
    "microsoftDefenderForCloudApps": "Defender for Cloud Apps",
    "microsoftDefenderForOffice365": "Defender for Office 365",
    "microsoft365Defender": "Microsoft Defender XDR",
    "azureAdIdentityProtection": "Entra ID Protection",
    "microsoftAppGovernance": "App Governance",
    "dataLossPrevention": "Datenverlustschutz",
    "microsoftDefenderForCloud": "Defender for Cloud",
    "microsoftSentinel": "Microsoft Sentinel",
    "microsoftInsiderRiskManagement": "Insider-Risikomanagement",
}

RISK_SEVERITY = {"high": 3, "medium": 4, "low": 5}


# --------------------------------------------------------------------------- Hilfsfunktionen


def clean_ip(value) -> str | None:
    """IP-Adresse ohne Port und ohne eckige Klammern (``1.2.3.4:5678``, ``[::1]:443``)."""
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    if s.startswith("["):
        s = s[1:].split("]", 1)[0]
    elif s.count(":") == 1:
        s = s.split(":", 1)[0]
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        return str(ip.ipv4_mapped)
    return str(ip)


def utc_time(value) -> float | None:
    """Zeitangaben von Microsoft haben teils keine Zeitzone – gemeint ist immer UTC."""
    if not value:
        return None
    s = str(value).strip()
    if len(s) >= 19 and s[10] in "T " and not (s.endswith("Z") or "+" in s[19:] or "-" in s[19:]):
        s += "Z"
    return parsers.parse_any_time(s)


def _int(value) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _name_values(items) -> dict:
    """``[{"Name": "a", "Value": "b"}, …]`` → ``{"a": "b"}``."""
    out = {}
    if isinstance(items, list):
        for it in items:
            if isinstance(it, dict) and it.get("Name"):
                out[str(it["Name"])] = it.get("Value")
    return out


def _modified(record: dict) -> dict:
    out = {}
    for it in record.get("ModifiedProperties") or []:
        if isinstance(it, dict) and it.get("Name"):
            out[str(it["Name"])] = it.get("NewValue")
    return out


def _unquote(v) -> str | None:
    """ModifiedProperties enthalten Werte oft als JSON-Text (``"[\\"Global Administrator\\"]"``)."""
    if v in (None, ""):
        return None
    s = str(v).strip()
    try:
        parsed = json.loads(s)
    except ValueError:
        return s.strip('"') or None
    if isinstance(parsed, list):
        parsed = ", ".join(str(x) for x in parsed if x not in (None, ""))
    return str(parsed).strip() or None


def _target_upn(record: dict) -> str | None:
    for t in record.get("Target") or []:
        if isinstance(t, dict) and t.get("Type") == 5 and t.get("ID"):
            return str(t["ID"])
    for t in record.get("Target") or []:
        if isinstance(t, dict) and "@" in str(t.get("ID") or ""):
            return str(t["ID"])
    return None


def error_text(code: int | None, fallback: str | None = None) -> str:
    if code is None:
        return fallback or "unbekannter Grund"
    text = ERROR_TEXT.get(code) or fallback or "Fehler"
    return f"{text} – Code {code}"


def login_outcome(code: int | None) -> tuple[str, str, int]:
    """(event_id, action, Schweregrad) für einen Entra-Fehlercode."""
    if not code:
        return "UserLoggedIn", "success", 6
    if code in INTERRUPT_CODES:
        return "UserLoginFailed", "interrupted", 6
    return "UserLoginFailed", "failure", 5


def _new(received: float | None) -> dict:
    ev = parsers.new_event("m365", None, received)
    ev["host"] = HOST
    return ev


def _is_guest(upn: str | None, role=None) -> bool:
    return bool(upn and "#ext#" in upn.lower()) or str(role) == "2"


# --------------------------------------------------------------------------- Überwachungsprotokoll


def _audit(ev: dict, r: dict) -> None:
    op = str(r.get("Operation") or "").strip()
    workload = str(r.get("Workload") or "")
    ev["ts"] = utc_time(r.get("CreationTime"))
    ev["app"] = WORKLOAD_APP.get(workload) or (workload.lower() or "microsoft365")
    ev["event_id"] = op or None
    user = r.get("UserId") or r.get("UserKey")
    ev["user"] = str(user) if user else None
    ev["src_ip"] = clean_ip(r.get("ClientIP")) or clean_ip(r.get("ActorIpAddress"))
    data: dict = {"src": "audit", "workload": workload, "record_type": r.get("RecordType"),
                  "result": r.get("ResultStatus"), "id": r.get("Id")}
    label, category, action, sev = OPERATIONS.get(op, (None, None, None, 6))
    detail = ""

    if op in ("UserLoggedIn", "UserLoginFailed"):
        code = _int(r.get("ErrorCode"))
        if op == "UserLoggedIn" and code is None:
            code = 0
        if op == "UserLoginFailed" and not code:
            code = _int(_name_values(r.get("ExtendedProperties")).get("ResultStatusDetail")) or None
        event_id, action, sev = login_outcome(code)
        if op == "UserLoginFailed" and not code:
            event_id, action, sev = "UserLoginFailed", "failure", 5
        ev["event_id"] = event_id
        category = "authentication"
        ext = _name_values(r.get("ExtendedProperties"))
        dev = _name_values(r.get("DeviceProperties"))
        if code is not None:
            data["error_code"] = code
        if r.get("LogonError"):
            data["logon_error"] = r["LogonError"]
        for k_src, k_dst in (("UserAgent", "user_agent"), ("RequestType", "request_type")):
            if ext.get(k_src):
                data[k_dst] = ext[k_src]
        for k_src, k_dst in (("OS", "device_os"), ("BrowserType", "browser"), ("DisplayName", "device"),
                             ("IsCompliant", "device_compliant")):
            if dev.get(k_src) not in (None, ""):
                data[k_dst] = dev[k_src]
        if r.get("ApplicationId"):
            data["app_id"] = r["ApplicationId"]
        if action == "success":
            label = "Anmeldung erfolgreich"
        elif action == "interrupted":
            label = "Anmeldung unterbrochen"
            detail = f"({error_text(code, r.get('LogonError'))})"
        else:
            label = "Anmeldung fehlgeschlagen"
            detail = f"({error_text(code, r.get('LogonError'))})"

    elif workload == "AzureActiveDirectory":
        mod = _modified(r)
        target = _target_upn(r) or (r.get("ObjectId") if "@" in str(r.get("ObjectId") or "") else None)
        if target:
            data["target_user"] = target
        if category == "role":
            role = _unquote(mod.get("Role.DisplayName")) or _unquote(mod.get("Role.WellKnownObjectName"))
            if role:
                data["role"] = role
                detail = f"→ {target or '?'} ({role})"
        elif op == "Update user." and any("StrongAuthentication" in k for k in mod) or (
                op == "Update user." and "StrongAuthentication" in str(mod.get("Included Updated Properties") or "")):
            label, category, action, sev = "MFA-Einstellungen eines Benutzers geändert", "mfa", "modified", 4
            data["changed"] = sorted(k for k in mod if k)
        elif category == "application":
            app_name = _unquote(mod.get("ServicePrincipal.DisplayName")) or _unquote(mod.get("DisplayName"))
            if not app_name:
                for t in r.get("Target") or []:
                    if isinstance(t, dict) and t.get("Type") == 1 and t.get("ID"):
                        app_name = str(t["ID"])
                        break
            if app_name:
                data["application"] = app_name
                detail = f"– {app_name}"
            if op == "Consent to application.":
                admin_consent = _unquote(mod.get("ConsentContext.IsAdminConsent"))
                if admin_consent:
                    data["admin_consent"] = admin_consent.lower() == "true"
                perms = _unquote(mod.get("ConsentAction.Permissions"))
                if perms:
                    data["permissions"] = perms[:1000]
        elif target:
            detail = f"→ {target}"
        if label is None and ("security info" in op.lower() or "strongauthentication" in op.lower().replace(" ", "")):
            label, category, action, sev = op.rstrip("."), "mfa", "modified", 5
        if ev["user"] and "@" not in ev["user"]:
            # Aktionen von Diensten: Anzeigename aus „Actor“
            for a in r.get("Actor") or []:
                if isinstance(a, dict) and "@" in str(a.get("ID") or ""):
                    ev["user"] = str(a["ID"])
                    break

    elif workload in ("SharePoint", "OneDrive"):
        path = ""
        if r.get("SourceRelativeUrl") or r.get("SourceFileName"):
            path = "/".join(p for p in (str(r.get("SourceRelativeUrl") or "").strip("/"),
                                        str(r.get("SourceFileName") or "")) if p)
        path = path or str(r.get("ObjectId") or "")
        for k_src, k_dst in (("SiteUrl", "site"), ("SourceFileName", "file"), ("SourceFileExtension", "extension"),
                             ("ObjectId", "object"), ("UserAgent", "user_agent"), ("ItemType", "item_type"),
                             ("TargetUserOrGroupName", "target"), ("TargetUserOrGroupType", "target_type"),
                             ("DestinationRelativeUrl", "destination"), ("SensitivityLabelId", "label_id")):
            if r.get(k_src) not in (None, ""):
                data[k_dst] = r[k_src]
        target_type = str(r.get("TargetUserOrGroupType") or "")
        target = r.get("TargetUserOrGroupName")
        if target_type.lower() == "guest" or _is_guest(str(target or "")):
            data["external"] = True
            if category == "sharing" and action in ("invite", "granted", "added", "link"):
                label = f"{label} – an externe Person"
                sev = min(sev, 5)
        if op == "FileMalwareDetected" and r.get("VirusInfo"):
            data["malware"] = r["VirusInfo"]
        if path:
            detail = f"– {path}"
        if target and category == "sharing":
            detail += f" → {target}"

    elif workload == "MicrosoftTeams":
        team = r.get("TeamName")
        if team:
            data["team"] = team
        if r.get("ChannelName"):
            data["channel"] = r["ChannelName"]
        members = [m for m in (r.get("Members") or []) if isinstance(m, dict)]
        guests = [str(m.get("UPN") or m.get("DisplayName") or "") for m in members
                  if _is_guest(str(m.get("UPN") or ""), m.get("Role"))]
        if members:
            data["members"] = [str(m.get("UPN") or m.get("DisplayName") or "") for m in members][:50]
        if op == "MemberAdded" and guests:
            label, category, action, sev = "Gast zu Team hinzugefügt", "guest", "added", 5
            data["guests"] = guests[:50]
        for k_src, k_dst in (("AddOnName", "addon"), ("AddonName", "addon"), ("Name", "setting"),
                             ("NewValue", "new_value"), ("OldValue", "old_value")):
            if r.get(k_src) not in (None, "") and k_dst not in data:
                data[k_dst] = r[k_src]
        who = ", ".join(x for x in (data.get("members") or [])[:5] if x)
        detail = " ".join(x for x in (f"– Team {team}" if team else "", f"→ {who}" if who else "") if x)
        if op in ("AppInstalled", "BotAddedToTeam", "ConnectorAdded") and data.get("addon"):
            detail = f"– {data['addon']}" + (f" (Team {team})" if team else "")

    elif workload == "SecurityComplianceCenter" and op.startswith("Alert"):
        name = r.get("Name") or r.get("AlertType") or "Warnung"
        sev = {"high": 3, "medium": 4, "low": 5, "informational": 6}.get(str(r.get("Severity") or "").lower(), sev)
        for k_src, k_dst in (("Name", "alert_name"), ("Severity", "alert_severity"), ("Category", "alert_category"),
                             ("Status", "alert_status"), ("AlertId", "alert_id"), ("PolicyId", "policy_id")):
            if r.get(k_src) not in (None, ""):
                data[k_dst] = r[k_src]
        detail = f"– {name}"

    if label is None:
        label = op or "Microsoft-365-Ereignis"
        category = category or CATEGORY_BY_WORKLOAD.get(workload)
        if str(r.get("ResultStatus") or "").lower() in ("failed", "false"):
            action, sev = "failure", min(sev, 5)

    ev["category"] = category
    ev["action"] = action
    ev["severity"] = sev
    who = ev["user"] or "?"
    parts = [f"{label}: {who}"]
    if detail:
        parts.append(detail)
    if ev["src_ip"] and category == "authentication":
        parts.append(f"von {ev['src_ip']}")
    ev["message"] = " ".join(parts)
    ev["data"] = {k: v for k, v in data.items() if v not in (None, "", [], {})}


# --------------------------------------------------------------------------- Graph: Anmeldungen


def _signin(ev: dict, r: dict) -> None:
    status = r.get("status") or {}
    code = _int(status.get("errorCode"))
    event_id, action, sev = login_outcome(code)
    ev["ts"] = utc_time(r.get("createdDateTime"))
    ev["app"] = "entra-id"
    ev["category"] = "authentication"
    ev["event_id"] = event_id
    ev["action"] = action
    ev["user"] = r.get("userPrincipalName") or r.get("userDisplayName") or None
    ev["src_ip"] = clean_ip(r.get("ipAddress"))
    loc = r.get("location") or {}
    dev = r.get("deviceDetail") or {}
    risk = str(r.get("riskLevelDuringSignIn") or "").lower()
    risk_agg = str(r.get("riskLevelAggregated") or "").lower()
    data = {
        "src": "graph", "id": r.get("id"), "error_code": code,
        "failure_reason": status.get("failureReason") if code else None,
        "application": r.get("appDisplayName"), "app_id": r.get("appId"),
        "resource": r.get("resourceDisplayName"), "client_app": r.get("clientAppUsed"),
        "interactive": r.get("isInteractive"), "ca_status": r.get("conditionalAccessStatus"),
        "country": loc.get("countryOrRegion"), "city": loc.get("city"), "state": loc.get("state"),
        "device_os": dev.get("operatingSystem"), "browser": dev.get("browser"), "device": dev.get("displayName"),
        "device_compliant": dev.get("isCompliant"), "device_managed": dev.get("isManaged"),
        "risk_level": risk if risk and risk != "none" else None,
        "risk_aggregated": risk_agg if risk_agg and risk_agg != "none" else None,
        "risk_state": r.get("riskState") if r.get("riskState") not in (None, "none") else None,
        "risk_events": r.get("riskEventTypes_v2") or None,
        "user_agent": r.get("userAgent"),
    }
    for level in (risk, risk_agg):
        if level in RISK_SEVERITY:
            sev = min(sev, RISK_SEVERITY[level])
    ev["severity"] = sev
    label = {"success": "Anmeldung erfolgreich", "interrupted": "Anmeldung unterbrochen"}.get(
        action, "Anmeldung fehlgeschlagen")
    parts = [f"{label}: {ev['user'] or '?'}"]
    if r.get("appDisplayName"):
        parts.append(f"bei {r['appDisplayName']}")
    if ev["src_ip"]:
        place = ", ".join(x for x in (loc.get("city"), loc.get("countryOrRegion")) if x)
        parts.append(f"von {ev['src_ip']}" + (f" ({place})" if place else ""))
    if code:
        parts.append(f"({error_text(code, status.get('failureReason'))})")
    if data["risk_level"] in RISK_SEVERITY:
        parts.append(f"– Risiko {data['risk_level']}")
    ev["message"] = " ".join(parts)
    ev["data"] = {k: v for k, v in data.items() if v not in (None, "", [], {})}


# --------------------------------------------------------------------------- Graph: Defender-Warnungen


def _evidence(r: dict) -> tuple[str | None, str | None, str | None]:
    """(Benutzer, IP-Adresse, Gerät) aus den Beweisen einer Warnung."""
    user = ip = device = None
    for e in r.get("evidence") or []:
        if not isinstance(e, dict):
            continue
        kind = str(e.get("@odata.type") or "")
        acct = e.get("userAccount") if isinstance(e.get("userAccount"), dict) else None
        if not user and acct:
            user = acct.get("userPrincipalName") or acct.get("accountName")
        if not ip and kind.endswith("ipEvidence"):
            ip = clean_ip(e.get("ipAddress"))
        if not device and kind.endswith("deviceEvidence"):
            device = e.get("deviceDnsName") or e.get("hostName")
            if not user:
                for u in e.get("loggedOnUsers") or []:
                    if isinstance(u, dict) and u.get("accountName"):
                        user = u["accountName"]
                        break
    return user, ip, device


def _alert(ev: dict, r: dict) -> None:
    sev_name = str(r.get("severity") or "unknown").lower()
    ev["ts"] = utc_time(r.get("createdDateTime"))
    ev["app"] = "defender"
    ev["category"] = "alert"
    ev["action"] = "alert"
    ev["event_id"] = "DefenderAlert"
    ev["severity"] = DEFENDER_SEVERITY.get(sev_name, 5)
    user, ip, device = _evidence(r)
    ev["user"] = user
    ev["src_ip"] = ip
    source = DEFENDER_SOURCES.get(str(r.get("serviceSource") or ""), r.get("serviceSource") or "Defender")
    title = r.get("title") or "Warnung"
    ev["message"] = (f"Defender-Warnung ({DEFENDER_SEVERITY_LABEL.get(sev_name, sev_name)}): {title} – {source}"
                     + (f" – Gerät {device}" if device else "") + (f" – {user}" if user else ""))
    data = {
        "src": "defender", "id": r.get("id"), "title": title, "severity": sev_name, "status": r.get("status"),
        "category": r.get("category"), "service": r.get("serviceSource"), "detection": r.get("detectionSource"),
        "incident_id": r.get("incidentId"), "url": r.get("alertWebUrl"), "incident_url": r.get("incidentWebUrl"),
        "mitre": r.get("mitreTechniques") or None, "threat": r.get("threatDisplayName"),
        "description": (r.get("description") or "")[:2000] or None,
        "recommended": (r.get("recommendedActions") or "")[:2000] or None,
        "device": device, "actor": r.get("actorDisplayName"),
    }
    ev["data"] = {k: v for k, v in data.items() if v not in (None, "", [], {})}


def parse_m365(kind: str, record: dict, received: float | None = None) -> dict:
    ev = _new(received)
    if kind == "audit":
        _audit(ev, record)
    elif kind == "signin":
        _signin(ev, record)
    elif kind == "alert":
        _alert(ev, record)
    else:
        ev["message"] = json.dumps(record, ensure_ascii=False, default=str)[:4000]
        ev["data"] = {"src": str(kind)}
    ev["host"] = HOST
    return parsers.finalize(ev)
