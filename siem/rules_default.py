"""Mitgelieferte Erkennungsregeln.

Sie werden beim ersten Start angelegt und können in der Oberfläche angepasst
oder deaktiviert werden. Neue Regeln in späteren Versionen werden anhand von
``key`` automatisch ergänzt – bereits vorhandene werden nie überschrieben.
"""

DEFAULT_RULES: list[dict] = [
    # ---------------------------------------------------------------- Linux / SSH
    {
        "key": "ssh-bruteforce",
        "name": "SSH: Brute-Force-Angriff",
        "description": "Viele fehlgeschlagene SSH-Anmeldungen von derselben IP-Adresse in kurzer Zeit.",
        "query": 'app:sshd* category:authentication action:failure',
        "severity": "high", "threshold": 10, "window": 300, "group_by": "src_ip",
    },
    {
        "key": "ssh-user-enum",
        "name": "SSH: Ausprobieren vieler Benutzernamen",
        "description": "Eine IP-Adresse versucht sich mit vielen unterschiedlichen Benutzernamen anzumelden.",
        "query": 'app:sshd* action:failure user:*',
        "severity": "high", "threshold": 5, "window": 600, "group_by": "src_ip",
        "distinct_field": "user",
    },
    {
        "key": "ssh-root-login",
        "name": "SSH: Anmeldung als root",
        "description": "Erfolgreiche SSH-Anmeldung direkt als root. Besser: persönliche Konten + sudo.",
        "query": 'app:sshd* action:success user:root',
        "severity": "medium", "threshold": 1, "window": 3600, "group_by": "host",
    },
    {
        "key": "sudo-failure",
        "name": "sudo: Falsches Passwort",
        "description": "Wiederholt falsches Passwort bei sudo – Tippfehler oder Versuch der Rechteausweitung.",
        "query": 'app:sudo ("incorrect password" OR "authentication failure")',
        "severity": "medium", "threshold": 3, "window": 600, "group_by": "user",
    },
    {
        "key": "linux-user-created",
        "name": "Linux: Neues Benutzerkonto",
        "description": "Auf einem Linux-System wurde ein Benutzer angelegt (useradd/adduser).",
        "query": '(app:useradd OR app:adduser) category:account action:created',
        "severity": "medium", "threshold": 1, "window": 3600, "group_by": "host",
    },
    {
        "key": "linux-oom",
        "name": "Linux: Speicher erschöpft (OOM-Killer)",
        "description": "Der Kernel hat wegen Speichermangels einen Prozess beendet.",
        "query": '"Out of memory" OR oom-kill',
        "severity": "low", "threshold": 1, "window": 3600, "group_by": "host",
    },
    # ---------------------------------------------------------------- Windows
    {
        "key": "win-logon-failures",
        "name": "Windows: Viele fehlgeschlagene Anmeldungen",
        "description": "Ereignis 4625 gehäuft für dasselbe Konto – Brute-Force oder falsch gespeichertes Passwort.",
        "query": 'event_id:4625',
        "severity": "high", "threshold": 10, "window": 300, "group_by": "user",
    },
    {
        "key": "win-password-spray",
        "name": "Windows: Password-Spraying",
        "description": "Fehlgeschlagene Anmeldungen für viele verschiedene Konten von derselben Quelle.",
        "query": 'event_id:4625 src_ip:*',
        "severity": "high", "threshold": 8, "window": 900, "group_by": "src_ip",
        "distinct_field": "user",
    },
    {
        "key": "win-account-lockout",
        "name": "Windows: Konto gesperrt",
        "description": "Ein Benutzerkonto wurde nach zu vielen Fehlversuchen gesperrt (4740).",
        "query": 'event_id:4740',
        "severity": "medium", "threshold": 1, "window": 3600, "group_by": "user",
    },
    {
        "key": "win-user-created",
        "name": "Windows: Benutzerkonto erstellt",
        "description": "Ein neues Benutzerkonto wurde angelegt (4720).",
        "query": 'event_id:4720',
        "severity": "medium", "threshold": 1, "window": 3600, "group_by": "host",
    },
    {
        "key": "win-group-add",
        "name": "Windows: Mitglied zu Sicherheitsgruppe hinzugefügt",
        "description": "Ein Konto wurde einer Sicherheitsgruppe hinzugefügt (4728/4732/4756). "
                       "Besonders kritisch bei Administratoren und Domänen-Admins.",
        "query": 'event_id:4728 OR event_id:4732 OR event_id:4756',
        "severity": "high", "threshold": 1, "window": 3600, "group_by": "user",
    },
    {
        "key": "win-log-cleared",
        "name": "Windows: Ereignisprotokoll gelöscht",
        "description": "Das Sicherheits- oder Systemprotokoll wurde geleert (1102/104) – "
                       "typisch für Angreifer, die Spuren verwischen.",
        "query": 'event_id:1102 OR (event_id:104 app:*Eventlog*)',
        "severity": "critical", "threshold": 1, "window": 3600, "group_by": "host",
    },
    {
        "key": "win-service-installed",
        "name": "Windows: Neuer Dienst installiert",
        "description": "Auf einem System wurde ein Dienst installiert (7045/4697). Kann auf Schadsoftware hinweisen.",
        "query": 'event_id:7045 OR event_id:4697',
        "severity": "medium", "threshold": 1, "window": 3600, "group_by": "host",
    },
    # ---------------------------------------------------------------- Netzwerk
    {
        "key": "net-portscan",
        "name": "Netzwerk: Portscan",
        "description": "Eine IP-Adresse spricht in kurzer Zeit sehr viele verschiedene Ports an "
                       "(Firewall-Logs mit Zielport).",
        "query": 'dst_port:* src_ip:*',
        "severity": "medium", "threshold": 25, "window": 120, "group_by": "src_ip",
        "distinct_field": "dst_port",
    },
    {
        "key": "web-attack-patterns",
        "name": "Web: Typische Angriffsmuster",
        "description": "Anfragen mit Mustern von SQL-Injection oder Pfad-Traversal in Webserver-Logs.",
        "query": 'message:~"union(\\s|%20|\\+)+(all(\\s|%20|\\+)+)?select" OR "../../" OR "/etc/passwd" '
                 'OR message:~"<script" OR message:~"[$][{]jndi:"',
        "severity": "medium", "threshold": 1, "window": 900, "group_by": "src_ip",
    },
    # ---------------------------------------------------------------- Docker (über den Agenten)
    {
        "key": "docker-privileged",
        "name": "Docker: Privilegierter Container gestartet",
        "description": "Ein Container läuft privilegiert, mit Zugriff auf den Docker-Socket oder im "
                       "Prozessraum des Hosts – damit lässt sich der ganze Server übernehmen.",
        "query": 'app:docker event_id:docker.start (data.privileged:true OR data.docker_socket:true '
                 'OR data.pid_host:true)',
        "severity": "high", "threshold": 1, "window": 3600, "group_by": "data.container",
    },
    {
        "key": "docker-exec",
        "name": "Docker: Befehl in laufendem Container",
        "description": "Jemand hat mit „docker exec“ einen Befehl im Container ausgeführt. Regelmäßige "
                       "Aufgaben (z. B. Backups) lassen sich ausnehmen: -data.exec_cmd:\"pg_dump*\"",
        "query": 'app:docker event_id:docker.exec_start',
        "severity": "low", "threshold": 1, "window": 900, "group_by": "data.container",
    },
    {
        "key": "docker-restart-loop",
        "name": "Docker: Container startet ständig neu",
        "description": "Ein Container beendet sich in kurzer Zeit immer wieder (Absturz- bzw. Neustartschleife).",
        "query": 'app:docker event_id:docker.die',
        "severity": "medium", "threshold": 5, "window": 600, "group_by": "data.container",
    },
    {
        "key": "docker-oom",
        "name": "Docker: Container wegen Speichermangel beendet",
        "description": "Der Container hat sein Speicherlimit überschritten und wurde beendet.",
        "query": 'app:docker event_id:docker.oom',
        "severity": "low", "threshold": 1, "window": 3600, "group_by": "data.container",
    },
    {
        "key": "docker-unhealthy",
        "name": "Docker: Container ungesund",
        "description": "Der Healthcheck eines Containers schlägt fehl.",
        "query": 'app:docker event_id:docker.health_status data.health:unhealthy',
        "severity": "low", "threshold": 1, "window": 3600, "group_by": "data.container",
    },
    # ---------------------------------------------------------------- Microsoft 365: Anmeldungen
    {
        "key": "m365-login-failures",
        "name": "Microsoft 365: Viele fehlgeschlagene Anmeldungen",
        "description": "Viele Fehlanmeldungen für dasselbe Konto – Brute-Force-Angriff oder ein Gerät mit "
                       "altem Kennwort. MFA-Abfragen und „Angemeldet bleiben?“ zählen nicht.",
        "query": 'app:entra-id event_id:UserLoginFailed action:failure',
        "severity": "medium", "threshold": 10, "window": 600, "group_by": "user",
    },
    {
        "key": "m365-password-spray",
        "name": "Microsoft 365: Password-Spray",
        "description": "Eine IP-Adresse probiert Kennwörter für viele verschiedene Konten aus.",
        "query": 'app:entra-id event_id:UserLoginFailed action:failure',
        "severity": "high", "threshold": 5, "window": 1800, "group_by": "src_ip", "distinct_field": "user",
    },
    {
        "key": "m365-mfa-fatigue",
        "name": "Microsoft 365: Viele abgelehnte MFA-Anfragen",
        "description": "MFA-Anfragen werden wiederholt abgelehnt oder laufen ins Leere – möglicher "
                       "MFA-Fatigue-Angriff mit einem bereits bekannten Kennwort.",
        "query": 'app:entra-id data.error_code:500121',
        "severity": "high", "threshold": 3, "window": 900, "group_by": "user",
    },
    {
        "key": "m365-risky-signin",
        "name": "Microsoft 365: Riskante Anmeldung",
        "description": "Entra ID stuft eine Anmeldung als riskant ein (benötigt Anmeldedetails über Graph; "
                       "Risikostufen gibt es mit Entra ID P2).",
        "query": 'app:entra-id category:authentication (data.risk_level:high OR data.risk_level:medium '
                 'OR data.risk_aggregated:high)',
        "severity": "high", "threshold": 1, "window": 3600, "group_by": "user",
    },
    {
        "key": "m365-foreign-login",
        "name": "Microsoft 365: Anmeldung aus ungewohntem Land",
        "description": "Erfolgreiche Anmeldung aus einem Land außerhalb der Liste. Bitte die Länder der Firma "
                       "eintragen (ISO-Code) und die Regel dann aktivieren. Benötigt Anmeldedetails über Graph.",
        "query": 'app:entra-id event_id:UserLoggedIn data.country:* -data.country:AT -data.country:DE '
                 '-data.country:CH',
        "severity": "medium", "threshold": 1, "window": 86400, "group_by": "user", "enabled": False,
    },
    # ---------------------------------------------------------------- Microsoft 365: Konten & Apps
    {
        "key": "m365-admin-role",
        "name": "Microsoft 365: Administratorrolle vergeben",
        "description": "Ein Konto wurde einer Administratorrolle in Entra ID zugewiesen (auch PIM-berechtigt) "
                       "oder als Websitesammlungsadministrator eingetragen.",
        "query": 'category:role action:added input:m365',
        "severity": "high", "threshold": 1, "window": 3600, "group_by": "user",
    },
    {
        "key": "m365-mfa-change",
        "name": "Microsoft 365: MFA entfernt oder geändert",
        "description": "Eine MFA-Methode wurde gelöscht, MFA deaktiviert oder von einem Admin geändert – "
                       "häufiger Schritt, um ein übernommenes Konto zu sichern.",
        "query": 'app:entra-id category:mfa (action:removed OR action:disabled OR action:modified)',
        "severity": "medium", "threshold": 1, "window": 3600, "group_by": "user",
    },
    {
        "key": "m365-app-consent",
        "name": "Microsoft 365: Anwendung erhält Berechtigungen",
        "description": "Zustimmung zu einer Anwendung, neue Anwendungsberechtigungen oder ein neues Geheimnis "
                       "für eine Anwendung – typisch für Consent-Phishing oder dauerhaften Zugang.",
        "query": 'app:entra-id (event_id:"Consent to application." OR action:permission OR action:credential)',
        "severity": "medium", "threshold": 1, "window": 3600, "group_by": "user",
    },
    {
        "key": "m365-federation",
        "name": "Microsoft 365: Domänen-Verbund geändert",
        "description": "Authentifizierung oder Verbundeinstellungen einer Domäne wurden geändert. Angreifer "
                       "nutzen das, um sich als beliebiger Benutzer anzumelden.",
        "query": 'app:entra-id action:federation',
        "severity": "critical", "threshold": 1, "window": 3600, "group_by": "user",
    },
    # ---------------------------------------------------------------- Microsoft 365: Dateien & Teams
    {
        "key": "m365-anonymous-link",
        "name": "Microsoft 365: Anonymer Freigabelink",
        "description": "Für eine Datei oder einen Ordner wurde ein Link erstellt, den jeder ohne Anmeldung "
                       "öffnen kann.",
        "query": 'category:sharing action:anonymous_link',
        "severity": "low", "threshold": 1, "window": 3600, "group_by": "user",
    },
    {
        "key": "m365-mass-download",
        "name": "Microsoft 365: Massen-Download",
        "description": "Ein Konto lädt in kurzer Zeit sehr viele Dateien aus SharePoint/OneDrive herunter – "
                       "möglicher Datenabfluss. (Auch beim Einrichten der OneDrive-Synchronisierung.)",
        "query": '(app:sharepoint OR app:onedrive) action:downloaded',
        "severity": "medium", "threshold": 100, "window": 600, "group_by": "user",
    },
    {
        "key": "m365-mass-delete",
        "name": "Microsoft 365: Massenlöschung",
        "description": "Ein Konto löscht in kurzer Zeit sehr viele Dateien – Sabotage oder Ransomware "
                       "über die Synchronisierung.",
        "query": '(app:sharepoint OR app:onedrive) category:file action:deleted',
        "severity": "high", "threshold": 100, "window": 600, "group_by": "user",
    },
    {
        "key": "m365-malware-file",
        "name": "Microsoft 365: Schadsoftware in Datei",
        "description": "SharePoint, OneDrive oder Teams hat in einer hochgeladenen Datei Schadsoftware erkannt.",
        "query": 'event_id:FileMalwareDetected',
        "severity": "high", "threshold": 1, "window": 3600, "group_by": "user",
    },
    {
        "key": "m365-teams-guest",
        "name": "Microsoft 365: Gast zu Team hinzugefügt",
        "description": "Eine externe Person (Gastkonto) wurde Mitglied eines Teams.",
        "query": 'app:teams category:guest',
        "severity": "low", "threshold": 1, "window": 3600, "group_by": "data.team",
    },
    # ---------------------------------------------------------------- Microsoft Defender
    {
        "key": "defender-high",
        "name": "Defender: Warnung mit hohem Schweregrad",
        "description": "Microsoft Defender meldet eine Bedrohung mit hohem Schweregrad. Details und "
                       "Gegenmaßnahmen stehen im Defender-Portal (Link im Event).",
        "query": 'app:defender data.severity:high',
        "severity": "high", "threshold": 1, "window": 3600, "group_by": "data.title",
    },
    {
        "key": "defender-medium",
        "name": "Defender: Warnung mit mittlerem Schweregrad",
        "description": "Microsoft Defender meldet eine verdächtige Aktivität mit mittlerem Schweregrad.",
        "query": 'app:defender data.severity:medium',
        "severity": "medium", "threshold": 1, "window": 3600, "group_by": "data.title",
    },
    {
        "key": "defender-low",
        "name": "Defender: Warnung mit niedrigem Schweregrad",
        "description": "Microsoft Defender meldet eine Auffälligkeit mit niedrigem Schweregrad.",
        "query": 'app:defender data.severity:low',
        "severity": "low", "threshold": 1, "window": 3600, "group_by": "data.title",
    },
    # ---------------------------------------------------------------- Allgemein
    {
        "key": "critical-messages",
        "name": "System: Kritische Meldungen",
        "description": "Meldungen mit Schweregrad emerg, alert oder crit.",
        "query": 'severity:<=crit',
        "severity": "high", "threshold": 1, "window": 1800, "group_by": "host",
    },
]

# Mitgelieferte Regeln, deren Abfrage sich geändert hat. Eine bestehende Regel wird nur
# angepasst, wenn sie noch genau die alte Abfrage hat (also nicht selbst geändert wurde).
RULE_UPGRADES: dict[str, list[tuple[str, str]]] = {
    "ssh-bruteforce": [('app:sshd category:authentication action:failure',
                        'app:sshd* category:authentication action:failure')],
    "ssh-user-enum": [('app:sshd action:failure user:*', 'app:sshd* action:failure user:*')],
    "ssh-root-login": [('app:sshd action:success user:root', 'app:sshd* action:success user:root')],
}
