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
        "query": 'app:sshd category:authentication action:failure',
        "severity": "high", "threshold": 10, "window": 300, "group_by": "src_ip",
    },
    {
        "key": "ssh-user-enum",
        "name": "SSH: Ausprobieren vieler Benutzernamen",
        "description": "Eine IP-Adresse versucht sich mit vielen unterschiedlichen Benutzernamen anzumelden.",
        "query": 'app:sshd action:failure user:*',
        "severity": "high", "threshold": 5, "window": 600, "group_by": "src_ip",
        "distinct_field": "user",
    },
    {
        "key": "ssh-root-login",
        "name": "SSH: Anmeldung als root",
        "description": "Erfolgreiche SSH-Anmeldung direkt als root. Besser: persönliche Konten + sudo.",
        "query": 'app:sshd action:success user:root',
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
    # ---------------------------------------------------------------- Allgemein
    {
        "key": "critical-messages",
        "name": "System: Kritische Meldungen",
        "description": "Meldungen mit Schweregrad emerg, alert oder crit.",
        "query": 'severity:<=crit',
        "severity": "high", "threshold": 1, "window": 1800, "group_by": "host",
    },
]
