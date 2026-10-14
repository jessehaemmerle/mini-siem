#!/usr/bin/env python3
"""Schickt Beispiel-Logs an das Mini-SIEM – zum Ausprobieren und Testen.

Beispiele:
    python3 scripts/demo_logs.py                       # Syslog an localhost:514
    python3 scripts/demo_logs.py --port 1514 --count 2000
    python3 scripts/demo_logs.py --url http://localhost:8080 --token siem_xxx   # zusätzlich HTTP/JSON

Erzeugt normalen Betrieb sowie einige Angriffe (SSH-Brute-Force, Portscan,
Windows-Fehlanmeldungen, Web-Angriff), damit Alarme entstehen.
Benötigt nur die Python-Standardbibliothek.
"""

import argparse
import json
import random
import socket
import time
import urllib.request

HOSTS = ["web01", "web02", "db01", "mail01", "fw01", "nas01"]
USERS = ["anna", "ben", "deploy", "backup", "root", "admin", "test", "oracle", "guest"]
ATTACKER = "203.0.113.66"
SCANNER = "198.51.100.23"


def bsd(pri, host, tag, msg, ts=None):
    t = time.strftime("%b %d %H:%M:%S", time.localtime(ts or time.time()))
    return f"<{pri}>{t} {host} {tag}: {msg}"


def normal_lines(n):
    out = []
    for _ in range(n):
        host = random.choice(HOSTS[:5])
        kind = random.random()
        if kind < 0.25:
            out.append(bsd(86, host, f"sshd[{random.randint(1000, 9999)}]",
                           f"Accepted publickey for {random.choice(['anna', 'ben', 'deploy'])} from 10.0.0.{random.randint(2, 60)} port {random.randint(30000, 60000)} ssh2"))
        elif kind < 0.45:
            out.append(bsd(78, host, f"CRON[{random.randint(1000, 9999)}]", "(root) CMD (/usr/local/bin/backup.sh >/dev/null 2>&1)"))
        elif kind < 0.6:
            out.append(bsd(30, host, "systemd[1]", random.choice(["Started Daily apt download activities.", "Finished Clean php session files.", "Starting Rotate log files..."])))
        elif kind < 0.7:
            out.append(bsd(28, host, "kernel", f"[UFW ALLOW] IN=eth0 OUT= SRC=10.0.0.{random.randint(2, 99)} DST=10.0.0.10 PROTO=TCP SPT={random.randint(30000, 60000)} DPT=443"))
        elif kind < 0.8:
            out.append(bsd(85, host, f"sudo", f"   anna : TTY=pts/0 ; PWD=/home/anna ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx"))
        elif kind < 0.9:
            out.append(bsd(19, "mail01", f"postfix/smtpd[{random.randint(1000, 9999)}]", f"connect from unknown[192.0.2.{random.randint(1, 250)}]"))
        elif kind < 0.97:
            out.append(bsd(27, host, "nginx", f"upstream timed out (110: Connection timed out) while reading response header from upstream, client: 10.0.0.{random.randint(2, 99)}"))
        else:
            out.append(bsd(27, "db01", "postgres[812]", "FATAL:  terminating connection due to administrator command"))
    return out


def attack_lines():
    out = []
    for i in range(18):
        user = random.choice(USERS)
        out.append(bsd(38, "web01", f"sshd[{4000 + i}]", f"Failed password for invalid user {user} from {ATTACKER} port {50000 + i} ssh2"))
    for port in random.sample(range(1, 10000), 40):
        out.append(bsd(4, "fw01", "kernel", f"[UFW BLOCK] IN=eth0 OUT= SRC={SCANNER} DST=10.0.0.1 PROTO=TCP SPT=40000 DPT={port}"))
    out.append(bsd(86, "web02", "sshd[777]", "Accepted password for root from 10.0.0.99 port 51515 ssh2"))
    out.append(bsd(86, "db01", "useradd[999]", "new user: name=support2, UID=1005, GID=1005, home=/home/support2, shell=/bin/bash"))
    out.append(bsd(2, "nas01", "kernel", "Out of memory: Killed process 4242 (java) total-vm:8123456kB"))
    out.append(bsd(10, "db01", "kernel", "EXT4-fs error (device sda1): ext4_find_entry:1455: inode #2: comm ls: reading directory lblock 0"))
    return out


def windows_events():
    evs = []
    for i in range(12):
        evs.append({"EventID": 4625, "Computer": "DC01.firma.local", "Channel": "Security",
                    "ProviderName": "Microsoft-Windows-Security-Auditing", "Keywords": "Audit Failure",
                    "TargetUserName": "j.mueller", "IpAddress": "10.0.5.77", "LogonType": 3,
                    "Message": "Fehler beim Anmelden eines Kontos."})
    evs.append({"EventID": 4740, "Computer": "DC01.firma.local", "Channel": "Security",
                "ProviderName": "Microsoft-Windows-Security-Auditing", "TargetUserName": "j.mueller",
                "Message": "Ein Benutzerkonto wurde gesperrt."})
    evs.append({"EventID": 4732, "Computer": "DC01.firma.local", "Channel": "Security",
                "ProviderName": "Microsoft-Windows-Security-Auditing", "MemberName": "CN=Support2,OU=IT,DC=firma,DC=local",
                "TargetUserName": "Administratoren", "SubjectUserName": "admin.x",
                "Message": "Ein Mitglied wurde einer sicherheitsaktivierten lokalen Gruppe hinzugefügt."})
    evs.append({"EventID": 4624, "Computer": "FS01.firma.local", "Channel": "Security",
                "ProviderName": "Microsoft-Windows-Security-Auditing", "TargetUserName": "anna", "IpAddress": "10.0.0.31",
                "LogonType": 3, "Message": "Ein Konto wurde erfolgreich angemeldet."})
    return evs


def app_events():
    return [
        {"message": "GET /shop/artikel?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1 403",
         "host": "web02", "app": "nginx", "src_ip": "192.0.2.150", "level": "warning", "status": 403},
        {"message": "Backup abgeschlossen", "host": "nas01", "app": "backup", "level": "info", "dauer_s": 512},
        {"message": "Zahlung fehlgeschlagen: Zeitüberschreitung beim Zahlungsanbieter", "host": "web01",
         "app": "shop", "level": "error", "order": "A-1042"},
    ]


def send_syslog(lines, host, port, proto):
    if proto == "udp":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for line in lines:
            s.sendto(line.encode(), (host, port))
            time.sleep(0.0005)
        s.close()
    else:
        with socket.create_connection((host, port), timeout=10) as s:
            s.sendall("".join(line + "\n" for line in lines).encode())


def send_http(url, token, events):
    req = urllib.request.Request(url.rstrip("/") + "/api/ingest", data=json.dumps(events).encode(),
                                 headers={"Content-Type": "application/json", "X-API-Key": token}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1", help="SIEM-Adresse für Syslog")
    ap.add_argument("--port", type=int, default=514, help="Syslog-Port")
    ap.add_argument("--proto", choices=["tcp", "udp"], default="tcp")
    ap.add_argument("--count", type=int, default=600, help="Anzahl normaler Meldungen")
    ap.add_argument("--no-attacks", action="store_true", help="keine Angriffe simulieren")
    ap.add_argument("--url", help="Basis-URL für HTTP, z. B. http://localhost:8080")
    ap.add_argument("--token", help="Ingest-Token für HTTP")
    args = ap.parse_args()

    lines = normal_lines(args.count)
    if not args.no_attacks:
        lines += attack_lines()
    random.shuffle(lines)
    send_syslog(lines, args.host, args.port, args.proto)
    print(f"{len(lines)} Syslog-Meldungen an {args.host}:{args.port}/{args.proto} gesendet")
    if args.url and args.token:
        events = windows_events() + app_events()
        r = send_http(args.url, args.token, events)
        print(f"{r.get('accepted')} JSON-Events per HTTP gesendet")


if __name__ == "__main__":
    main()
