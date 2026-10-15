"""Verwaltung der Agenten auf Serverseite.

* Registrierung mit einem Registrierungsschlüssel → jeder Agent erhält ein
  eigenes Token (nur als Hash gespeichert).
* Zentrale Konfiguration: Standard für alle Agenten, optional je Agent
  überschrieben. Agenten holen sie beim regelmäßigen Melden ("Check-in") ab.
* Auslieferung der Agent-Programmdateien und der Installationsskripte.
"""

from __future__ import annotations

import copy
import hashlib
import json
import secrets
import threading
import time
from pathlib import Path

from .auth import hash_token

PLATFORMS = ("linux-amd64", "linux-arm64", "windows-amd64")
ONLINE_SECONDS = 180  # Agent gilt als verbunden, wenn er sich in dieser Zeit gemeldet hat

DEFAULT_AGENT_CONFIG: dict = {
    "linux": {
        "journald": True,
        "min_priority": 6,           # 0 = emerg … 7 = debug; 6 = alles außer Debug
        "files": [],                 # zusätzliche Logdateien, Platzhalter erlaubt
    },
    "windows": {
        "channels": [
            # max_level: 1 kritisch, 2 Fehler, 3 Warnung, 4 Info, 5 ausführlich
            {"name": "Security", "max_level": 5, "event_ids": [],
             "exclude_ids": [4658, 4656, 4662, 4663, 4690, 5145, 5156, 5157, 5158]},
            {"name": "System", "max_level": 4, "event_ids": [], "exclude_ids": []},
            {"name": "Application", "max_level": 3, "event_ids": [], "exclude_ids": []},
            {"name": "Microsoft-Windows-PowerShell/Operational", "max_level": 3, "event_ids": [4104],
             "exclude_ids": []},
            {"name": "Microsoft-Windows-Windows Defender/Operational", "max_level": 4, "event_ids": [],
             "exclude_ids": []},
            {"name": "Microsoft-Windows-Sysmon/Operational", "max_level": 5, "event_ids": [],
             "exclude_ids": []},
        ],
    },
    "docker": {
        "enabled": True,
        "logs": True,
        "events": True,
        "exclude": ["mini-siem"],    # Containernamen, die nicht erfasst werden
    },
}


def _int_list(v, name: str) -> list[int]:
    if v in (None, ""):
        return []
    if not isinstance(v, list):
        raise ValueError(f"{name} muss eine Liste sein")
    out = []
    for x in v:
        try:
            n = int(x)
        except (TypeError, ValueError):
            raise ValueError(f"{name}: '{x}' ist keine Zahl") from None
        if not 0 <= n <= 65535:
            raise ValueError(f"{name}: {n} ist keine gültige Ereignis-ID")
        out.append(n)
    return sorted(set(out))[:200]


def validate_config(cfg: dict) -> dict:
    """Prüft eine Agent-Konfiguration und ergänzt fehlende Werte mit Standards."""
    if not isinstance(cfg, dict):
        raise ValueError("Konfiguration muss ein Objekt sein")
    out = copy.deepcopy(DEFAULT_AGENT_CONFIG)

    lx = cfg.get("linux") or {}
    out["linux"]["journald"] = bool(lx.get("journald", True))
    try:
        out["linux"]["min_priority"] = max(0, min(7, int(lx.get("min_priority", 6))))
    except (TypeError, ValueError):
        raise ValueError("Linux: Mindest-Priorität muss eine Zahl von 0 bis 7 sein") from None
    files = lx.get("files") or []
    if not isinstance(files, list) or not all(isinstance(f, str) for f in files):
        raise ValueError("Linux: Dateien müssen eine Liste von Pfaden sein")
    clean = []
    for f in files:
        f = f.strip()
        if not f:
            continue
        if not f.startswith("/") or "\x00" in f or len(f) > 512:
            raise ValueError(f"Linux: '{f}' ist kein absoluter Pfad")
        clean.append(f)
    out["linux"]["files"] = clean[:50]

    win = cfg.get("windows") or {}
    channels = win.get("channels")
    if channels is not None:
        if not isinstance(channels, list):
            raise ValueError("Windows: Kanäle müssen eine Liste sein")
        result = []
        for ch in channels[:40]:
            if not isinstance(ch, dict) or not str(ch.get("name") or "").strip():
                raise ValueError("Windows: jeder Kanal braucht einen Namen")
            name = str(ch["name"]).strip()
            if any(c in name for c in "\"'<>\x00") or len(name) > 200:
                raise ValueError(f"Windows: ungültiger Kanalname '{name}'")
            try:
                max_level = max(1, min(5, int(ch.get("max_level", 4))))
            except (TypeError, ValueError):
                raise ValueError(f"Windows: Stufe für '{name}' muss eine Zahl sein") from None
            result.append({
                "name": name,
                "max_level": max_level,
                "event_ids": _int_list(ch.get("event_ids"), f"Windows '{name}' Ereignis-IDs"),
                "exclude_ids": _int_list(ch.get("exclude_ids"), f"Windows '{name}' ausgeschlossene IDs"),
            })
        out["windows"]["channels"] = result

    dk = cfg.get("docker") or {}
    out["docker"]["enabled"] = bool(dk.get("enabled", True))
    out["docker"]["logs"] = bool(dk.get("logs", True))
    out["docker"]["events"] = bool(dk.get("events", True))
    excl = dk.get("exclude", out["docker"]["exclude"])
    if not isinstance(excl, list):
        raise ValueError("Docker: ausgeschlossene Container müssen eine Liste sein")
    out["docker"]["exclude"] = [str(x).strip().lstrip("/") for x in excl if str(x).strip()][:100]
    return out


def config_version(cfg: dict) -> str:
    return hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).hexdigest()[:16]


def new_enroll_key() -> str:
    return "enr_" + secrets.token_urlsafe(24)


def new_agent_token() -> str:
    return "agt_" + secrets.token_urlsafe(32)


class AgentRegistry:
    """Schneller Zugriff auf Agenten anhand ihres Tokens (ohne DB-Abfrage pro Request)."""

    def __init__(self, db):
        self.db = db
        self._by_hash: dict[str, dict] = {}
        self._loaded = 0.0
        self._lock = threading.Lock()
        self._counts: dict[int, int] = {}

    def invalidate(self) -> None:
        self._loaded = 0.0

    def lookup(self, token: str | None) -> dict | None:
        if not token:
            return None
        with self._lock:
            if time.time() - self._loaded > 30:
                rows = self.db.all("SELECT id, hostname, name, token_hash, disabled FROM agents")
                self._by_hash = {r["token_hash"]: r for r in rows}
                self._loaded = time.time()
            agent = self._by_hash.get(hash_token(token.strip()))
        if agent is None or agent["disabled"]:
            return None
        return agent

    def count(self, agent_id: int, n: int) -> None:
        with self._lock:
            self._counts[agent_id] = self._counts.get(agent_id, 0) + n

    def flush_counts(self) -> None:
        with self._lock:
            counts, self._counts = self._counts, {}
        if counts:
            with self.db.tx() as conn:
                conn.executemany("UPDATE agents SET events = events + ? WHERE id = ?",
                                 [(n, aid) for aid, n in counts.items()])


class AgentDist:
    """Die mitgelieferten Agent-Programmdateien (im Container unter /app/agent-dist)."""

    def __init__(self, directory: Path):
        self.dir = Path(directory)
        self._sha: dict[str, tuple[float, str]] = {}

    def filename(self, platform: str) -> str:
        return "mini-siem-agent-" + platform + (".exe" if platform.startswith("windows") else "")

    def path(self, platform: str) -> Path | None:
        if platform not in PLATFORMS:
            return None
        p = self.dir / self.filename(platform)
        return p if p.is_file() else None

    def sha256(self, platform: str) -> str | None:
        p = self.path(platform)
        if p is None:
            return None
        mtime = p.stat().st_mtime
        cached = self._sha.get(platform)
        if cached and cached[0] == mtime:
            return cached[1]
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        digest = h.hexdigest()
        self._sha[platform] = (mtime, digest)
        return digest

    def version(self) -> str | None:
        v = self.dir / "VERSION"
        return v.read_text().strip() if v.is_file() else None

    def available(self) -> list[str]:
        return [p for p in PLATFORMS if self.path(p)]


# ---------------------------------------------------------------------------
# Installationsskripte (Platzhalter __SERVER__ wird beim Abruf ersetzt)
# ---------------------------------------------------------------------------

INSTALL_SH = r"""#!/usr/bin/env bash
# Mini-SIEM Agent – Installation für Debian/Ubuntu (und andere systemd-Distributionen)
# Aufruf: curl -fsSL __SERVER__/api/agent/install.sh | sudo bash -s -- --key <Registrierungsschlüssel>
set -euo pipefail
SERVER="__SERVER__"
KEY=""
INSECURE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --key) KEY="${2:-}"; shift 2 ;;
    --insecure) INSECURE="1"; shift ;;
    *) echo "Unbekannte Option: $1" >&2; exit 1 ;;
  esac
done
if [ "$(id -u)" -ne 0 ]; then echo "Bitte mit sudo bzw. als root ausführen." >&2; exit 1; fi
if [ -z "$KEY" ]; then echo "Der Registrierungsschlüssel fehlt (--key …)." >&2; exit 1; fi
if ! command -v systemctl >/dev/null 2>&1; then echo "systemd wird benötigt." >&2; exit 1; fi
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "Prozessorarchitektur $(uname -m) wird nicht unterstützt." >&2; exit 1 ;;
esac
CURL="curl -fsSL"
[ -n "$INSECURE" ] && CURL="$CURL -k"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
echo "Lade Agent für linux-$ARCH …"
$CURL "$SERVER/api/agent/download/linux-$ARCH" -o "$TMP"
EXPECTED="$($CURL "$SERVER/api/agent/download/linux-$ARCH.sha256")"
echo "$EXPECTED  $TMP" | sha256sum -c --quiet - || { echo "Prüfsumme stimmt nicht – Abbruch." >&2; exit 1; }
if systemctl is-active --quiet mini-siem-agent 2>/dev/null; then systemctl stop mini-siem-agent; fi
install -d -m 0755 /opt/mini-siem-agent
install -m 0755 "$TMP" /opt/mini-siem-agent/mini-siem-agent
ln -sf /opt/mini-siem-agent/mini-siem-agent /usr/local/bin/mini-siem-agent
ARGS=(install --server "$SERVER" --key "$KEY")
[ -n "$INSECURE" ] && ARGS+=(--insecure)
/opt/mini-siem-agent/mini-siem-agent "${ARGS[@]}"
"""

INSTALL_PS1 = r"""# Mini-SIEM Agent – Installation für Windows (PowerShell als Administrator)
# Aufruf: & ([scriptblock]::Create((irm __SERVER__/api/agent/install.ps1))) -Key <Registrierungsschlüssel>
param(
  [Parameter(Mandatory = $true)][string]$Key,
  [switch]$Insecure
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Server = '__SERVER__'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Bitte PowerShell als Administrator starten.'
}
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
if ($Insecure) { [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } }
$dir = Join-Path $env:ProgramFiles 'MiniSIEM'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$exe = Join-Path $dir 'mini-siem-agent.exe'
$tmp = "$exe.download"
Write-Host 'Lade Agent für windows-amd64 …'
Invoke-WebRequest -UseBasicParsing -Uri "$Server/api/agent/download/windows-amd64" -OutFile $tmp
$expected = ((Invoke-WebRequest -UseBasicParsing -Uri "$Server/api/agent/download/windows-amd64.sha256").Content).Trim().ToLower()
$actual = (Get-FileHash -Algorithm SHA256 -Path $tmp).Hash.ToLower()
if ($actual -ne $expected) { Remove-Item $tmp -Force; throw 'Prüfsumme stimmt nicht – Abbruch.' }
if (Get-Service -Name 'mini-siem-agent' -ErrorAction SilentlyContinue) { Stop-Service -Name 'mini-siem-agent' -Force }
Move-Item -Force -Path $tmp -Destination $exe
$agentArgs = @('install', '--server', $Server, '--key', $Key)
if ($Insecure) { $agentArgs += '--insecure' }
& $exe @agentArgs
if ($LASTEXITCODE -ne 0) { throw "Installation fehlgeschlagen (Code $LASTEXITCODE)." }
"""
