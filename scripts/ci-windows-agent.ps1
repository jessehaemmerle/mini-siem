# Ende-zu-Ende-Test des Windows-Agenten (CI auf einem GitHub-Windows-Runner):
#  1. SIEM starten (mit dem frisch gebauten Agenten in dist/)
#  2. Agent mit dem Einzeiler aus der Oberfläche installieren – in Windows PowerShell 5.1
#  3. Ereignis ins Anwendungsprotokoll schreiben und prüfen, dass es im SIEM ankommt
#  4. Agentenliste, Dienst und Deinstallation prüfen
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$base = 'http://127.0.0.1:8080'
$password = 'CI-Passwort-123'

function Show-Logs {
    Write-Host '----- SIEM-Protokoll -----'
    Get-Content (Join-Path $root 'siem.err.log') -ErrorAction SilentlyContinue | Select-Object -Last 80
    Write-Host '----- Agent-Protokoll -----'
    Get-Content (Join-Path $env:ProgramData 'MiniSIEM\agent.log') -ErrorAction SilentlyContinue | Select-Object -Last 80
}

# ------------------------------------------------------------------ 1. SIEM starten
$env:SIEM_DATA_DIR = Join-Path $root 'ci-data'
$env:SIEM_AGENT_DIST = Join-Path $root 'dist'
$env:SIEM_ADMIN_PASSWORD = $password
$env:SIEM_SYSLOG_UDP_PORT = '0'
$env:SIEM_SYSLOG_TCP_PORT = '0'
$siem = Start-Process -FilePath python -ArgumentList '-m', 'siem' -WorkingDirectory $root -PassThru -NoNewWindow `
    -RedirectStandardOutput (Join-Path $root 'siem.log') -RedirectStandardError (Join-Path $root 'siem.err.log')
$up = $false
for ($i = 0; $i -lt 60 -and -not $up; $i++) {
    Start-Sleep -Seconds 1
    try { $up = (Invoke-RestMethod "$base/api/health").status -eq 'ok' } catch { }
}
if (-not $up) { Show-Logs; throw 'Das SIEM ist nicht gestartet.' }

$session = $null
Invoke-RestMethod -Method Post -Uri "$base/api/auth/login" -ContentType 'application/json' `
    -Body (@{ username = 'admin'; password = $password } | ConvertTo-Json) -SessionVariable session | Out-Null
$h = @{ 'X-SIEM' = '1' }
$settings = Invoke-RestMethod -Uri "$base/api/agents-settings" -WebSession $session -Headers $h
if ($settings.platforms -notcontains 'windows-amd64') { throw 'Kein Windows-Agent in dist/ gefunden.' }

# ------------------------------------------------------------------ 2. Einzeiler wie in der Oberfläche
$cmd = $settings.commands.windows
Write-Host "Installationsbefehl: $cmd"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command $cmd
if ($LASTEXITCODE -ne 0) { Show-Logs; throw "Installation fehlgeschlagen (Code $LASTEXITCODE)." }
$svc = Get-Service -Name 'mini-siem-agent'
if ($svc.Status -ne 'Running') { Show-Logs; throw "Dienst läuft nicht: $($svc.Status)" }
$svcInfo = Get-CimInstance Win32_Service -Filter "Name='mini-siem-agent'"
Write-Host "Dienst: $($svcInfo.State), Start: $($svcInfo.StartMode), Pfad: $($svcInfo.PathName)"
if ($svcInfo.StartMode -ne 'Auto') { throw 'Der Dienst startet nicht automatisch.' }

# ------------------------------------------------------------------ 3. Ereignis erzeugen und wiederfinden
Start-Sleep -Seconds 8
$marker = "Mini-SIEM-E2E-$([guid]::NewGuid().ToString('N'))"
eventcreate /T ERROR /ID 778 /L APPLICATION /SO MiniSIEME2E /D $marker | Out-Null
$deadline = (Get-Date).AddSeconds(120)
$hit = $null
do {
    Start-Sleep -Seconds 3
    $from = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - 3600
    $r = Invoke-RestMethod -Uri "$base/api/events" -WebSession $session -Headers $h `
        -Body @{ q = 'input:agent event_id:778'; from = $from }
    $hit = $r.events | Where-Object { $_.message -like "*$marker*" } | Select-Object -First 1
} until ($hit -or (Get-Date) -gt $deadline)
if (-not $hit) { Show-Logs; throw 'Das Testereignis ist nicht im SIEM angekommen.' }
Write-Host "Angekommen: host=$($hit.host) app=$($hit.app) severity=$($hit.severity) message=$($hit.message)"
if ($hit.severity -gt 3) { throw "Schweregrad für ERROR erwartet ≤ 3, bekommen $($hit.severity)" }

# ------------------------------------------------------------------ 4. Agentenliste und Deinstallation
Start-Sleep -Seconds 65   # nächster Check-in mit Status der Sammler
$agent = (Invoke-RestMethod -Uri "$base/api/agents" -WebSession $session -Headers $h).agents |
    Where-Object { $_.os -eq 'windows' } | Select-Object -First 1
$agent | ConvertTo-Json -Depth 5 | Write-Host
if (-not $agent.online) { Show-Logs; throw 'Der Agent ist nicht als verbunden gelistet.' }
if ($agent.version -ne $settings.version) { throw "Version $($agent.version) statt $($settings.version)" }
if ($agent.stats.collectors.'Windows-Ereignisprotokolle' -ne 'läuft') { Show-Logs; throw 'Der Ereignisprotokoll-Sammler läuft nicht.' }

& (Join-Path $env:ProgramFiles 'MiniSIEM\mini-siem-agent.exe') uninstall
if ($LASTEXITCODE -ne 0) { throw "Deinstallation fehlgeschlagen (Code $LASTEXITCODE)." }
$gone = $false
for ($i = 0; $i -lt 30 -and -not $gone; $i++) {
    $gone = -not (Get-Service -Name 'mini-siem-agent' -ErrorAction SilentlyContinue)
    if (-not $gone) { Start-Sleep -Seconds 1 }
}
if (-not $gone) { throw 'Der Dienst ist nach der Deinstallation noch vorhanden.' }

Stop-Process -Id $siem.Id -Force
Write-Host 'Windows-Agent: Ende-zu-Ende-Test bestanden.'
