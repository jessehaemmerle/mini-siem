#!/usr/bin/env bash
# Ende-zu-Ende-Test des Linux-Agenten (CI auf einem GitHub-Ubuntu-Runner mit systemd und Docker).
# Voraussetzung: der SIEM-Container läuft auf http://localhost:8080 mit Admin-Passwort $SIEM_PW.
set -euo pipefail
BASE=http://localhost:8080
JAR=$(mktemp)
H=(-H "X-SIEM: 1" -b "$JAR" -c "$JAR")

logs() {
  echo "----- Agent -----"; sudo journalctl -u mini-siem-agent --no-pager -n 60 || true
  echo "----- SIEM -----"; docker logs --tail 60 siem || true
}
trap 'logs' ERR

curl -fsS "${H[@]}" -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"$SIEM_PW\"}" "$BASE/api/auth/login" >/dev/null
SETTINGS=$(curl -fsS "${H[@]}" "$BASE/api/agents-settings")
CMD=$(echo "$SETTINGS" | jq -r .commands.linux)
VERSION=$(echo "$SETTINGS" | jq -r .version)
echo "Installationsbefehl: $CMD"

# 1. Einzeiler wie in der Oberfläche
bash -c "$CMD"
systemctl is-active --quiet mini-siem-agent
systemctl is-enabled --quiet mini-siem-agent
sudo mini-siem-agent status

# 2. Journal: Testmeldung muss ankommen
MARKER="mini-siem-e2e-$RANDOM$RANDOM"
sleep 5
logger -t e2e-test "Hallo $MARKER"
# 3. Docker: Container starten, Ausgabe und Ereignis müssen ankommen
docker run -d --name e2e-container alpine:3.20 sh -c "sleep 3; echo Docker $MARKER; sleep 30" >/dev/null

found() {
  curl -fsS "${H[@]}" --get --data-urlencode "q=$1" --data-urlencode "from=$(( $(date +%s) - 3600 ))" \
    "$BASE/api/events" | jq -e '.events | length > 0' >/dev/null
}
for q in "app:e2e-test \"$MARKER\"" "app:e2e-container \"$MARKER\"" "event_id:docker.start data.container:e2e-container"; do
  ok=0
  for _ in $(seq 1 40); do
    if found "$q"; then ok=1; break; fi
    sleep 3
  done
  [ "$ok" = 1 ] || { echo "Nicht angekommen: $q"; logs; exit 1; }
  echo "angekommen: $q"
done

# 4. Agentenliste nach dem nächsten Check-in
sleep 65
AGENT=$(curl -fsS "${H[@]}" "$BASE/api/agents" | jq '.agents[] | select(.os == "linux")')
echo "$AGENT"
echo "$AGENT" | jq -e '.online == true' >/dev/null
echo "$AGENT" | jq -e --arg v "$VERSION" '.version == $v' >/dev/null
echo "$AGENT" | jq -e '.stats.collectors.journald == "läuft" and .stats.collectors.Docker == "läuft"' >/dev/null

docker rm -f e2e-container >/dev/null

# 5. Deinstallation
sudo mini-siem-agent uninstall
if systemctl is-active --quiet mini-siem-agent; then echo "Dienst läuft nach der Deinstallation noch"; exit 1; fi
[ ! -e /opt/mini-siem-agent ]
echo "Linux-Agent: Ende-zu-Ende-Test bestanden."
