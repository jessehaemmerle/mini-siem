//go:build linux

package main

// Liest das systemd-Journal über "journalctl --follow --output=json". Der Cursor
// wird gespeichert, damit nach einem Neustart genau dort weitergelesen wird.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type journaldCollector struct {
	minPriority int
	state       *State
	emit        func(Event) bool
}

func (c *journaldCollector) Name() string { return "journald" }

func (c *journaldCollector) Run(ctx context.Context) error {
	if _, err := exec.LookPath("journalctl"); err != nil {
		return errors.New("journalctl nicht gefunden")
	}
	args := []string{"--follow", "--output=json", "--no-pager", "--priority=" + strconv.Itoa(c.minPriority)}
	if cursor := c.state.Get("journald.cursor"); cursor != "" {
		args = append(args, "--after-cursor="+cursor)
	} else {
		args = append(args, "--since=-10min")
	}
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		var rec map[string]any
		if json.Unmarshal(sc.Bytes(), &rec) != nil {
			continue
		}
		if cur, _ := rec["__CURSOR"].(string); cur != "" {
			c.state.Set("journald.cursor", cur)
		}
		if ev := journalEvent(rec); ev != nil {
			if !c.emit(ev) {
				break
			}
		}
	}
	err = cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	msg := strings.TrimSpace(stderr.String())
	if msg != "" {
		return fmt.Errorf("journalctl beendet: %s", msg)
	}
	if err != nil {
		return fmt.Errorf("journalctl beendet: %w", err)
	}
	return errors.New("journalctl wurde unerwartet beendet")
}

// journalEvent übersetzt einen Journal-Eintrag in das kompakte Agent-Format.
func journalEvent(rec map[string]any) Event {
	str := func(k string) string { s, _ := rec[k].(string); return s }
	ident := str("SYSLOG_IDENTIFIER")
	unit := str("_SYSTEMD_UNIT")
	if ident == "mini-siem-agent" || unit == "mini-siem-agent.service" {
		return nil // eigene Meldungen nicht zurückschicken (sonst Schleife bei Fehlern)
	}
	ev := Event{"src": "journald", "msg": rec["MESSAGE"]}
	if us, err := strconv.ParseInt(str("__REALTIME_TIMESTAMP"), 10, 64); err == nil {
		ev["t"] = float64(us) / 1e6
	} else {
		ev["t"] = nowUnix()
	}
	if p, err := strconv.Atoi(str("PRIORITY")); err == nil {
		ev["prio"] = p
	}
	if f, err := strconv.Atoi(str("SYSLOG_FACILITY")); err == nil {
		ev["facility"] = f
	}
	set := func(key, field string) {
		if v := str(field); v != "" {
			ev[key] = v
		}
	}
	set("ident", "SYSLOG_IDENTIFIER")
	set("comm", "_COMM")
	set("unit", "_SYSTEMD_UNIT")
	set("pid", "_PID")
	set("uid", "_UID")
	set("exe", "_EXE")
	set("transport", "_TRANSPORT")
	return ev
}
