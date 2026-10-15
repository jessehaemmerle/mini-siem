//go:build linux

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
)

const (
	unitPath   = "/etc/systemd/system/mini-siem-agent.service"
	installDir = "/opt/mini-siem-agent"
	binLink    = "/usr/local/bin/mini-siem-agent"
)

const unitFile = `[Unit]
Description=Mini-SIEM Agent
Documentation=https://github.com/jessehaemmerle/mini-siem
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s run
Restart=always
RestartSec=5
# Root wird für das Journal aller Dienste und den Docker-Socket benötigt;
# das Dateisystem ist bis auf die eigenen Verzeichnisse schreibgeschützt.
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ReadWritePaths=/var/lib/mini-siem-agent /opt/mini-siem-agent
StateDirectory=mini-siem-agent
StateDirectoryMode=0700

[Install]
WantedBy=multi-user.target
`

type SystemInfo struct {
	Hostname, OS, OSVersion, Arch, MachineID string
}

func systemInfo() SystemInfo {
	host, _ := os.Hostname()
	return SystemInfo{Hostname: host, OS: "linux", OSVersion: osRelease(), Arch: runtime.GOARCH, MachineID: machineID()}
}

func osRelease() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "PRETTY_NAME="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

func machineID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil {
			if id := strings.TrimSpace(string(b)); len(id) >= 16 {
				return id
			}
		}
	}
	// Fallback: einmalig erzeugte ID im Zustandsverzeichnis
	p := stateDir() + "/machine-id"
	if b, err := os.ReadFile(p); err == nil && len(strings.TrimSpace(string(b))) >= 16 {
		return strings.TrimSpace(string(b))
	}
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	id := hex.EncodeToString(buf)
	_ = os.MkdirAll(stateDir(), 0o700)
	_ = os.WriteFile(p, []byte(id), 0o600)
	return id
}

func platformCollectors(cfg *CentralConfig, state *State, emit func(Event) bool) []collector {
	var out []collector
	if cfg.Linux.Journald {
		out = append(out, &journaldCollector{minPriority: cfg.Linux.MinPriority, state: state, emit: emit})
	}
	if len(cfg.Linux.Files) > 0 {
		out = append(out, &fileCollector{patterns: cfg.Linux.Files, state: state, emit: emit})
	}
	if cfg.Docker.Enabled && (cfg.Docker.Logs || cfg.Docker.Events) {
		out = append(out, newDockerCollector(cfg, state, emit))
	}
	return out
}

func runMain() int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return runAgent(ctx)
}

func requireAdmin() error {
	if os.Geteuid() != 0 {
		return errors.New("bitte mit sudo bzw. als root ausführen")
	}
	return nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// installService legt das Programm unter /opt ab und richtet den systemd-Dienst ein.
func installService() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	target := installDir + "/mini-siem-agent"
	if exe != target {
		data, err := os.ReadFile(exe)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(installDir, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(target+".new", data, 0o755); err != nil {
			return err
		}
		if err := os.Rename(target+".new", target); err != nil {
			return err
		}
		if fi, err := os.Lstat(binLink); err == nil && fi.Mode().IsRegular() {
			_ = os.Remove(binLink) // ersetzt durch Verknüpfung
		}
		_ = os.Remove(binLink)
		_ = os.Symlink(target, binLink)
	}
	if err := os.WriteFile(unitPath, []byte(fmt.Sprintf(unitFile, target)), 0o644); err != nil {
		return err
	}
	if err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := run("systemctl", "enable", "mini-siem-agent"); err != nil {
		return err
	}
	return run("systemctl", "restart", "mini-siem-agent")
}

func uninstallService() error {
	_ = run("systemctl", "disable", "--now", "mini-siem-agent")
	if err := os.Remove(unitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return run("systemctl", "daemon-reload")
}

func removeInstalledFiles() {
	_ = os.Remove(binLink)
	_ = os.RemoveAll(installDir)
	_ = os.RemoveAll(configDir())
}

func serviceStatus() string {
	out, _ := exec.Command("systemctl", "is-active", "mini-siem-agent").Output()
	s := strings.TrimSpace(string(out))
	switch s {
	case "active":
		return "läuft"
	case "":
		return "unbekannt"
	default:
		return s
	}
}

// replaceExecutable tauscht die laufende Datei aus (unter Linux direkt möglich).
func replaceExecutable(exe, newPath string) error {
	return os.Rename(newPath, exe)
}
