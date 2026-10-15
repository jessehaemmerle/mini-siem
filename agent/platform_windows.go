//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "mini-siem-agent"

type SystemInfo struct {
	Hostname, OS, OSVersion, Arch, MachineID string
}

func systemInfo() SystemInfo {
	host, _ := os.Hostname()
	return SystemInfo{Hostname: host, OS: "windows", OSVersion: windowsVersion(), Arch: runtime.GOARCH, MachineID: machineID()}
}

func windowsVersion() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	name, _, _ := k.GetStringValue("ProductName")
	disp, _, _ := k.GetStringValue("DisplayVersion")
	build, _, _ := k.GetStringValue("CurrentBuild")
	// Windows 11 meldet sich in ProductName weiterhin als "Windows 10"
	if strings.HasPrefix(name, "Windows 10") && build >= "22000" {
		name = "Windows 11" + strings.TrimPrefix(name, "Windows 10")
	}
	return strings.TrimSpace(fmt.Sprintf("%s %s (Build %s)", name, disp, build))
}

func machineID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`,
		registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err == nil {
		defer k.Close()
		if v, _, err := k.GetStringValue("MachineGuid"); err == nil && v != "" {
			return v
		}
	}
	host, _ := os.Hostname()
	return "host-" + host
}

func platformCollectors(cfg *CentralConfig, state *State, emit func(Event) bool) []collector {
	var out []collector
	if len(cfg.Windows.Channels) > 0 {
		out = append(out, newWinlogCollector(cfg, state, emit))
	}
	return out
}

// ---------------------------------------------------------------- Dienst

type agentService struct{}

func (agentService) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- runAgent(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(25 * time.Second):
				}
				return false, 0
			}
		case code := <-done:
			cancel()
			if code != 0 {
				// Exit-Code ≠ 0: Windows startet den Dienst laut Wiederherstellungsoptionen neu
				return true, uint32(code)
			}
			return false, 0
		}
	}
}

func runMain() int {
	isService, err := svc.IsWindowsService()
	if err == nil && isService {
		setupFileLog()
		if err := svc.Run(serviceName, agentService{}); err != nil {
			logf("Dienst konnte nicht gestartet werden: %v", err)
			return 1
		}
		return 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return runAgent(ctx)
}

// setupFileLog schreibt das Protokoll nach C:\ProgramData\MiniSIEM\agent.log (max. 2 × 5 MB).
func setupFileLog() {
	path := filepath.Join(configDir(), "agent.log")
	_ = os.MkdirAll(configDir(), 0o700)
	if fi, err := os.Stat(path); err == nil && fi.Size() > 5<<20 {
		_ = os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	log.SetOutput(io.Writer(f))
}

func requireAdmin() error {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(&windows.SECURITY_NT_AUTHORITY, 2,
		windows.SECURITY_BUILTIN_DOMAIN_RID, windows.DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &sid)
	if err != nil {
		return err
	}
	defer windows.FreeSid(sid)
	member, err := windows.Token(0).IsMember(sid)
	if err != nil || !member {
		return errors.New("bitte die Eingabeaufforderung bzw. PowerShell als Administrator starten")
	}
	return nil
}

func installService() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err == nil {
		// vorhandenen Dienst aktualisieren
		_, _ = s.Control(svc.Stop)
		waitStopped(s)
		cfg, err := s.Config()
		if err == nil {
			cfg.BinaryPathName = `"` + exe + `" run`
			cfg.StartType = mgr.StartAutomatic
			_ = s.UpdateConfig(cfg)
		}
	} else {
		s, err = m.CreateService(serviceName, exe, mgr.Config{
			DisplayName:  "Mini-SIEM Agent",
			Description:  "Sammelt Windows-Ereignisprotokolle und sendet sie an das Mini-SIEM.",
			StartType:    mgr.StartAutomatic,
			ErrorControl: mgr.ErrorNormal,
		}, "run")
		if err != nil {
			return err
		}
	}
	defer s.Close()
	actions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 2 * time.Minute},
	}
	if err := s.SetRecoveryActions(actions, 86400); err != nil {
		return err
	}
	_ = s.SetRecoveryActionsOnNonCrashFailures(true)
	return s.Start()
}

func waitStopped(s *mgr.Service) {
	for i := 0; i < 30; i++ {
		st, err := s.Query()
		if err != nil || st.State == svc.Stopped {
			return
		}
		time.Sleep(time.Second)
	}
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return nil // nicht installiert
	}
	defer s.Close()
	_, _ = s.Control(svc.Stop)
	waitStopped(s)
	return s.Delete()
}

func removeInstalledFiles() {
	// Die eigene .exe kann nicht gelöscht werden, solange sie läuft – Hinweis genügt.
	_ = os.RemoveAll(configDir())
	if exe, err := os.Executable(); err == nil {
		fmt.Printf("Die Programmdatei %s kann jetzt gelöscht werden.\n", exe)
	}
}

func serviceStatus() string {
	m, err := mgr.Connect()
	if err != nil {
		return "unbekannt"
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return "nicht installiert"
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return "unbekannt"
	}
	switch st.State {
	case svc.Running:
		return "läuft"
	case svc.Stopped:
		return "gestoppt"
	default:
		return fmt.Sprintf("Zustand %d", st.State)
	}
}

// replaceExecutable: Eine laufende .exe kann umbenannt, aber nicht überschrieben werden.
func replaceExecutable(exe, newPath string) error {
	old := exe + ".old"
	_ = os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		return err
	}
	if err := os.Rename(newPath, exe); err != nil {
		_ = os.Rename(old, exe)
		return err
	}
	return nil
}
