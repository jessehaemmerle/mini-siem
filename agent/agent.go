package main

// Steuerung: Quellen starten, regelmäßig beim SIEM melden (Konfiguration und
// Updates abholen), bei geänderter Konfiguration die Quellen neu starten.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	checkinInterval = 60 * time.Second
	exitRestart     = 3 // Dienstverwaltung startet den Agenten neu (nach einem Update)
)

var errNotPresent = errors.New("auf diesem System nicht vorhanden")

var errAlreadyRunning = errors.New("der Agent läuft bereits (als Dienst oder in einem anderen Fenster) – bitte nur einmal starten")

type collector interface {
	Name() string
	Run(ctx context.Context) error
}

type Agent struct {
	local  *LocalConfig
	info   SystemInfo
	client *Client
	state  *State
	sender *Sender

	mu         sync.Mutex
	status     map[string]string
	collectors []collector
	started    time.Time
}

// runAgent läuft, bis ctx beendet wird, und liefert den Exit-Code.
func runAgent(ctx context.Context) int {
	local, err := loadLocalConfig()
	if err != nil {
		logf("%v", err)
		return 1
	}
	if err := os.MkdirAll(stateDir(), 0o700); err != nil {
		logf("Zustandsverzeichnis: %v", err)
		return 1
	}
	unlock, err := acquireLock(filepath.Join(stateDir(), "agent.lock"))
	if err != nil {
		logf("%v", err)
		return 1
	}
	defer unlock()
	removeOldBinary()
	a := &Agent{local: local, info: systemInfo(), state: openState(), status: map[string]string{}, started: time.Now()}
	a.client = newClient(local.Server, local.Token, local.Insecure)
	a.sender = newSender(a.client)
	logf("Mini-SIEM Agent %s startet (Server %s, Host %s)", version, local.Server, a.info.Hostname)

	stopSave := make(chan struct{})
	saveDone := make(chan struct{})
	go func() { a.state.SaveLoop(stopSave); close(saveDone) }()

	senderCtx, stopSender := context.WithCancel(context.Background())
	senderDone := make(chan struct{})
	go func() { a.sender.Run(senderCtx); close(senderDone) }()

	cfg, cfgVersion := loadCachedConfig()
	collectCtx, stopCollectors := context.WithCancel(ctx)
	var wg sync.WaitGroup
	a.startCollectors(collectCtx, cfg, &wg)

	code := 0
	ticker := time.NewTicker(checkinInterval)
	defer ticker.Stop()
	first := time.After(2 * time.Second)
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-first:
		case <-ticker.C:
		}
		resp, err := a.client.Checkin(a.info, a.stats())
		if err != nil {
			logf("Melden beim SIEM fehlgeschlagen: %v", err)
			continue
		}
		a.sender.unauthorized.Store(false)
		if resp.Config != nil && resp.ConfigVersion != cfgVersion {
			logf("Neue Einstellungen vom SIEM übernommen")
			saveCachedConfig(resp.Config, resp.ConfigVersion)
			stopCollectors()
			wg.Wait()
			cfg, cfgVersion = resp.Config, resp.ConfigVersion
			collectCtx, stopCollectors = context.WithCancel(ctx)
			a.startCollectors(collectCtx, cfg, &wg)
		}
		if resp.Update != nil && resp.Update.Version != "" && resp.Update.Version != version {
			if err := applyUpdate(a.client, resp.Update); err != nil {
				logf("Update auf %s fehlgeschlagen: %v", resp.Update.Version, err)
			} else {
				logf("Update auf %s installiert – Neustart", resp.Update.Version)
				code = exitRestart
				break loop
			}
		}
	}
	stopCollectors()
	waitTimeout(&wg, 10*time.Second)
	stopSender()
	<-senderDone
	close(stopSave)
	<-saveDone
	logf("Mini-SIEM Agent beendet")
	return code
}

func waitTimeout(wg *sync.WaitGroup, d time.Duration) {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
	}
}

func (a *Agent) startCollectors(ctx context.Context, cfg *CentralConfig, wg *sync.WaitGroup) {
	emit := func(ev Event) bool { return a.sender.Enqueue(ctx, ev) }
	cols := platformCollectors(cfg, a.state, emit)
	a.mu.Lock()
	a.collectors = cols
	a.status = map[string]string{}
	a.mu.Unlock()
	for _, c := range cols {
		wg.Add(1)
		go func(c collector) {
			defer wg.Done()
			a.supervise(ctx, c)
		}(c)
	}
}

// supervise startet eine Quelle nach Fehlern mit Wartezeit neu.
func (a *Agent) supervise(ctx context.Context, c collector) {
	for {
		a.setStatus(c.Name(), "läuft")
		err := c.Run(ctx)
		if ctx.Err() != nil {
			return
		}
		wait := 5 * time.Second
		switch {
		case errors.Is(err, errNotPresent):
			a.setStatus(c.Name(), "nicht vorhanden")
			wait = time.Minute
		case err != nil:
			a.setStatus(c.Name(), "Fehler: "+err.Error())
			logf("%s: %v", c.Name(), err)
		default:
			a.setStatus(c.Name(), "beendet")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (a *Agent) setStatus(name, s string) {
	a.mu.Lock()
	a.status[name] = s
	a.mu.Unlock()
}

func (a *Agent) stats() map[string]any {
	out := a.sender.Stats()
	a.mu.Lock()
	cols := map[string]string{}
	for k, v := range a.status {
		cols[k] = v
	}
	for _, c := range a.collectors {
		if d, ok := c.(interface{ Running() int }); ok {
			out["docker_containers"] = d.Running()
		}
		if w, ok := c.(interface{ Missing() []string }); ok {
			if m := w.Missing(); len(m) > 0 {
				out["missing_channels"] = m
			}
		}
	}
	a.mu.Unlock()
	out["collectors"] = cols
	out["uptime"] = int(time.Since(a.started).Seconds())
	return out
}

// ---------------------------------------------------------------- Selbst-Update

func applyUpdate(c *Client, u *UpdateInfo) error {
	data, err := c.Download(u.URL)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != u.SHA256 {
		return errors.New("Prüfsumme stimmt nicht")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	tmp := exe + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return fmt.Errorf("neue Version kann nicht geschrieben werden: %w", err)
	}
	return replaceExecutable(exe, tmp)
}

func removeOldBinary() {
	if exe, err := os.Executable(); err == nil {
		_ = os.Remove(exe + ".old")
	}
}
