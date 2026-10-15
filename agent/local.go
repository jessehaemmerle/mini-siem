package main

// Lokale Konfiguration (Server, Token) und Zustand (Lesepositionen der Quellen).

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// LocalConfig wird bei der Installation geschrieben und enthält die Zugangsdaten.
type LocalConfig struct {
	Server   string `json:"server"`
	Token    string `json:"token"`
	AgentID  int    `json:"agent_id"`
	Insecure bool   `json:"insecure,omitempty"`
	Hostname string `json:"hostname"`
}

func configDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(programData(), "MiniSIEM")
	}
	return "/etc/mini-siem-agent"
}

func stateDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(programData(), "MiniSIEM", "state")
	}
	return "/var/lib/mini-siem-agent"
}

func programData() string {
	if p := os.Getenv("ProgramData"); p != "" {
		return p
	}
	return `C:\ProgramData`
}

func configPath() string { return filepath.Join(configDir(), "agent.json") }

func loadLocalConfig() (*LocalConfig, error) {
	b, err := os.ReadFile(configPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("der Agent ist noch nicht registriert – bitte zuerst 'mini-siem-agent install' ausführen")
		}
		return nil, err
	}
	var c LocalConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.Server == "" || c.Token == "" {
		return nil, errors.New("die Konfiguration ist unvollständig – bitte den Agenten neu installieren")
	}
	return &c, nil
}

func saveLocalConfig(c *LocalConfig) error {
	if err := os.MkdirAll(configDir(), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return writeFileAtomic(configPath(), b, 0o600)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// State speichert Lesepositionen (journald-Cursor, Datei-Offsets, Windows-Record-IDs …),
// damit nach einem Neustart weder Events fehlen noch doppelt gesendet werden.
type State struct {
	mu    sync.Mutex
	path  string
	data  map[string]string
	dirty bool
}

func openState() *State {
	s := &State{path: filepath.Join(stateDir(), "state.json"), data: map[string]string{}}
	if b, err := os.ReadFile(s.path); err == nil {
		_ = json.Unmarshal(b, &s.data)
	}
	return s
}

func (s *State) Get(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data[key]
}

func (s *State) Set(key, value string) {
	s.mu.Lock()
	if s.data[key] != value {
		s.data[key] = value
		s.dirty = true
	}
	s.mu.Unlock()
}

func (s *State) Delete(key string) {
	s.mu.Lock()
	if _, ok := s.data[key]; ok {
		delete(s.data, key)
		s.dirty = true
	}
	s.mu.Unlock()
}

func (s *State) Save() error {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	b, _ := json.Marshal(s.data)
	s.dirty = false
	s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(s.path, b, 0o600)
}

// SaveLoop speichert den Zustand alle paar Sekunden.
func (s *State) SaveLoop(stop <-chan struct{}) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			_ = s.Save()
			return
		case <-t.C:
			if err := s.Save(); err != nil {
				logf("Zustand konnte nicht gespeichert werden: %v", err)
			}
		}
	}
}
