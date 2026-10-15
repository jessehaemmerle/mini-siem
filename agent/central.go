package main

// Zentrale Konfiguration, die der Agent beim Check-in vom SIEM erhält.

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Channel struct {
	Name       string `json:"name"`
	MaxLevel   int    `json:"max_level"`
	EventIDs   []int  `json:"event_ids"`
	ExcludeIDs []int  `json:"exclude_ids"`
}

type CentralConfig struct {
	Linux struct {
		Journald    bool     `json:"journald"`
		MinPriority int      `json:"min_priority"`
		Files       []string `json:"files"`
	} `json:"linux"`
	Windows struct {
		Channels []Channel `json:"channels"`
	} `json:"windows"`
	Docker struct {
		Enabled bool     `json:"enabled"`
		Logs    bool     `json:"logs"`
		Events  bool     `json:"events"`
		Exclude []string `json:"exclude"`
	} `json:"docker"`
}

// defaultCentralConfig gilt, bis der Agent zum ersten Mal mit dem SIEM gesprochen hat.
func defaultCentralConfig() *CentralConfig {
	c := &CentralConfig{}
	c.Linux.Journald = true
	c.Linux.MinPriority = 6
	c.Windows.Channels = []Channel{
		{Name: "Security", MaxLevel: 5, ExcludeIDs: []int{4658, 4656, 4662, 4663, 4690, 5145, 5156, 5157, 5158}},
		{Name: "System", MaxLevel: 4},
		{Name: "Application", MaxLevel: 3},
	}
	c.Docker.Enabled, c.Docker.Logs, c.Docker.Events = true, true, true
	return c
}

func cachedConfigPath() string { return filepath.Join(stateDir(), "config-cache.json") }

// loadCachedConfig liefert die zuletzt vom Server erhaltene Konfiguration,
// damit der Agent auch startet, wenn das SIEM gerade nicht erreichbar ist.
func loadCachedConfig() (*CentralConfig, string) {
	b, err := os.ReadFile(cachedConfigPath())
	if err != nil {
		return defaultCentralConfig(), ""
	}
	var wrapper struct {
		Version string         `json:"version"`
		Config  *CentralConfig `json:"config"`
	}
	if json.Unmarshal(b, &wrapper) != nil || wrapper.Config == nil {
		return defaultCentralConfig(), ""
	}
	return wrapper.Config, wrapper.Version
}

func saveCachedConfig(c *CentralConfig, version string) {
	b, _ := json.Marshal(map[string]any{"version": version, "config": c})
	_ = os.MkdirAll(stateDir(), 0o700)
	_ = writeFileAtomic(cachedConfigPath(), b, 0o600)
}
