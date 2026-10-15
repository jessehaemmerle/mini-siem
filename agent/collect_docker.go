package main

// Überwacht Docker über den lokalen Docker-Socket:
//   - Ausgaben (stdout/stderr) aller laufenden Container
//   - Docker-Ereignisse: Start/Stopp/Absturz/OOM, "docker exec", Kopieren von Dateien,
//     Healthchecks; beim Start wird geprüft, ob der Container privilegiert läuft oder
//     den Docker-Socket eingebunden hat.
// Container mit dem Label mini-siem.ignore=true oder in der Ausschlussliste werden übersprungen.

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var dockerSockets = []string{"/var/run/docker.sock", "/run/docker.sock"}

// Ereignisse, die weitergegeben werden (andere wie exec_create/exec_die sind Rauschen).
var dockerActions = map[string]bool{
	"create": true, "start": true, "restart": true, "stop": true, "kill": true, "die": true,
	"oom": true, "destroy": true, "pause": true, "unpause": true, "exec_start": true,
	"health_status": true, "rename": true, "update": true, "extract-to-dir": true,
}

type dockerCollector struct {
	logs, events bool
	exclude      map[string]bool
	state        *State
	emit         func(Event) bool

	http    *http.Client
	mu      sync.Mutex
	follow  map[string]context.CancelFunc
	running int
	health  map[string]string // Container-ID → Healthcheck-Befehl (wird bei exec_start herausgefiltert)
}

func newDockerCollector(cfg *CentralConfig, state *State, emit func(Event) bool) *dockerCollector {
	ex := map[string]bool{}
	for _, n := range cfg.Docker.Exclude {
		ex[strings.TrimPrefix(n, "/")] = true
	}
	return &dockerCollector{logs: cfg.Docker.Logs, events: cfg.Docker.Events, exclude: ex, state: state, emit: emit,
		follow: map[string]context.CancelFunc{}, health: map[string]string{}}
}

func (c *dockerCollector) Name() string { return "Docker" }

func findDockerSocket() string {
	if h := os.Getenv("DOCKER_HOST"); strings.HasPrefix(h, "unix://") {
		return strings.TrimPrefix(h, "unix://")
	}
	for _, s := range dockerSockets {
		if fi, err := os.Stat(s); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return s
		}
	}
	return ""
}

func (c *dockerCollector) Run(ctx context.Context) error {
	sock := findDockerSocket()
	if sock == "" {
		return errNotPresent
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}
	c.http = &http.Client{Transport: tr}
	defer tr.CloseIdleConnections()

	if _, err := c.get(ctx, "/_ping"); err != nil {
		return fmt.Errorf("Docker nicht erreichbar: %w", err)
	}
	if c.logs {
		var list []struct {
			ID     string            `json:"Id"`
			Names  []string          `json:"Names"`
			Image  string            `json:"Image"`
			Labels map[string]string `json:"Labels"`
		}
		if b, err := c.get(ctx, "/containers/json"); err == nil {
			_ = json.Unmarshal(b, &list)
		}
		for _, ct := range list {
			name := ""
			if len(ct.Names) > 0 {
				name = strings.TrimPrefix(ct.Names[0], "/")
			}
			if !c.skip(name, ct.Labels) {
				c.startFollow(ctx, ct.ID)
			}
		}
	}
	defer c.stopAll()
	return c.watchEvents(ctx)
}

func (c *dockerCollector) skip(name string, labels map[string]string) bool {
	return c.exclude[name] || strings.EqualFold(labels["mini-siem.ignore"], "true")
}

func (c *dockerCollector) get(ctx context.Context, path string) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://docker"+path, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode == http.StatusNotFound {
		return nil, errContainerGone
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("Docker-API %s: %d", path, resp.StatusCode)
	}
	return b, nil
}

// errContainerGone: Container existiert nicht mehr (z. B. bei nachgeholten Ereignissen nach dem Start).
var errContainerGone = errors.New("Container existiert nicht mehr")

// ---------------------------------------------------------------- Ereignisse

type dockerEvent struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		ID         string            `json:"ID"`
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
	Time     int64 `json:"time"`
	TimeNano int64 `json:"timeNano"`
}

func (c *dockerCollector) watchEvents(ctx context.Context) error {
	since := c.state.Get("docker.events_since")
	if since == "" {
		since = strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10)
	}
	filters := url.QueryEscape(`{"type":["container"]}`)
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://docker/events?since="+since+"&filters="+filters, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("Docker-Ereignisse: Status %d", resp.StatusCode)
	}
	dec := json.NewDecoder(resp.Body)
	for {
		var ev dockerEvent
		if err := dec.Decode(&ev); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("Docker-Ereignisstrom beendet: %w", err)
		}
		c.state.Set("docker.events_since", strconv.FormatInt(ev.Time+1, 10))
		c.handleEvent(ctx, ev)
	}
}

func (c *dockerCollector) handleEvent(ctx context.Context, ev dockerEvent) {
	action, detail, _ := strings.Cut(ev.Action, ":")
	action = strings.TrimSpace(action)
	detail = strings.TrimSpace(detail)
	attrs := ev.Actor.Attributes
	name := attrs["name"]
	if c.skip(name, attrs) {
		return
	}
	if action == "start" && c.logs {
		c.startFollow(ctx, ev.Actor.ID)
	}
	if action == "destroy" {
		c.mu.Lock()
		delete(c.health, ev.Actor.ID)
		c.mu.Unlock()
	}
	if !c.events || !dockerActions[action] {
		return
	}
	t := float64(ev.TimeNano) / 1e9
	if ev.TimeNano == 0 {
		t = float64(ev.Time)
	}
	out := Event{"src": "docker", "kind": "event", "t": t, "action": action, "container": name,
		"container_id": shortID(ev.Actor.ID), "image": attrs["image"]}
	if p := attrs["com.docker.compose.project"]; p != "" {
		out["compose_project"] = p
		out["compose_service"] = attrs["com.docker.compose.service"]
	}
	switch action {
	case "die":
		out["exit_code"] = attrs["exitCode"]
	case "health_status":
		out["health"] = detail
	case "exec_start":
		if detail != "" && detail == c.healthCmd(ctx, ev.Actor.ID) {
			return // Docker meldet jeden Healthcheck als exec – das ist kein Benutzerbefehl
		}
		out["exec_cmd"] = detail
		if id := attrs["execID"]; id != "" {
			if b, err := c.get(ctx, "/exec/"+id+"/json"); err == nil {
				var info struct {
					ProcessConfig struct {
						User       string `json:"user"`
						Privileged bool   `json:"privileged"`
					} `json:"ProcessConfig"`
				}
				if json.Unmarshal(b, &info) == nil {
					out["exec_user"] = info.ProcessConfig.User
					if info.ProcessConfig.Privileged {
						out["privileged"] = true
					}
				}
			}
		}
	case "extract-to-dir":
		out["action"] = "copy"
	case "start":
		c.inspectRisk(ctx, ev.Actor.ID, out)
	}
	c.emit(out)
}

// healthCmd liefert den Healthcheck-Befehl eines Containers so, wie Docker ihn im
// exec_start-Ereignis meldet ("/bin/sh -c …" bzw. die Befehlszeile).
func (c *dockerCollector) healthCmd(ctx context.Context, id string) string {
	c.mu.Lock()
	cmd, ok := c.health[id]
	c.mu.Unlock()
	if ok {
		return cmd
	}
	if b, err := c.get(ctx, "/containers/"+id+"/json"); err == nil {
		var info struct {
			Config struct {
				Healthcheck *struct {
					Test []string `json:"Test"`
				} `json:"Healthcheck"`
			} `json:"Config"`
		}
		if json.Unmarshal(b, &info) == nil && info.Config.Healthcheck != nil {
			cmd = healthCommand(info.Config.Healthcheck.Test)
		}
	}
	c.mu.Lock()
	c.health[id] = cmd
	c.mu.Unlock()
	return cmd
}

func healthCommand(test []string) string {
	if len(test) < 2 {
		return ""
	}
	switch test[0] {
	case "CMD-SHELL":
		return "/bin/sh -c " + test[1]
	case "CMD":
		return strings.Join(test[1:], " ")
	}
	return ""
}

// inspectRisk ergänzt beim Start Hinweise auf riskante Container-Einstellungen.
func (c *dockerCollector) inspectRisk(ctx context.Context, id string, out Event) {
	b, err := c.get(ctx, "/containers/"+id+"/json")
	if err != nil {
		return
	}
	var info struct {
		HostConfig struct {
			Privileged  bool     `json:"Privileged"`
			NetworkMode string   `json:"NetworkMode"`
			PidMode     string   `json:"PidMode"`
			CapAdd      []string `json:"CapAdd"`
		} `json:"HostConfig"`
		Mounts []struct {
			Source string `json:"Source"`
		} `json:"Mounts"`
	}
	if json.Unmarshal(b, &info) != nil {
		return
	}
	if info.HostConfig.Privileged {
		out["privileged"] = true
	}
	if info.HostConfig.NetworkMode == "host" {
		out["network_host"] = true
	}
	if info.HostConfig.PidMode == "host" {
		out["pid_host"] = true
	}
	if len(info.HostConfig.CapAdd) > 0 {
		out["cap_add"] = strings.Join(info.HostConfig.CapAdd, ",")
	}
	for _, m := range info.Mounts {
		if strings.HasSuffix(m.Source, "/docker.sock") {
			out["docker_socket"] = true
		}
	}
}

// ---------------------------------------------------------------- Container-Ausgaben

func (c *dockerCollector) startFollow(parent context.Context, id string) {
	c.mu.Lock()
	if _, ok := c.follow[id]; ok {
		c.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(parent)
	c.follow[id] = cancel
	c.running++
	c.mu.Unlock()
	go func() {
		defer func() {
			c.mu.Lock()
			delete(c.follow, id)
			c.running--
			c.mu.Unlock()
			cancel()
		}()
		if err := c.followLogs(ctx, id); err != nil && ctx.Err() == nil && !errors.Is(err, errContainerGone) {
			logf("Docker-Ausgaben von %s: %v", shortID(id), err)
		}
	}()
}

func (c *dockerCollector) stopAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, cancel := range c.follow {
		cancel()
	}
}

func (c *dockerCollector) Running() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}

func (c *dockerCollector) followLogs(ctx context.Context, id string) error {
	b, err := c.get(ctx, "/containers/"+id+"/json")
	if err != nil {
		return err
	}
	var info struct {
		Name   string `json:"Name"`
		Config struct {
			Tty    bool              `json:"Tty"`
			Image  string            `json:"Image"`
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := json.Unmarshal(b, &info); err != nil {
		return err
	}
	name := strings.TrimPrefix(info.Name, "/")
	if c.skip(name, info.Config.Labels) {
		return nil
	}
	key := "docker.logs." + id
	since := strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10)
	var lastT time.Time // Zeitpunkt der letzten gelesenen Zeile
	if t, err := time.Parse(time.RFC3339Nano, c.state.Get(key)); err == nil {
		lastT = t
		since = strconv.FormatInt(t.Unix(), 10)
	}
	req, _ := http.NewRequestWithContext(ctx, "GET",
		"http://docker/containers/"+id+"/logs?follow=1&stdout=1&stderr=1&timestamps=1&since="+since, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return errContainerGone
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("Status %d", resp.StatusCode)
	}
	base := Event{"src": "docker", "kind": "log", "container": name, "container_id": shortID(id),
		"image": info.Config.Image}
	if p := info.Config.Labels["com.docker.compose.project"]; p != "" {
		base["compose_project"] = p
		base["compose_service"] = info.Config.Labels["com.docker.compose.service"]
	}
	handle := func(stream, line string) bool {
		ts, msg, ok := strings.Cut(line, " ")
		if !ok {
			return true
		}
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return true
		}
		if !lastT.IsZero() && !t.After(lastT) {
			return true // bereits gesendet (Überlappung beim Wiederaufsetzen)
		}
		lastT = t
		c.state.Set(key, ts)
		if strings.TrimSpace(msg) == "" {
			return true
		}
		if len(msg) > maxLineBytes {
			msg = msg[:maxLineBytes]
		}
		ev := Event{"t": float64(t.UnixNano()) / 1e9, "stream": stream, "msg": strings.TrimRight(msg, "\r")}
		for k, v := range base {
			ev[k] = v
		}
		return c.emit(ev)
	}
	if info.Config.Tty {
		return scanLines(resp.Body, func(l string) bool { return handle("stdout", l) })
	}
	return demuxDockerStream(resp.Body, handle)
}

func scanLines(r io.Reader, fn func(string) bool) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if !fn(sc.Text()) {
			return nil
		}
	}
	return sc.Err()
}

// demuxDockerStream zerlegt den Docker-Multiplex-Strom (8-Byte-Kopf je Block) in Zeilen.
func demuxDockerStream(r io.Reader, fn func(stream, line string) bool) error {
	br := bufio.NewReaderSize(r, 64<<10)
	header := make([]byte, 8)
	partial := map[byte][]byte{}
	for {
		if _, err := io.ReadFull(br, header); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		size := binary.BigEndian.Uint32(header[4:8])
		if size > 16<<20 {
			return errors.New("ungültiger Docker-Datenblock")
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(br, payload); err != nil {
			return nil
		}
		kind := header[0]
		stream := "stdout"
		if kind == 2 {
			stream = "stderr"
		}
		data := append(partial[kind], payload...)
		for {
			i := strings.IndexByte(string(data), '\n')
			if i < 0 {
				break
			}
			if !fn(stream, string(data[:i])) {
				return nil
			}
			data = data[i+1:]
		}
		if len(data) > maxLineBytes {
			if !fn(stream, string(data)) {
				return nil
			}
			data = nil
		}
		partial[kind] = append([]byte(nil), data...)
	}
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
