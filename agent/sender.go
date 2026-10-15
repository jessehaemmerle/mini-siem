package main

// Sammelt Events, schickt sie stapelweise (gzip) an das SIEM und puffert sie
// auf der Festplatte, solange das SIEM nicht erreichbar ist.

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Event ist ein frei strukturiertes Objekt (siehe siem/agent_events.py).
type Event map[string]any

const (
	batchMax      = 500
	batchInterval = 2 * time.Second
	spoolMaxBytes = 256 << 20 // höchstens 256 MB Puffer auf der Festplatte
)

type Sender struct {
	client   *Client
	queue    chan Event
	spoolDir string

	sent, dropped, spooledEvents atomic.Int64
	mu                           sync.Mutex
	lastError                    string
	lastErrorAt                  time.Time
	unauthorized                 atomic.Bool
	lastSpool                    atomic.Int64
}

func newSender(c *Client) *Sender {
	return &Sender{client: c, queue: make(chan Event, 20000), spoolDir: filepath.Join(stateDir(), "spool")}
}

// Enqueue blockiert, wenn die Warteschlange voll ist (Quellen lesen dann langsamer),
// bricht aber ab, sobald der Agent beendet wird.
func (s *Sender) Enqueue(ctx context.Context, ev Event) bool {
	select {
	case s.queue <- ev:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *Sender) setError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		s.lastError = ""
		return
	}
	s.lastError = err.Error()
	s.lastErrorAt = time.Now()
}

func (s *Sender) Stats() map[string]any {
	files, size := s.spoolInfo()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]any{
		"sent": s.sent.Load(), "dropped": s.dropped.Load(), "queue": len(s.queue),
		"spool_files": files, "spool_bytes": size,
	}
	if s.lastError != "" {
		out["last_error"] = s.lastError
		out["last_error_at"] = s.lastErrorAt.Unix()
	}
	return out
}

func encodeBatch(batch []Event) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(batch); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Run läuft bis ctx beendet ist und leert dann die Warteschlange in den Puffer.
func (s *Sender) Run(ctx context.Context) {
	ticker := time.NewTicker(batchInterval)
	defer ticker.Stop()
	batch := make([]Event, 0, batchMax)
	backoff := time.Duration(0)
	var nextTry time.Time

	flush := func() {
		if len(batch) == 0 {
			return
		}
		gz, err := encodeBatch(batch)
		if err != nil {
			s.dropped.Add(int64(len(batch)))
			batch = batch[:0]
			return
		}
		n := len(batch)
		batch = batch[:0]
		if time.Now().Before(nextTry) || s.unauthorized.Load() {
			s.spool(gz, n)
			return
		}
		if err := s.send(gz, n); err != nil {
			s.spool(gz, n)
			backoff = nextBackoff(backoff)
			nextTry = time.Now().Add(backoff)
			return
		}
		backoff = 0
	}

	for {
		select {
		case <-ctx.Done():
			for {
				select {
				case ev := <-s.queue:
					batch = append(batch, ev)
					if len(batch) >= batchMax {
						s.spoolBatch(&batch)
					}
				default:
					s.spoolBatch(&batch)
					return
				}
			}
		case ev := <-s.queue:
			batch = append(batch, ev)
			if len(batch) >= batchMax {
				flush()
			}
		case <-ticker.C:
			flush()
			if time.Now().After(nextTry) && !s.unauthorized.Load() {
				if err := s.drainSpool(); err != nil {
					backoff = nextBackoff(backoff)
					nextTry = time.Now().Add(backoff)
				}
			}
		}
	}
}

func nextBackoff(d time.Duration) time.Duration {
	if d == 0 {
		return 5 * time.Second
	}
	d *= 2
	if d > 5*time.Minute {
		d = 5 * time.Minute
	}
	return d
}

func (s *Sender) send(gz []byte, n int) error {
	err := s.client.SendEvents(gz)
	if err == nil {
		s.sent.Add(int64(n))
		s.setError(nil)
		return nil
	}
	var ae *apiError
	if errors.As(err, &ae) && ae.Status == 400 {
		// vom Server abgelehnt – erneutes Senden hilft nicht
		s.dropped.Add(int64(n))
		s.setError(err)
		logf("Stapel mit %d Events abgelehnt: %v", n, err)
		return nil
	}
	if errors.Is(err, errUnauthorized) {
		s.unauthorized.Store(true)
	}
	s.setError(err)
	logf("Senden fehlgeschlagen, Events werden zwischengespeichert: %v", err)
	return err
}

func (s *Sender) spoolBatch(batch *[]Event) {
	if len(*batch) == 0 {
		return
	}
	if gz, err := encodeBatch(*batch); err == nil {
		s.spool(gz, len(*batch))
	}
	*batch = (*batch)[:0]
}

func (s *Sender) spool(gz []byte, n int) {
	if err := os.MkdirAll(s.spoolDir, 0o700); err != nil {
		s.dropped.Add(int64(n))
		return
	}
	name := filepath.Join(s.spoolDir, fmt.Sprintf("%020d-%d.json.gz", s.spoolStamp(), n))
	if err := os.WriteFile(name, gz, 0o600); err != nil {
		s.dropped.Add(int64(n))
		return
	}
	s.spooledEvents.Add(int64(n))
	s.trimSpool()
}

// spoolStamp liefert streng steigende Zeitstempel für die Dateinamen: Unter Windows
// schreitet die Uhr nur alle paar Millisekunden fort – zwei gleich große Stapel kurz
// hintereinander bekämen sonst denselben Namen und einer ginge verloren.
func (s *Sender) spoolStamp() int64 {
	for {
		last := s.lastSpool.Load()
		ts := time.Now().UnixNano()
		if ts <= last {
			ts = last + 1
		}
		if s.lastSpool.CompareAndSwap(last, ts) {
			return ts
		}
	}
}

func (s *Sender) spoolFiles() []string {
	entries, err := os.ReadDir(s.spoolDir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".gz" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names
}

func (s *Sender) spoolInfo() (int, int64) {
	var size int64
	names := s.spoolFiles()
	for _, n := range names {
		if fi, err := os.Stat(filepath.Join(s.spoolDir, n)); err == nil {
			size += fi.Size()
		}
	}
	return len(names), size
}

// trimSpool löscht die ältesten Pufferdateien, wenn das Limit überschritten ist.
func (s *Sender) trimSpool() {
	names := s.spoolFiles()
	var total int64
	sizes := make([]int64, len(names))
	for i, n := range names {
		if fi, err := os.Stat(filepath.Join(s.spoolDir, n)); err == nil {
			sizes[i] = fi.Size()
			total += fi.Size()
		}
	}
	for i := 0; total > spoolMaxBytes && i < len(names); i++ {
		var count int64
		_, _ = fmt.Sscanf(names[i][21:], "%d", &count)
		if os.Remove(filepath.Join(s.spoolDir, names[i])) == nil {
			total -= sizes[i]
			s.dropped.Add(count)
		}
	}
}

// drainSpool schickt gepufferte Stapel (älteste zuerst), solange das klappt.
func (s *Sender) drainSpool() error {
	for i, name := range s.spoolFiles() {
		if i >= 20 { // pro Durchlauf begrenzen, damit neue Events nicht warten
			return nil
		}
		path := filepath.Join(s.spoolDir, name)
		gz, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var n int
		_, _ = fmt.Sscanf(name[21:], "%d", &n)
		if err := s.send(gz, n); err != nil {
			return err
		}
		_ = os.Remove(path)
	}
	return nil
}
