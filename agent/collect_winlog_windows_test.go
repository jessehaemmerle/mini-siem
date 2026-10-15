//go:build windows

package main

// Diese Tests greifen auf die echten Ereignisprotokolle zu und laufen daher nur
// unter Windows (in der CI auf einem GitHub-Windows-Runner mit Administratorrechten).

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWinlogReadSystemChannel(t *testing.T) {
	rs, err := evtQuery("System", "*")
	if err != nil {
		t.Fatalf("EvtQuery: %v", err)
	}
	defer evtClose(rs)
	handles := make([]evtHandle, 5)
	n, err := evtNext(rs, handles)
	if err != nil || n == 0 {
		t.Fatalf("EvtNext: n=%d err=%v", n, err)
	}
	pubs := publisherCache{handles: map[string]evtHandle{}}
	defer pubs.close()
	buf := make([]byte, 1024) // absichtlich klein: Vergrößern des Puffers mittesten
	var maxRID uint64
	messages := 0
	for _, h := range handles[:n] {
		raw, b, err := evtRenderXML(h, buf)
		buf = b
		if err != nil {
			t.Fatalf("EvtRender: %v", err)
		}
		ev, rid, err := parseWinEventXML(raw, nil)
		if err != nil || ev == nil {
			t.Fatalf("XML: %v\n%s", err, raw)
		}
		if ev["channel"] != "System" || rid == 0 {
			t.Errorf("unerwartet: %v (Record %d)", ev, rid)
		}
		if formatMessage(pubs.get(fmt.Sprint(ev["provider"])), h) != "" {
			messages++
		}
		if rid > maxRID {
			maxRID = rid
		}
		evtClose(h)
	}
	if messages == 0 {
		t.Error("für keines der Ereignisse wurde ein Meldungstext erzeugt")
	}
	latest, err := latestRecordID("System")
	if err != nil || latest < maxRID {
		t.Errorf("latestRecordID = %d, %v (erwartet ≥ %d)", latest, err, maxRID)
	}
}

func TestWinlogMissingChannel(t *testing.T) {
	_, err := evtQuery("Gibt-Es-Nicht/Operational", "*")
	if !errors.Is(err, errChannelNotFound) {
		t.Fatalf("erwartet errChannelNotFound, bekommen %v", err)
	}
}

func TestWinlogCollectorPicksUpNewEvent(t *testing.T) {
	marker := fmt.Sprintf("Mini-SIEM-Test %d", time.Now().UnixNano())
	st := &State{path: filepath.Join(t.TempDir(), "state.json"), data: map[string]string{}}
	var mu sync.Mutex
	var got []Event
	cfg := &CentralConfig{}
	cfg.Windows.Channels = []Channel{{Name: "Application", MaxLevel: 4}, {Name: "Gibt-Es-Nicht/Operational", MaxLevel: 4}}
	c := newWinlogCollector(cfg, st, func(e Event) bool {
		mu.Lock()
		got = append(got, e)
		mu.Unlock()
		return true
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	time.Sleep(2 * time.Second)

	out, err := exec.Command("eventcreate", "/T", "WARNING", "/ID", "777", "/L", "APPLICATION",
		"/SO", "MiniSIEMTest", "/D", marker).CombinedOutput()
	if err != nil {
		t.Fatalf("eventcreate: %v: %s", err, out)
	}
	deadline := time.Now().Add(20 * time.Second)
	var found Event
	for time.Now().Before(deadline) && found == nil {
		time.Sleep(time.Second)
		mu.Lock()
		for _, e := range got {
			if e["event_id"] == 777 && strings.Contains(fmt.Sprint(e["msg"]), marker) {
				found = e
			}
		}
		mu.Unlock()
	}
	cancel()
	<-done
	if found == nil {
		t.Fatalf("Ereignis 777 mit %q nicht erfasst (%d andere Ereignisse)", marker, len(got))
	}
	if found["channel"] != "Application" || found["level"] != 3 {
		t.Errorf("Felder: %v", found)
	}
	if st.Get("winlog.Application") == "" {
		t.Error("Record-ID wurde nicht gespeichert")
	}
	if m := c.Missing(); len(m) != 1 || m[0] != "Gibt-Es-Nicht/Operational" {
		t.Errorf("Missing() = %v", m)
	}
}
