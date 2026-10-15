package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const sample4625 = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>
<Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
<EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode>
<Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2026-10-15T08:00:01.1234567Z'/>
<EventRecordID>48211</EventRecordID><Correlation/><Execution ProcessID='668' ThreadID='712'/>
<Channel>Security</Channel><Computer>DC01.firma.local</Computer><Security/></System>
<EventData><Data Name='SubjectUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>j.mueller</Data>
<Data Name='TargetDomainName'>FIRMA</Data><Data Name='LogonType'>3</Data><Data Name='IpAddress'>10.1.2.3</Data>
<Data Name='WorkstationName'>-</Data></EventData></Event>`

const sample1102 = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>
<Provider Name='Microsoft-Windows-Eventlog'/><EventID>1102</EventID><Level>4</Level>
<Keywords>0x4020000000000000</Keywords><TimeCreated SystemTime='2026-10-15T08:00:02Z'/>
<EventRecordID>48212</EventRecordID><Channel>Security</Channel><Computer>DC01</Computer>
<Security UserID='S-1-5-21-1'/></System><UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>
<SubjectUserSid>S-1-5-21-1</SubjectUserSid><SubjectUserName>admin.x</SubjectUserName></LogFileCleared></UserData></Event>`

func TestParseWinEventXML(t *testing.T) {
	ev, rid, err := parseWinEventXML([]byte(sample4625), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rid != 48211 || ev["event_id"] != 4625 || ev["computer"] != "DC01.firma.local" {
		t.Fatalf("unerwartet: %v %v", rid, ev)
	}
	if !strings.Contains(ev["keywords"].(string), "Audit Failure") {
		t.Errorf("Audit Failure fehlt: %v", ev["keywords"])
	}
	data := ev["data"].(map[string]string)
	if data["TargetUserName"] != "j.mueller" || data["IpAddress"] != "10.1.2.3" {
		t.Errorf("EventData: %v", data)
	}
	if _, ok := data["WorkstationName"]; ok {
		t.Error("'-' sollte weggelassen werden")
	}
	if ts := ev["t"].(float64); ts < 1.7e9 {
		t.Errorf("Zeit: %v", ts)
	}

	ev, _, err = parseWinEventXML([]byte(sample1102), nil)
	if err != nil {
		t.Fatal(err)
	}
	d := ev["data"].(map[string]string)
	if d["SubjectUserName"] != "admin.x" || d["UserSID"] != "S-1-5-21-1" {
		t.Errorf("UserData: %v", d)
	}
	if !strings.Contains(ev["keywords"].(string), "Audit Success") {
		t.Errorf("Audit Success fehlt: %v", ev["keywords"])
	}

	ev, rid, _ = parseWinEventXML([]byte(sample4625), map[int]bool{4625: true})
	if ev != nil || rid != 48211 {
		t.Error("ausgeschlossene ID muss verworfen, Record-ID aber gemeldet werden")
	}
}

func TestWinQuery(t *testing.T) {
	q := winQuery(Channel{Name: "Security", MaxLevel: 5}, 100, 0)
	if q != "*[System[EventRecordID > 100]]" {
		t.Errorf("q = %s", q)
	}
	q = winQuery(Channel{Name: "PS", MaxLevel: 3, EventIDs: []int{4104, 4103}}, 0, 600000)
	want := "*[System[TimeCreated[timediff(@SystemTime) <= 600000] and (Level = 0 or Level <= 3) and (EventID = 4104 or EventID = 4103)]]"
	if q != want {
		t.Errorf("q = %s", q)
	}
}

func frame(stream byte, payload string) []byte {
	h := make([]byte, 8)
	h[0] = stream
	binary.BigEndian.PutUint32(h[4:], uint32(len(payload)))
	return append(h, payload...)
}

func TestDemuxDockerStream(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(frame(1, "2026-10-15T08:00:00.1Z hallo\n2026-10-15T08:00:00.2Z zwei"))
	buf.Write(frame(2, "2026-10-15T08:00:00.3Z fehler\n"))
	buf.Write(frame(1, "teile\n"))
	var got []string
	err := demuxDockerStream(&buf, func(stream, line string) bool {
		got = append(got, stream+"|"+line)
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"stdout|2026-10-15T08:00:00.1Z hallo", "stderr|2026-10-15T08:00:00.3Z fehler",
		"stdout|2026-10-15T08:00:00.2Z zweiteile"}
	if strings.Join(got, ";") != strings.Join(want, ";") {
		t.Errorf("got %v", got)
	}
}

func TestFileCollectorRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	if err := os.WriteFile(path, []byte("alt 1\nalt 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := &State{path: filepath.Join(dir, "state.json"), data: map[string]string{}}
	var mu sync.Mutex
	var lines []string
	c := &fileCollector{patterns: []string{filepath.Join(dir, "*.log")}, state: st, emit: func(e Event) bool {
		mu.Lock()
		lines = append(lines, e["msg"].(string))
		mu.Unlock()
		return true
	}}
	ctx := context.Background()
	if err := c.readFile(ctx, path, true); err != nil { // erster Start: nur neue Zeilen
		t.Fatal(err)
	}
	appendFile(t, path, "neu 1\nhalbe ")
	_ = c.readFile(ctx, path, false)
	appendFile(t, path, "Zeile\n")
	_ = c.readFile(ctx, path, false)
	// Rotation: Datei wird ersetzt
	_ = os.Rename(path, path+".1")
	if err := os.WriteFile(path, []byte("nach rotation\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = c.readFile(ctx, path, false)
	want := "neu 1|halbe Zeile|nach rotation"
	if got := strings.Join(lines, "|"); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func appendFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_, _ = f.WriteString(s)
}

func TestSenderSpoolAndDrain(t *testing.T) {
	dir := t.TempDir()
	s := &Sender{spoolDir: dir, queue: make(chan Event, 10)}
	gz, err := encodeBatch([]Event{{"msg": "a"}, {"msg": "b"}})
	if err != nil {
		t.Fatal(err)
	}
	// ohne Pause: gleich große Stapel dürfen sich nicht überschreiben
	s.spool(gz, 2)
	s.spool(gz, 2)
	s.spool(gz, 2)
	files, size := s.spoolInfo()
	if files != 3 || size == 0 {
		t.Fatalf("Puffer: %d Dateien, %d Bytes", files, size)
	}
	names := s.spoolFiles()
	if names[0] >= names[1] {
		t.Error("Pufferdateien müssen zeitlich sortiert sein")
	}
}

func TestSingleInstanceLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.lock")
	unlock, err := acquireLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquireLock(path); err != errAlreadyRunning {
		t.Fatalf("zweiter Start: %v", err)
	}
	unlock()
	unlock2, err := acquireLock(path)
	if err != nil {
		t.Fatalf("nach Freigabe: %v", err)
	}
	unlock2()
}
