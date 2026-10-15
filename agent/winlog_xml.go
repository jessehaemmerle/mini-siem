package main

// Plattformunabhängige Teile der Windows-Ereignisprotokoll-Erfassung:
// Abfrage (XPath) bauen und gerendertes Ereignis-XML übersetzen.

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	keywordAuditFailure = 0x10000000000000
	keywordAuditSuccess = 0x20000000000000
)

type winEventXML struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     string `xml:"EventID"`
		Level       int    `xml:"Level"`
		Task        int    `xml:"Task"`
		Keywords    string `xml:"Keywords"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		EventRecordID uint64 `xml:"EventRecordID"`
		Channel       string `xml:"Channel"`
		Computer      string `xml:"Computer"`
		Security      struct {
			UserID string `xml:"UserID,attr"`
		} `xml:"Security"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
	UserData struct {
		Inner []byte `xml:",innerxml"`
	} `xml:"UserData"`
}

// winQuery baut die XPath-Abfrage für einen Kanal: nur neue Datensätze, gewünschte
// Stufen und – falls angegeben – nur bestimmte Ereignis-IDs.
func winQuery(ch Channel, afterRecord uint64, sinceMillis int64) string {
	var cond []string
	if afterRecord > 0 {
		cond = append(cond, fmt.Sprintf("EventRecordID > %d", afterRecord))
	} else if sinceMillis > 0 {
		cond = append(cond, fmt.Sprintf("TimeCreated[timediff(@SystemTime) <= %d]", sinceMillis))
	}
	if ch.MaxLevel > 0 && ch.MaxLevel < 5 {
		cond = append(cond, fmt.Sprintf("(Level = 0 or Level <= %d)", ch.MaxLevel))
	}
	if len(ch.EventIDs) > 0 {
		parts := make([]string, 0, len(ch.EventIDs))
		for _, id := range ch.EventIDs {
			parts = append(parts, fmt.Sprintf("EventID = %d", id))
		}
		cond = append(cond, "("+strings.Join(parts, " or ")+")")
	}
	if len(cond) == 0 {
		return "*"
	}
	return "*[System[" + strings.Join(cond, " and ") + "]]"
}

// parseWinEventXML übersetzt ein gerendertes Ereignis in das Agent-Format.
// Ereignisse aus excludeIDs werden verworfen (nil).
func parseWinEventXML(raw []byte, excludeIDs map[int]bool) (Event, uint64, error) {
	var x winEventXML
	if err := xml.Unmarshal(raw, &x); err != nil {
		return nil, 0, err
	}
	sys := x.System
	id, _ := strconv.Atoi(strings.TrimSpace(sys.EventID))
	if excludeIDs[id] {
		return nil, sys.EventRecordID, nil
	}
	ev := Event{
		"src": "winlog", "channel": sys.Channel, "provider": sys.Provider.Name, "event_id": id,
		"level": sys.Level, "record_id": sys.EventRecordID, "computer": sys.Computer,
	}
	if sys.Task != 0 {
		ev["task"] = sys.Task
	}
	if t, err := time.Parse(time.RFC3339Nano, sys.TimeCreated.SystemTime); err == nil {
		ev["t"] = float64(t.UnixNano()) / 1e9
	} else {
		ev["t"] = nowUnix()
	}
	kw := strings.TrimSpace(sys.Keywords)
	if v, err := strconv.ParseUint(strings.TrimPrefix(kw, "0x"), 16, 64); err == nil {
		switch {
		case v&keywordAuditFailure != 0:
			kw += " Audit Failure"
		case v&keywordAuditSuccess != 0:
			kw += " Audit Success"
		}
	}
	ev["keywords"] = kw
	data := map[string]string{}
	for i, d := range x.EventData.Data {
		name := d.Name
		if name == "" {
			name = "param" + strconv.Itoa(i+1)
		}
		v := strings.TrimSpace(d.Value)
		if v != "" && v != "-" {
			data[name] = v
		}
	}
	if len(x.UserData.Inner) > 0 {
		for k, v := range leafValues(x.UserData.Inner) {
			if _, exists := data[k]; !exists {
				data[k] = v
			}
		}
	}
	if sys.Security.UserID != "" {
		data["UserSID"] = sys.Security.UserID
	}
	if len(data) > 0 {
		ev["data"] = data
	}
	return ev, sys.EventRecordID, nil
}

// leafValues sammelt alle Blatt-Elemente (Name → Text) aus UserData.
func leafValues(inner []byte) map[string]string {
	out := map[string]string{}
	dec := xml.NewDecoder(bytes.NewReader(inner))
	var stack []string
	var text strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return out
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
			text.Reset()
		case xml.CharData:
			text.Write(t)
		case xml.EndElement:
			if len(stack) > 0 {
				name := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if v := strings.TrimSpace(text.String()); v != "" && len(out) < 50 {
					out[name] = v
				}
				text.Reset()
			}
		}
	}
}
