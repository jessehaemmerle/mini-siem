//go:build windows

package main

// Liest Windows-Ereignisprotokolle über die Windows-API (wevtapi.dll).
// Je Kanal wird alle paar Sekunden nach Datensätzen mit höherer Record-ID gefragt;
// die zuletzt gelesene ID wird gespeichert.

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modwevtapi                   = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery                 = modwevtapi.NewProc("EvtQuery")
	procEvtNext                  = modwevtapi.NewProc("EvtNext")
	procEvtRender                = modwevtapi.NewProc("EvtRender")
	procEvtClose                 = modwevtapi.NewProc("EvtClose")
	procEvtFormatMessage         = modwevtapi.NewProc("EvtFormatMessage")
	procEvtOpenPublisherMetadata = modwevtapi.NewProc("EvtOpenPublisherMetadata")
)

const (
	evtQueryChannelPath      = 0x1
	evtQueryForwardDirection = 0x100
	evtQueryReverseDirection = 0x200
	evtRenderEventXML        = 1
	evtFormatMessageEvent    = 1

	errNoMoreItems         = syscall.Errno(259)
	errInsufficientBuffer  = syscall.Errno(122)
	errChannelNotFound     = syscall.Errno(15007)
	errEvtQueryResultStale = syscall.Errno(15011)
)

type evtHandle uintptr

func evtClose(h evtHandle) {
	if h != 0 {
		procEvtClose.Call(uintptr(h))
	}
}

func evtQuery(channel, query string) (evtHandle, error) {
	return evtQueryFlags(channel, query, evtQueryChannelPath|evtQueryForwardDirection)
}

func evtQueryFlags(channel, query string, flags uintptr) (evtHandle, error) {
	p, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return 0, err
	}
	q, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return 0, err
	}
	r, _, e := procEvtQuery.Call(0, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(q)), flags)
	if r == 0 {
		return 0, e
	}
	return evtHandle(r), nil
}

func evtNext(rs evtHandle, out []evtHandle) (int, error) {
	var returned uint32
	r, _, e := procEvtNext.Call(uintptr(rs), uintptr(len(out)), uintptr(unsafe.Pointer(&out[0])), 1000, 0,
		uintptr(unsafe.Pointer(&returned)))
	if r == 0 {
		if errors.Is(e, errNoMoreItems) {
			return 0, nil
		}
		return 0, e
	}
	return int(returned), nil
}

func evtRenderXML(h evtHandle, buf []byte) ([]byte, []byte, error) {
	for {
		var used, props uint32
		var ptr uintptr
		if len(buf) > 0 {
			ptr = uintptr(unsafe.Pointer(&buf[0]))
		}
		r, _, e := procEvtRender.Call(0, uintptr(h), evtRenderEventXML, uintptr(len(buf)), ptr,
			uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
		if r != 0 {
			return utf16BytesToUTF8(buf[:used]), buf, nil
		}
		if errors.Is(e, errInsufficientBuffer) {
			buf = make([]byte, used+64)
			continue
		}
		return nil, buf, e
	}
}

func utf16BytesToUTF8(b []byte) []byte {
	if len(b) < 2 {
		return nil
	}
	u := unsafe.Slice((*uint16)(unsafe.Pointer(&b[0])), len(b)/2)
	for len(u) > 0 && u[len(u)-1] == 0 {
		u = u[:len(u)-1]
	}
	return []byte(windows.UTF16ToString(u))
}

// Nachrichtentexte: je Anbieter einmal die Metadaten öffnen.
type publisherCache struct {
	mu      sync.Mutex
	handles map[string]evtHandle
}

func (pc *publisherCache) get(provider string) evtHandle {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if h, ok := pc.handles[provider]; ok {
		return h
	}
	var h evtHandle
	if p, err := windows.UTF16PtrFromString(provider); err == nil {
		r, _, _ := procEvtOpenPublisherMetadata.Call(0, uintptr(unsafe.Pointer(p)), 0, 0, 0)
		h = evtHandle(r)
	}
	pc.handles[provider] = h // auch 0 merken, damit nicht ständig erneut versucht wird
	return h
}

func (pc *publisherCache) close() {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	for _, h := range pc.handles {
		evtClose(h)
	}
	pc.handles = map[string]evtHandle{}
}

func formatMessage(meta, ev evtHandle) string {
	if meta == 0 {
		return ""
	}
	buf := make([]uint16, 2048)
	for {
		var used uint32
		r, _, e := procEvtFormatMessage.Call(uintptr(meta), uintptr(ev), 0, 0, 0, evtFormatMessageEvent,
			uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)))
		if r != 0 {
			return windows.UTF16ToString(buf[:used])
		}
		if errors.Is(e, errInsufficientBuffer) && used > uint32(len(buf)) && used < 1<<20 {
			buf = make([]uint16, used)
			continue
		}
		return ""
	}
}

// latestRecordID liefert die Record-ID des neuesten Ereignisses eines Kanals (0 = leer).
func latestRecordID(channel string) (uint64, error) {
	rs, err := evtQueryFlags(channel, "*", evtQueryChannelPath|evtQueryReverseDirection)
	if err != nil {
		return 0, err
	}
	defer evtClose(rs)
	handles := make([]evtHandle, 1)
	n, err := evtNext(rs, handles)
	if err != nil || n == 0 {
		return 0, err
	}
	defer evtClose(handles[0])
	raw, _, err := evtRenderXML(handles[0], make([]byte, 8<<10))
	if err != nil {
		return 0, err
	}
	_, rid, err := parseWinEventXML(raw, nil)
	return rid, err
}

type winlogCollector struct {
	channels []Channel
	state    *State
	emit     func(Event) bool
	pubs     publisherCache
	checked  map[string]time.Time // letzte Prüfung, ob ein Kanal geleert wurde

	mu      sync.Mutex
	missing []string
}

func newWinlogCollector(cfg *CentralConfig, state *State, emit func(Event) bool) *winlogCollector {
	return &winlogCollector{channels: cfg.Windows.Channels, state: state, emit: emit,
		pubs: publisherCache{handles: map[string]evtHandle{}}, checked: map[string]time.Time{}}
}

func (c *winlogCollector) Name() string { return "Windows-Ereignisprotokolle" }

func (c *winlogCollector) Missing() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.missing...)
}

func (c *winlogCollector) Run(ctx context.Context) error {
	if err := modwevtapi.Load(); err != nil {
		return fmt.Errorf("wevtapi.dll nicht verfügbar: %w", err)
	}
	defer c.pubs.close()
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	retryMissing := time.Now()
	missing := map[string]bool{}
	for {
		for _, ch := range c.channels {
			if ctx.Err() != nil {
				return nil
			}
			if missing[ch.Name] && time.Now().Before(retryMissing) {
				continue
			}
			err := c.readChannel(ctx, ch)
			switch {
			case errors.Is(err, errChannelNotFound):
				missing[ch.Name] = true
			case err != nil:
				logf("Ereignisprotokoll %s: %v", ch.Name, err)
			default:
				delete(missing, ch.Name)
			}
		}
		if time.Now().After(retryMissing) {
			retryMissing = time.Now().Add(5 * time.Minute)
		}
		c.mu.Lock()
		c.missing = c.missing[:0]
		for name := range missing {
			c.missing = append(c.missing, name)
		}
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (c *winlogCollector) readChannel(ctx context.Context, ch Channel) error {
	key := "winlog." + ch.Name
	last, _ := strconv.ParseUint(c.state.Get(key), 10, 64)
	query := winQuery(ch, last, 10*60*1000) // beim ersten Mal: die letzten 10 Minuten
	rs, err := evtQuery(ch.Name, query)
	if err != nil {
		return err
	}
	defer evtClose(rs)
	exclude := map[int]bool{}
	for _, id := range ch.ExcludeIDs {
		exclude[id] = true
	}
	handles := make([]evtHandle, 64)
	buf := make([]byte, 16<<10)
	read := 0
	for {
		n, err := evtNext(rs, handles)
		if err != nil {
			if errors.Is(err, errEvtQueryResultStale) {
				return nil
			}
			return err
		}
		if n == 0 {
			if read == 0 && last > 0 {
				c.checkCleared(ch.Name, key, last)
			}
			return nil
		}
		read += n
		for i := 0; i < n; i++ {
			h := handles[i]
			var raw []byte
			raw, buf, err = evtRenderXML(h, buf)
			if err == nil {
				ev, rid, perr := parseWinEventXML(raw, exclude)
				if perr == nil && ev != nil {
					if msg := formatMessage(c.pubs.get(fmt.Sprint(ev["provider"])), h); msg != "" {
						if len(msg) > 8192 {
							msg = msg[:8192]
						}
						ev["msg"] = msg
					}
					if !c.emit(ev) {
						evtCloseRest(handles[i:n])
						return nil
					}
				}
				if rid > last {
					last = rid
					c.state.Set(key, strconv.FormatUint(last, 10))
				}
			}
			evtClose(h)
		}
		if ctx.Err() != nil {
			return nil
		}
	}
}

func evtCloseRest(hs []evtHandle) {
	for _, h := range hs {
		evtClose(h)
	}
}

// checkCleared erkennt ein geleertes Protokoll: Windows beginnt danach wieder bei
// Record-ID 1, die Abfrage „größer als die letzte ID“ fände nichts mehr – auch nicht
// das Ereignis 1102 „Protokoll gelöscht“. Dann wird wieder ab Beginn gelesen.
func (c *winlogCollector) checkCleared(channel, key string, last uint64) {
	if time.Since(c.checked[channel]) < 30*time.Second {
		return
	}
	c.checked[channel] = time.Now()
	latest, err := latestRecordID(channel)
	if err != nil || latest >= last {
		return
	}
	logf("Ereignisprotokoll %s wurde geleert (neueste Record-ID %d < %d) – lese neu ab Beginn", channel, latest, last)
	c.state.Set(key, "0")
}
