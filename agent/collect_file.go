package main

// Liest neue Zeilen aus Logdateien (wie "tail -F"), auch über Logrotation hinweg.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const maxLineBytes = 64 << 10

type fileCollector struct {
	patterns []string
	state    *State
	emit     func(Event) bool
}

type tailPos struct {
	offset int64
	ident  string
}

func (p tailPos) String() string { return fmt.Sprintf("%d|%s", p.offset, p.ident) }

func parseTailPos(s string) (tailPos, bool) {
	off, ident, ok := strings.Cut(s, "|")
	if !ok {
		return tailPos{}, false
	}
	n, err := strconv.ParseInt(off, 10, 64)
	if err != nil {
		return tailPos{}, false
	}
	return tailPos{offset: n, ident: ident}, true
}

func (c *fileCollector) Name() string { return "Dateien" }

func (c *fileCollector) Run(ctx context.Context) error {
	first := true
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		seen := map[string]bool{}
		for _, pattern := range c.patterns {
			matches, err := filepath.Glob(pattern)
			if err != nil {
				return fmt.Errorf("ungültiges Muster %q: %w", pattern, err)
			}
			for _, path := range matches {
				if seen[path] {
					continue
				}
				seen[path] = true
				if err := c.readFile(ctx, path, first); err != nil && ctx.Err() == nil {
					logf("Datei %s: %v", path, err)
				}
			}
		}
		first = false
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// readFile liest ab der gespeicherten Position bis zum Dateiende. Eine noch
// unvollständige letzte Zeile wird beim nächsten Durchlauf erneut gelesen.
func (c *fileCollector) readFile(ctx context.Context, path string, initial bool) error {
	f, err := openShared(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.IsDir() {
		return err
	}
	key := "file:" + path
	ident := fileIdentity(f, fi)
	pos, known := parseTailPos(c.state.Get(key))
	switch {
	case !known && initial:
		// Beim ersten Start nur neue Zeilen lesen
		c.state.Set(key, tailPos{offset: fi.Size(), ident: ident}.String())
		return nil
	case !known:
		pos = tailPos{offset: 0, ident: ident} // neu entstandene Datei (z. B. nach Rotation)
	case pos.ident != ident || fi.Size() < pos.offset:
		pos = tailPos{offset: 0, ident: ident} // rotiert oder gekürzt
	}
	if fi.Size() == pos.offset {
		c.state.Set(key, pos.String())
		return nil
	}
	if _, err := f.Seek(pos.offset, io.SeekStart); err != nil {
		return err
	}
	consumed := pos.offset
	buf := make([]byte, 256<<10)
	var carry []byte
	for {
		n, err := f.Read(buf)
		if n > 0 {
			data := append(carry, buf[:n]...)
			for {
				i := bytes.IndexByte(data, '\n')
				if i < 0 {
					break
				}
				line := strings.TrimRight(string(data[:i]), "\r")
				if strings.TrimSpace(line) != "" {
					if len(line) > maxLineBytes {
						line = line[:maxLineBytes]
					}
					if !c.emit(Event{"src": "file", "t": nowUnix(), "path": path, "msg": line}) {
						return nil
					}
				}
				consumed += int64(i + 1)
				data = data[i+1:]
			}
			if len(data) > maxLineBytes { // überlange Zeile ohne Ende verwerfen
				consumed += int64(len(data))
				data = nil
			}
			carry = append([]byte(nil), data...)
			c.state.Set(key, tailPos{offset: consumed, ident: ident}.String())
		}
		if err == io.EOF || n == 0 {
			return nil
		}
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
	}
}

func nowUnix() float64 { return float64(time.Now().UnixNano()) / 1e9 }
