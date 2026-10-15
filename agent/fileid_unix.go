//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

// fileIdentity erkennt, ob unter demselben Pfad inzwischen eine andere Datei liegt (Rotation).
func fileIdentity(_ *os.File, fi os.FileInfo) string {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d:%d", st.Dev, st.Ino)
	}
	return ""
}

func openShared(path string) (*os.File, error) { return os.Open(path) }
