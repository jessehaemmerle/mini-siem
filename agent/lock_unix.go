//go:build !windows

package main

import (
	"os"
	"syscall"
)

// acquireLock verhindert, dass zwei Agenten gleichzeitig laufen (z. B. Dienst und
// „mini-siem-agent run“ von Hand) und sich Zustand und Puffer teilen.
func acquireLock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errAlreadyRunning
	}
	return func() { f.Close() }, nil
}
