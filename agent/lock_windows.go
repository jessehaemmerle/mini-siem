//go:build windows

package main

import (
	"errors"

	"golang.org/x/sys/windows"
)

// acquireLock verhindert, dass zwei Agenten gleichzeitig laufen (z. B. Dienst und
// „mini-siem-agent run“ von Hand) und sich Zustand und Puffer teilen.
func acquireLock(path string) (func(), error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// Freigabemodus 0: solange die Datei offen ist, kann sie niemand sonst öffnen
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
		windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return nil, errAlreadyRunning
		}
		return nil, err
	}
	return func() { windows.CloseHandle(h) }, nil
}
