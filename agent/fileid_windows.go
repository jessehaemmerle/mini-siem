//go:build windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// fileIdentity erkennt, ob unter demselben Pfad inzwischen eine andere Datei liegt (Rotation).
// Volume-Seriennummer und Dateiindex statt Erstellungszeit: NTFS übernimmt die
// Erstellungszeit für eine Datei, die kurz nach dem Umbenennen gleichnamig neu entsteht
// („File System Tunneling“).
func fileIdentity(f *os.File, _ os.FileInfo) string {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
		return ""
	}
	return fmt.Sprintf("%x:%x:%x", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow)
}

// openShared öffnet eine Logdatei so, dass die schreibende Anwendung sie währenddessen
// weiterhin umbenennen oder löschen kann (Logrotation).
func openShared(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}
