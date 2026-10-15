// Mini-SIEM Agent – sammelt Ereignisse auf Windows- und Linux-Rechnern
// (Ereignisprotokolle, systemd-Journal, Logdateien, Docker) und schickt sie an das Mini-SIEM.
//
//	mini-siem-agent install --server URL --key SCHLÜSSEL [--insecure]
//	mini-siem-agent status
//	mini-siem-agent uninstall
//	mini-siem-agent run        (wird vom Dienst aufgerufen)
//	mini-siem-agent version
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

// version wird beim Bauen gesetzt (-ldflags "-X main.version=…").
var version = "dev"

func logf(format string, args ...any) { log.Printf(format, args...) }

func usage() {
	fmt.Fprint(os.Stderr, `Mini-SIEM Agent `+version+`

Verwendung:
  mini-siem-agent install --server https://siem.firma.local --key <Registrierungsschlüssel> [--insecure]
      registriert den Rechner beim SIEM und richtet den Dienst ein
  mini-siem-agent status      zeigt Konfiguration und Dienststatus
  mini-siem-agent uninstall   entfernt Dienst und Konfiguration
  mini-siem-agent run         startet den Agenten im Vordergrund (sonst macht das der Dienst)
  mini-siem-agent version     zeigt die Version
`)
}

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		os.Exit(runMain())
	case "install":
		os.Exit(installCmd(os.Args[2:]))
	case "uninstall":
		os.Exit(uninstallCmd())
	case "status":
		os.Exit(statusCmd())
	case "version", "--version", "-v":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
}

func installCmd(args []string) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	server := fs.String("server", "", "Adresse des SIEM, z. B. https://siem.firma.local")
	key := fs.String("key", "", "Registrierungsschlüssel aus der SIEM-Oberfläche (Quellen → Agenten)")
	insecure := fs.Bool("insecure", false, "Zertifikat des SIEM nicht prüfen (nur für Tests)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *server == "" || *key == "" {
		fmt.Fprintln(os.Stderr, "Bitte --server und --key angeben.")
		return 2
	}
	if err := requireAdmin(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	srv := strings.TrimRight(*server, "/")
	info := systemInfo()
	fmt.Printf("Registriere %s (%s %s) bei %s …\n", info.Hostname, info.OS, info.Arch, srv)
	resp, err := newClient(srv, "", *insecure).Enroll(*key, info)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Registrierung fehlgeschlagen: %v\n", err)
		return 1
	}
	cfg := &LocalConfig{Server: srv, Token: resp.Token, AgentID: resp.AgentID, Insecure: *insecure, Hostname: resp.Hostname}
	if err := saveLocalConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Konfiguration kann nicht gespeichert werden: %v\n", err)
		return 1
	}
	if err := installService(); err != nil {
		fmt.Fprintf(os.Stderr, "Dienst konnte nicht eingerichtet werden: %v\n", err)
		return 1
	}
	fmt.Printf("Fertig. Der Agent läuft als Dienst \"mini-siem-agent\" und erscheint im SIEM unter Quellen → Agenten.\n")
	return 0
}

func uninstallCmd() int {
	if err := requireAdmin(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := uninstallService(); err != nil {
		fmt.Fprintf(os.Stderr, "Dienst konnte nicht entfernt werden: %v\n", err)
	}
	_ = os.RemoveAll(stateDir())
	_ = os.Remove(configPath())
	_ = os.Remove(cachedConfigPath())
	removeInstalledFiles()
	fmt.Println("Der Agent wurde entfernt. Im SIEM kann er unter Quellen → Agenten gelöscht werden.")
	return 0
}

func statusCmd() int {
	fmt.Printf("Version:      %s\n", version)
	fmt.Printf("Konfiguration: %s\n", configPath())
	cfg, err := loadLocalConfig()
	if err != nil {
		fmt.Printf("Status:       %v\n", err)
		return 1
	}
	fmt.Printf("SIEM:         %s\n", cfg.Server)
	fmt.Printf("Agent-Nr.:    %d (%s)\n", cfg.AgentID, cfg.Hostname)
	fmt.Printf("Dienst:       %s\n", serviceStatus())
	files, size := newSender(nil).spoolInfo()
	if files > 0 {
		fmt.Printf("Puffer:       %d Datei(en), %.1f MB noch nicht gesendet\n", files, float64(size)/1048576)
	}
	return 0
}
