package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/NikolaBasser/OneTunnel-Core/internal/platform"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func main() {
	scan := flag.Bool("scan", false, "list OneTunnel WFP providers without changing networking (default)")
	all := flag.Bool("recover-all", false, "remove all validated OneTunnel persistent WFP objects")
	provider := flag.String("provider", "", "recover only this OneTunnel provider GUID")
	stop := flag.Bool("stop-service", false, "stop OneTunnelCore before recovery")
	flag.Parse()
	if flag.NArg() != 0 || *all && *provider != "" || *scan && (*all || *provider != "" || *stop) || *stop && !*all && *provider == "" {
		fmt.Fprintln(os.Stderr, "Invalid options. Use --scan or --recover-all --stop-service.")
		os.Exit(2)
	}
	if *provider != "" {
		key, err := windows.GUIDFromString(*provider)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Invalid provider GUID; no changes made.")
			os.Exit(2)
		}
		*provider = key.String()
	}
	if (*all || *provider != "" || *stop) && !windows.GetCurrentProcessToken().IsElevated() {
		fmt.Fprintln(os.Stderr, "Recovery requires Run as administrator.")
		os.Exit(3)
	}
	if *all || *provider != "" {
		if err := ensureCoreStopped(*stop); err != nil {
			fail(err)
		}
	}
	entries, err := platform.EmergencyWFPInventory()
	if err != nil {
		fail(err)
	}
	if !*all && *provider == "" {
		if err = json.NewEncoder(os.Stdout).Encode(entries); err != nil {
			fail(err)
		}
		return
	}
	if *provider != "" {
		if err = platform.RecoverEmergencyWFPProvider(*provider); err != nil {
			fail(err)
		}
	} else {
		for _, entry := range entries {
			if !entry.Recoverable {
				fail(fmt.Errorf("provider %s refused: %s", entry.GUID, entry.Reason))
			}
		}
		if err = platform.RecoverAllEmergencyWFP(); err != nil {
			fail(err)
		}
		for _, entry := range entries {
			fmt.Println("Removed OneTunnel WFP provider", entry.GUID)
		}
	}
	remaining, err := platform.EmergencyWFPInventory()
	if err != nil {
		fail(err)
	}
	if *all && len(remaining) != 0 {
		fail(fmt.Errorf("%d providers remain", len(remaining)))
	}
	for _, entry := range remaining {
		if entry.GUID == *provider {
			fail(fmt.Errorf("selected provider remains after recovery"))
		}
	}
	fmt.Printf("Recovery complete. No internet connection was used. Remaining OneTunnel providers: %d.\n", len(remaining))
}

func fail(err error) { fmt.Fprintln(os.Stderr, "Recovery failed:", err); os.Exit(1) }

func ensureCoreStopped(allowStop bool) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService("OneTunnelCore")
	if err == windows.ERROR_SERVICE_DOES_NOT_EXIST {
		return nil
	}
	if err != nil {
		return err
	}
	defer s.Close()
	status, err := s.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Stopped {
		return nil
	}
	if !allowStop {
		return fmt.Errorf("OneTunnelCore is running; use --stop-service before removing protection")
	}
	if status.State != svc.StopPending {
		if _, err = s.Control(svc.Stop); err != nil && err != windows.ERROR_SERVICE_NOT_ACTIVE {
			return err
		}
	}
	// Match the service's advertised drain/recovery window before touching WFP.
	deadline := time.Now().Add(420 * time.Second)
	for time.Now().Before(deadline) {
		status, err = s.Query()
		if err != nil {
			return err
		}
		if status.State == svc.Stopped {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("OneTunnelCore did not stop within 420 seconds; no filters removed")
}
