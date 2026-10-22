package platform

import (
	"context"
	"encoding/json"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"onetunnel/core/internal/control"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"
)

func TestLiveInstalledService(t *testing.T) {
	root := os.Getenv("ONETUNNEL_INSTALLED_WATCHDIR")
	if root == "" {
		t.Skip("explicit independent SYSTEM watchdog required")
	}
	if !exists(filepath.Join(root, "watch-ready")) {
		t.Fatal("SYSTEM recovery guard unavailable")
	}
	b, err := os.ReadFile(filepath.Join(root, "profiles-machine.bin"))
	if err != nil {
		t.Fatal("protected profiles missing")
	}
	in := windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
	var out windows.DataBlob
	if windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out) != nil {
		t.Fatal("protected profiles inaccessible")
	}
	plain := unsafe.Slice(out.Data, out.Size)
	var profiles []control.Profile
	err = json.Unmarshal(plain, &profiles)
	clear(plain)
	windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	if err != nil {
		t.Fatal("protected profiles invalid")
	}
	call := func(request control.Request) (control.Response, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		pipe, e := winio.DialPipeContext(ctx, control.PipeName)
		if e != nil {
			return control.Response{}, e
		}
		defer pipe.Close()
		pipe.SetDeadline(time.Now().Add(38 * time.Second))
		if e = control.WriteFrame(pipe, request); e != nil {
			return control.Response{}, e
		}
		return control.ReadFrame[control.Response](pipe)
	}
	clean := func() bool {
		response, e := call(control.Request{Version: 1, Command: "status"})
		return e == nil && response.Error == nil && !response.State.Active && !response.State.NeedsRecovery && !response.State.TrafficLocked
	}
	if !clean() {
		t.Fatal("installed service must be idle")
	}
	physical, err := routeInterface("1.1.1.1")
	if err != nil {
		t.Fatal("baseline unavailable")
	}
	type result struct {
		Index, Protocol         int
		Started, HTTPS, Cleanup bool
	}
	results := []result{}
	for _, text := range strings.Split(os.Getenv("ONETUNNEL_INSTALLED_INDICES"), ",") {
		index, e := strconv.Atoi(text)
		if e != nil || index < 0 || index >= len(profiles) {
			t.Fatal("invalid selected index")
		}
		expiry := time.Now().UTC().Add(75*time.Second).UnixNano()/100 + 621355968000000000
		if os.WriteFile(filepath.Join(root, "watch-armed"), []byte(strconv.FormatInt(expiry, 10)), 0600) != nil {
			t.Fatal("guard arming failed")
		}
		row := result{Index: index, Protocol: profiles[index].Protocol}
		response, e := call(control.Request{Version: 1, Command: "start", Profile: &profiles[index], FullDevice: true})
		row.Started = e == nil && response.Error == nil && response.State.Active && response.State.TrafficLocked
		if row.Started {
			ctx, cancel := context.WithTimeout(context.Background(), 17*time.Second)
			row.HTTPS = httpsCheck(ctx, 0) == nil
			cancel()
		}
		_, _ = call(control.Request{Version: 1, Command: "stop"})
		after, e := routeInterface("1.1.1.1")
		ctx, cancel := context.WithTimeout(context.Background(), 17*time.Second)
		row.Cleanup = clean() && e == nil && after == physical && httpsCheck(ctx, 0) == nil
		cancel()
		results = append(results, row)
		data, _ := json.MarshalIndent(results, "", "  ")
		os.WriteFile(filepath.Join(root, "installed-results.json"), data, 0600)
		t.Logf("installed profile %d protocol %d: start=%v https=%v cleanup=%v", index, row.Protocol, row.Started, row.HTTPS, row.Cleanup)
		if !row.Cleanup {
			t.Fatal("cleanup incomplete; SYSTEM guard remains armed")
		}
		if os.Remove(filepath.Join(root, "watch-armed")) != nil {
			t.Fatal("guard disarming failed")
		}
		if !row.Started || !row.HTTPS {
			t.Error("installed connection failed")
		}
	}
}
