//go:build windows && onetunnel_network_live_acceptance

package profiles

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
	"github.com/NikolaBasser/OneTunnel-Core/internal/platform"
)

type liveNetworkProfile struct {
	InstanceID, Name, InterfaceAlias, NetworkCategory string
	InterfaceIndex                                    int
}

func liveNetworkPS(script string) ([]byte, error) {
	units := utf16.Encode([]rune("$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding=New-Object Text.UTF8Encoding($false); " + script))
	bytes := make([]byte, len(units)*2)
	for i, value := range units {
		bytes[2*i], bytes[2*i+1] = byte(value), byte(value>>8)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(bytes)).CombinedOutput()
}

func liveNetworkQuote(text string) string { return "'" + strings.ReplaceAll(text, "'", "''") + "'" }

func liveNetworkRead() (liveNetworkProfile, error) {
	var p liveNetworkProfile
	b, err := liveNetworkPS(`$p=@(Get-NetConnectionProfile -InterfaceIndex 6); if($p.Count -ne 1){throw 'expected one physical profile'}; $p[0] | Select-Object InstanceID,Name,InterfaceAlias,InterfaceIndex,@{n='NetworkCategory';e={$_.NetworkCategory.ToString()}} | ConvertTo-Json -Compress`)
	if err == nil {
		err = json.Unmarshal(b, &p)
	}
	return p, err
}

func liveNetworkIdentity(p liveNetworkProfile) string {
	return fmt.Sprintf(`$p=@(Get-NetConnectionProfile -InterfaceIndex 6); if($p.Count -ne 1){throw 'physical profile count changed'}; $p=$p[0]; if($p.InstanceID -cne %s -or $p.Name -cne %s -or $p.InterfaceAlias -cne %s -or $p.InterfaceIndex -ne 6){throw 'physical profile identity changed'}; `, liveNetworkQuote(p.InstanceID), liveNetworkQuote(p.Name), liveNetworkQuote(p.InterfaceAlias))
}

func liveNetworkArm(t *testing.T) (liveNetworkProfile, time.Time, string) {
	t.Helper()
	p, err := liveNetworkRead()
	if err != nil || p.InstanceID == "" || p.Name == "" || p.InterfaceAlias == "" || p.InterfaceIndex != 6 || (p.NetworkCategory != "Public" && p.NetworkCategory != "Private") {
		t.Fatalf("dedicated physical profile unavailable: %+v %v", p, err)
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	task := "OneTunnel-Network-Acceptance-" + hex.EncodeToString(nonce[:])
	dir := filepath.Join(os.Getenv("ProgramData"), task)
	if err = os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	acl := exec.Command("icacls.exe", dir, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F")
	if output, err := acl.CombinedOutput(); err != nil {
		t.Fatalf("protect recovery directory: %s %v", output, err)
	}
	end := time.Now().Add(40 * time.Second).UTC()
	scriptPath := filepath.Join(dir, "recover.ps1")
	recovery := "$ErrorActionPreference='Stop'\r\n" + liveNetworkIdentity(p) + fmt.Sprintf(`if($p.NetworkCategory.ToString() -notin @('Public','Private')){throw 'foreign category preserved'}; Set-NetConnectionProfile -InterfaceIndex 6 -NetworkCategory %s; $p=Get-NetConnectionProfile -InterfaceIndex 6; if($p.NetworkCategory.ToString() -cne %s){throw 'network category restoration failed'}; @{Restored=$true;Category=$p.NetworkCategory.ToString();UTC=[datetime]::UtcNow.ToString('o')} | ConvertTo-Json -Compress | Set-Content -LiteralPath %s`, liveNetworkQuote(p.NetworkCategory), liveNetworkQuote(p.NetworkCategory), liveNetworkQuote(filepath.Join(dir, "recovery.json")))
	if err = os.WriteFile(scriptPath, []byte(recovery), 0600); err != nil {
		t.Fatal(err)
	}
	actionArguments := `-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "` + scriptPath + `"`
	register := fmt.Sprintf(`$exe=$env:WINDIR+'\System32\WindowsPowerShell\v1.0\powershell.exe'; $arguments=%s; $a=New-ScheduledTaskAction -Execute $exe -Argument $arguments; $at=[datetime]::Parse(%s).ToLocalTime(); $tr=New-ScheduledTaskTrigger -Once -At $at; $s=New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 1); Register-ScheduledTask -TaskName %s -Action $a -Trigger $tr -Settings $s -User SYSTEM -RunLevel Highest | Out-Null; $task=Get-ScheduledTask -TaskName %s; $info=Get-ScheduledTaskInfo -TaskName %s; if($task.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or $task.Actions.Execute -cne $exe -or $task.Actions.Arguments -cne $arguments -or [math]::Abs(($info.NextRunTime-$at).TotalSeconds) -gt 1 -or $task.State -eq 'Disabled'){throw 'independent recovery registration invalid'}; 'RECOVERY-READY'`, liveNetworkQuote(actionArguments), liveNetworkQuote(end.Format(time.RFC3339Nano)), liveNetworkQuote(task), liveNetworkQuote(task), liveNetworkQuote(task))
	output, err := liveNetworkPS(register)
	if err != nil || !strings.Contains(string(output), "RECOVERY-READY") {
		t.Fatalf("arm independent SYSTEM recovery: %s %v", output, err)
	}
	t.Cleanup(func() {
		// Exact task and recovery evidence remain available if synchronous restore fails.
		output, err := liveNetworkPS("& " + liveNetworkQuote(scriptPath))
		if err != nil {
			t.Errorf("category restore failed; absolute recovery task retained: %s %v", output, err)
			return
		}
		after, err := liveNetworkRead()
		if err != nil || after != p {
			t.Errorf("physical profile baseline differs: %+v %v", after, err)
			return
		}
		cleanup := fmt.Sprintf(`$t=Get-ScheduledTask -TaskName %s; if($t.Actions.Arguments -cne %s){throw 'recovery task ownership changed'}; Unregister-ScheduledTask -TaskName %s -Confirm:$false`, liveNetworkQuote(task), liveNetworkQuote(actionArguments), liveNetworkQuote(task))
		if output, err := liveNetworkPS(cleanup); err != nil {
			t.Errorf("exact recovery task cleanup: %s %v", output, err)
		}
	})
	return p, end, dir
}

func TestUserNetworkLiveAcceptance(t *testing.T) {
	if os.Getenv("ONETUNNEL_LIVE_NETWORK_ACCEPTANCE") != "dedicated-server-only" {
		t.Skip("real network-category acceptance requires dedicated-server opt-in")
	}
	host, err := os.Hostname()
	if err != nil || !strings.EqualFold(host, "WIN-67BE833BA6F") || !strings.EqualFold(os.Getenv("USERNAME"), "codex") {
		t.Fatal("network-category mutation restricted to dedicated server codex user")
	}
	for _, stage := range []string{"stable permissions", "first status", "second status", "download"} {
		t.Run(stage, func(t *testing.T) {
			physical, end, dir := liveNetworkArm(t)
			change := func(category string) {
				t.Helper()
				if time.Until(end) < 12*time.Second {
					t.Fatal("insufficient independent network recovery window")
				}
				output, err := liveNetworkPS(liveNetworkIdentity(physical) + "Set-NetConnectionProfile -InterfaceIndex 6 -NetworkCategory " + liveNetworkQuote(category))
				if err != nil {
					t.Fatalf("set physical network category: %s %v", output, err)
				}
				want := platform.UserNetworkPublic
				if category == "Private" {
					want = platform.UserNetworkTrusted
				}
				limit := time.Now().Add(3 * time.Second)
				for platform.CurrentUserPhysicalNetworkCategory() != want {
					if time.Now().After(limit) {
						t.Fatalf("real NLM did not classify %s as %s", category, want)
					}
					time.Sleep(50 * time.Millisecond)
				}
			}
			a, _, _, now, _ := automationFixture(t)
			a.UserAutomation.NetworkCategory = platform.CurrentUserPhysicalNetworkCategory
			doc, err := a.Store.Load()
			if err != nil {
				t.Fatal(err)
			}
			if stage != "stable permissions" {
				doc.SubscriptionSources[doc.Profiles[0].Group] = "https://subscription.test/synthetic"
				if err = a.Store.Save(doc); err != nil {
					t.Fatal(err)
				}
			}
			saveAutomation(t, a, UserPreferences{AutoConnect: true, ProfileID: doc.Profiles[0].ID, AllowTrusted: true})
			statuses, starts, downloads := 0, 0, 0
			changed := false
			transition := func() {
				if !changed {
					change("Public")
					changed = true
					*now = now.Add(31 * time.Second)
				}
			}
			a.ServiceCall = func(_ context.Context, request control.Request) (control.Response, int64, error) {
				switch request.Command {
				case "status":
					statuses++
					if stage == "first status" && statuses == 1 || stage == "second status" && statuses == 2 {
						transition()
					}
				case "start":
					starts++
				default:
					t.Fatalf("unexpected synthetic controller command %s", request.Command)
				}
				return control.Response{Version: 1, Instance: "synthetic-network-acceptance", Revision: uint64(statuses + starts + 1)}, 1, nil
			}
			a.Downloader = func(context.Context, string) (ImportResult, error) {
				downloads++
				if stage == "download" {
					transition()
				}
				return ImportResult{}, errors.New("synthetic offline subscription response")
			}
			tick := func(seconds int) {
				t.Helper()
				*now = now.Add(time.Duration(seconds) * time.Second)
				if _, err := a.tickUserSettings(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if stage == "stable permissions" {
				change("Public")
				tick(0)
				tick(6)
				if starts != 0 {
					t.Fatal("forbidden real public network started connection")
				}
				change("Private")
				tick(0)
				tick(4)
				if starts != 0 {
					t.Fatal("private network bypassed category debounce")
				}
				tick(2)
				if starts != 1 {
					t.Fatalf("stable trusted network starts=%d want=1", starts)
				}
			} else {
				change("Private")
				tick(0)
				tick(6)
				if !changed || starts != 0 {
					t.Fatalf("real NLM transition recheck failed: changed=%t starts=%d", changed, starts)
				}
				wantDownloads := 0
				if stage == "download" {
					wantDownloads = 1
				}
				if downloads != wantDownloads {
					t.Fatalf("downloads=%d want=%d", downloads, wantDownloads)
				}
				tick(4)
				tick(2)
				if starts != 0 {
					t.Fatal("stable forbidden public network started after transition")
				}
			}
			report, _ := json.Marshal(map[string]any{"Stage": stage, "RealNLM": true, "Controller": "synthetic", "Session": "synthetic", "Clock": "synthetic-debounce-only", "Starts": starts, "Downloads": downloads})
			if err := os.WriteFile(filepath.Join(dir, "acceptance.json"), report, 0600); err != nil {
				t.Fatal(err)
			}
			t.Log("actual Windows NLM category transition verified with synthetic controller/session and debounce clock; service start/logon/network-adapter change not tested")
		})
	}
}
