package control

import (
	"context"
	"testing"
)

func TestDesktopRepliesNegotiateRevisionWithoutChangingLegacy(t *testing.T) {
	manager, _ := fakeManager(t)
	defer manager.Close()
	legacy := manager.Dispatch(context.Background(), Request{Version: 1, Command: "status"})
	revised := manager.Dispatch(context.Background(), Request{Version: 1, Command: "desktop.status"})
	if legacy.Revision != 0 || revised.Error != nil || revised.Revision == 0 || revised.Instance != legacy.Instance || revised.State != legacy.State {
		t.Fatal("revision negotiation broke snapshots or API1")
	}
}
