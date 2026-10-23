package protocol

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestLegacyKCPSettingsRemainStoredButCannotBeSilentlyIgnored(t *testing.T) {
	for _, settings := range []string{`{"congestion":true}`, `{"readBufferSize":4}`, `{"writeBufferSize":4}`, `{"tti":1500}`, `{}`, `{"tti":1000,"cwndMultiplier":2,"maxSendingWindow":64}`} {
		source := fmt.Sprintf(`{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":12345,"users":[{"id":"6d7a9bdf-fdeb-4b9b-aa68-24abfa4bd12a","encryption":"none"}]}]},"streamSettings":{"network":"kcp","kcpSettings":%s}}`, settings)
		if _, err := Outbound(source, 2); err != nil {
			t.Fatal("stored configuration became unreadable")
		}
		legacy := strings.Contains(settings, "Buffer") || strings.Contains(settings, "congestion") || strings.Contains(settings, "1500")
		err := CheckEngineCompatibility(source, 2)
		if errors.Is(err, ErrTransportUpgrade) != legacy {
			t.Fatalf("incorrect KCP compatibility result: %s", settings)
		}
	}
}
