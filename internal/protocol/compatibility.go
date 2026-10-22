package protocol

import (
	"errors"
	"strings"
)

var ErrTransportUpgrade = errors.New("transport settings require engine migration")

// Keep stored profiles intact. Reject settings removed by upstream before a
// runtime can create a session, install routes or arm traffic protection.
func CheckEngineCompatibility(source string, kind int) error {
	if kind != 2 || !strings.HasPrefix(strings.TrimSpace(source), "{") {
		return nil
	}
	out, err := Outbound(source, kind)
	if err != nil {
		return err
	}
	stream := obj(out["streamSettings"])
	if !has(s(stream["network"]), "kcp mkcp") {
		return nil
	}
	for key, value := range obj(stream["kcpSettings"]) {
		switch strings.ToLower(key) {
		case "congestion", "readbuffersize", "writebuffersize":
			return ErrTransportUpgrade
		case "tti":
			if n(value) > 1000 {
				return ErrTransportUpgrade
			}
		}
	}
	return nil
}
