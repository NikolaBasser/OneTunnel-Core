package protocol

import (
	"encoding/base64"
	"strconv"
	"strings"
)

const AWGFieldPattern = `Jc|Jmin|Jmax|S[1-4]|H[1-4]|I[1-5]|HeaderProtectionKey|ContentPaddingAddition|RekeyAfterTime|RekeyTimeout|RejectAfterTime|KeepaliveTimeout|MaxHandshakeAttempts|RandomTrailers|DisableCookies`

func validateAWG31(fields map[string]string) error {
	for _, name := range []string{"contentpaddingaddition", "rekeyaftertime", "rekeytimeout", "rejectaftertime", "keepalivetimeout", "maxhandshakeattempts"} {
		if value := fields["i"+name]; value != "" && !boundedRange(value, 0, 65535) {
			return ErrConfiguration
		}
	}
	for _, name := range []string{"randomtrailers", "disablecookies"} {
		if value := strings.ToLower(fields["i"+name]); value != "" && value != "on" && value != "off" && value != "true" && value != "false" {
			return ErrConfiguration
		}
	}
	if value := fields["iheaderprotectionkey"]; value != "" {
		key, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(key) != 32 {
			return ErrConfiguration
		}
		active := false
		for _, v := range key {
			active = active || v != 0
		}
		clear(key)
		if active {
			for _, name := range []string{"s1", "s2", "s3", "s4"} {
				n, err := strconv.Atoi(fields["i"+name])
				if err != nil || n < 12 || n > 65535 {
					return ErrConfiguration
				}
			}
		}
	}
	return nil
}
