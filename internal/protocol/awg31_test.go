package protocol

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestAWG31Validation(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	valid := map[string]string{"iheaderprotectionkey": key, "is1": "16", "is2": "16", "is3": "16", "is4": "16", "icontentpaddingaddition": "0-32", "irekeyaftertime": "110-130", "irekeytimeout": "4-6", "irejectaftertime": "170-190", "ikeepalivetimeout": "20-30", "imaxhandshakeattempts": "12-18", "irandomtrailers": "on", "idisablecookies": "off"}
	if e := validateAWG31(valid); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct{ k, v string }{{"iheaderprotectionkey", "bad"}, {"is4", "11"}, {"icontentpaddingaddition", "65536"}, {"irekeyaftertime", "130-110"}, {"irandomtrailers", "yes"}, {"idisablecookies", "1"}} {
		copy := map[string]string{}
		for k, v := range valid {
			copy[k] = v
		}
		copy[tc.k] = tc.v
		if validateAWG31(copy) == nil {
			t.Fatalf("accepted invalid %s", tc.k)
		}
	}
}
