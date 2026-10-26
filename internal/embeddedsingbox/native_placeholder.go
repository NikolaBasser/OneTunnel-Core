package embeddedsingbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// checkNativePlaceholder only permits the generated type=onetunnel-native,
// tag=proxy object at the explicit injected-transport boundary.
func checkNativePlaceholder(data []byte, injected bool) (bool, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		if injected {
			return false, err
		}
		return false, nil
	}
	rawOutbounds, ok := root["outbounds"]
	if !ok {
		if injected {
			return false, errors.New("native outbound missing")
		}
		return false, nil
	}
	var outbounds []json.RawMessage
	if err := json.Unmarshal(rawOutbounds, &outbounds); err != nil {
		if injected {
			return false, err
		}
		return false, nil
	}
	count := 0
	for _, raw := range outbounds {
		fields, err := decodeOutboundObject(raw)
		if err != nil {
			return false, err
		}
		var typ string
		if err = json.Unmarshal(fields["type"], &typ); err != nil || typ != nativeOutboundType {
			continue
		}
		count++
		if !injected {
			return true, errors.New("native outbound requires injected transport")
		}
		var tag string
		if len(fields) != 2 || json.Unmarshal(fields["tag"], &tag) != nil || tag != "proxy" {
			return true, errors.New("invalid native outbound placeholder")
		}
	}
	if injected && count != 1 {
		return false, errors.New("exactly one native outbound placeholder is required")
	}
	return count == 1, nil
}

func decodeOutboundObject(raw []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("invalid outbound object")
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return nil, errors.New("invalid outbound object")
		}
		key, ok := token.(string)
		if !ok {
			return nil, errors.New("invalid outbound object")
		}
		if _, exists := fields[key]; exists {
			return nil, errors.New("duplicate outbound field")
		}
		var value json.RawMessage
		if err = decoder.Decode(&value); err != nil {
			return nil, err
		}
		fields[key] = value
	}
	if _, err = decoder.Token(); err != nil {
		return nil, errors.New("invalid outbound object")
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("invalid outbound object")
	}
	return fields, nil
}
