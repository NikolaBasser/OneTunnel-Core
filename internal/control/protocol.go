package control

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
	"io"
	"regexp"
	"strings"
	"unicode/utf16"
)

const Version = 1
const MaxFrameBytes = 5 * 1024 * 1024
const ServiceName = "OneTunnelCore"
const PipeName = `\\.\pipe\OneTunnel.Core.v1`

var ErrFrame = errors.New("invalid control frame")
var guid = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Numeric protocol IDs and PascalCase JSON are the existing desktop v1 contract.
type Profile struct {
	Reliability *ReliabilityOptions        `json:"Reliability,omitempty"`
	Transport   *protocol.TransportOptions `json:"Transport,omitempty"`
	Network     *protocol.NetworkOptions   `json:"Network,omitempty"`
	ID          string                     `json:"Id"`
	Name        string                     `json:"Name"`
	Protocol    int                        `json:"Protocol"`
	Source      string                     `json:"Source"`
	Group       string                     `json:"Group"`
	Label       string                     `json:"Label,omitempty"`
}
type Request struct {
	Fallbacks  []Profile `json:"Fallbacks,omitempty"`
	Version    int       `json:"Version"`
	Command    string    `json:"Command"`
	Profile    *Profile  `json:"Profile"`
	FullDevice bool      `json:"FullDevice"`
}
type State struct {
	Reconnecting      bool                  `json:"Reconnecting,omitempty"`
	ReconnectAttempt  int                   `json:"ReconnectAttempt,omitempty"`
	Active            bool                  `json:"Active"`
	NeedsRecovery     bool                  `json:"NeedsRecovery"`
	TrafficLocked     bool                  `json:"TrafficLocked"`
	WholeDevice       bool                  `json:"WholeDevice"`
	FullDeviceMode    bool                  `json:"FullDeviceMode"`
	ClockSynchronized bool                  `json:"ClockSynchronized"`
	LocalPort         int                   `json:"LocalPort"`
	Status            string                `json:"Status"`
	ProfileID         *string               `json:"ProfileId"`
	Statistics        *ConnectionStatistics `json:"Statistics,omitempty"`
}
type Response struct {
	Revision  uint64     `json:"Revision,omitempty"`
	Version   int        `json:"Version"`
	Instance  string     `json:"Instance"`
	State     State      `json:"State"`
	Result    *string    `json:"Result"`
	Error     *string    `json:"Error"`
	ErrorInfo *ErrorInfo `json:"ErrorInfo,omitempty"`
}
type BackendResult struct {
	State     State      `json:"State"`
	Result    *string    `json:"Result"`
	Error     *string    `json:"Error"`
	ErrorInfo *ErrorInfo `json:"ErrorInfo,omitempty"`
}

func Validate(r Request) string {
	if r.Version != Version {
		return "incompatible_version"
	}
	if len(r.Fallbacks) > 8 || (r.Command != "start" && len(r.Fallbacks) > 0) {
		return "invalid_request"
	}
	if r.Command != "start" && r.Command != "check-profile" && (r.Profile != nil || r.FullDevice) {
		return "invalid_request"
	}
	switch r.Command {
	case "hello", "status", "watch", "stop", "recover", "probe":
		return ""
	case "start", "check-profile":
		if r.Command == "check-profile" && r.FullDevice {
			return "invalid_request"
		}
		p := r.Profile
		if p == nil || !guid.MatchString(p.ID) || strings.ReplaceAll(p.ID, "-", "") == strings.Repeat("0", 32) || p.Protocol < 0 || p.Protocol > protocol.MaxKind || strings.TrimSpace(p.Source) == "" || len(utf16.Encode([]rune(p.Source))) > 131072 || len(utf16.Encode([]rune(p.Name))) > 4096 {
			return "invalid_configuration"
		}
		if p.Reliability != nil && p.Reliability.UseFallbacks && !p.Reliability.AutoReconnect {
			return "invalid_configuration"
		}
		if p.Reliability != nil && p.Reliability.AutoSelect && (!p.Reliability.AutoReconnect || !p.Reliability.UseFallbacks || p.Protocol < 2 || !protocol.NetworkOptionsEmpty(p.Network) || r.FullDevice) {
			return "invalid_configuration"
		}
		policyMode := r.FullDevice || r.Command == "check-profile"
		if protocol.ValidateNetworkOptions(p.Network, p.Protocol, policyMode) != nil {
			return "invalid_configuration"
		}
		for _, candidate := range r.Fallbacks {
			if candidate.ID == p.ID || candidate.Group != p.Group || !CompatibleFallback(*p, candidate, r.FullDevice) || Validate(Request{Version: Version, Command: "start", Profile: &candidate, FullDevice: r.FullDevice}) != "" {
				return "invalid_configuration"
			}
		}
		return ""
	default:
		return "unknown_command"
	}
}

func ReadFrame[T any](r io.Reader) (T, error) {
	var out T
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return out, err
	}
	length := binary.LittleEndian.Uint32(header[:])
	if length < 2 || length > MaxFrameBytes {
		return out, ErrFrame
	}
	data := make([]byte, int(length))
	defer clear(data)
	if _, err := io.ReadFull(r, data); err != nil {
		return out, err
	}
	// Match the desktop decoder's depth bound before decoding nested profile data.
	depth, quoted, escaped := 0, false, false
	for _, c := range data {
		if quoted {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		if c == '"' {
			quoted = true
		} else if c == '{' || c == '[' {
			depth++
			if depth > 48 {
				return out, ErrFrame
			}
		} else if c == '}' || c == ']' {
			depth--
		}
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&out); err != nil {
		return out, ErrFrame
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return out, ErrFrame
	}
	return out, nil
}
func WriteFrame[T any](w io.Writer, value T) error {
	data, err := json.Marshal(value)
	if err != nil {
		return ErrFrame
	}
	defer clear(data)
	if len(data) > MaxFrameBytes {
		return ErrFrame
	}
	var header [4]byte
	binary.LittleEndian.PutUint32(header[:], uint32(len(data)))
	if err = writeAll(w, header[:]); err != nil {
		return err
	}
	return writeAll(w, data)
}
func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
