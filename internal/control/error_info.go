package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"

	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

// ErrorInfo carries bounded, typed failure metadata without exposing details.
type ErrorInfo struct {
	Stage     string `json:"Stage"`
	Code      string `json:"Code"`
	Retryable bool   `json:"Retryable"`
}

func ClassifyError(stage string, err error) *ErrorInfo {
	if err == nil {
		return nil
	}
	switch stage {
	case "configuration", "bootstrap", "engine", "probe":
	default:
		stage = "engine"
	}
	code := "unknown"
	var dns *net.DNSError
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalidCert x509.CertificateInvalidError
	var record tls.RecordHeaderError
	var alert tls.AlertError
	var netErr net.Error
	switch {
	case errors.Is(err, protocol.ErrTransportUpgrade):
		code = "unsupported"
	case errors.Is(err, context.DeadlineExceeded):
		code = "timeout"
	case errors.As(err, &dns):
		code = "dns"
	case errors.As(err, &unknownAuthority), errors.As(err, &hostname), errors.As(err, &invalidCert), errors.As(err, &record), errors.As(err, &alert):
		code = "tls"
	case errors.As(err, &netErr):
		if netErr.Timeout() {
			code = "timeout"
		} else {
			code = "network"
		}
	}
	return &ErrorInfo{Stage: stage, Code: code, Retryable: code == "dns" || code == "timeout" || code == "network"}
}
