package engine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/outbound"
	"mac-proxy/internal/trace"
	"mac-proxy/internal/wire"
)

type DialFailure struct {
	Via     string `json:"via,omitempty"`
	Stage   string `json:"stage"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type reportedDialError struct {
	message string
	cause   error
}

func (e reportedDialError) Error() string { return e.message }
func (e reportedDialError) Unwrap() error { return e.cause }

func (r *Record) setFailure(failure DialFailure) {
	r.Stage, r.FailureCode, r.Error = failure.Stage, failure.Code, failure.Message
}

func (r *Record) recordAttemptFailure(err error) {
	failure := diagnoseDial(err, r.Stage)
	failure.Via = r.Via
	r.setFailure(failure)
	r.Failures = append(r.Failures, failure)
}

// Diagnose the cause without copying text from an upstream peer into status,
// probe output or the error returned to callers.
func diagnoseDial(err error, stage string) DialFailure {
	var probe *probeFailure
	if errors.As(err, &probe) {
		stage = probe.stage
	}
	if stage == "" {
		stage = trace.StageHandshake
	}
	failure := func(code, message string) DialFailure {
		return DialFailure{Stage: stage, Code: code, Message: message}
	}
	var hostError x509.HostnameError
	var invalid x509.CertificateInvalidError
	var authority x509.UnknownAuthorityError
	var verification *tls.CertificateVerificationError
	var dnsError *net.DNSError
	var httpStatus probeHTTPStatus
	switch {
	case errors.Is(err, context.Canceled):
		return failure("canceled", "operation canceled")
	case errors.Is(err, outbound.ErrRejected):
		stage = trace.StageRoute
		return failure("policy-rejected", outbound.ErrRejected.Error())
	case errors.Is(err, backend.ErrLoop):
		return failure("proxy-loop", backend.ErrLoop.Error())
	case errors.Is(err, backend.ErrEndpointCooling):
		return failure("endpoint-cooldown", backend.ErrEndpointCooling.Error())
	case errors.Is(err, errEndpointBusy):
		return failure("endpoint-busy", errEndpointBusy.Error())
	case errors.Is(err, backend.ErrPacketCongested):
		return failure("packet-busy", backend.ErrPacketCongested.Error())
	case wire.DescriptorExhausted(err):
		stage = trace.StageConnect
		return failure("fd-exhausted", "proxy file descriptor limit reached")
	case errors.Is(err, backend.ErrNoUDP):
		return failure("udp-unsupported", backend.ErrNoUDP.Error())
	case errors.As(err, &hostError):
		return failure("tls-hostname", "TLS certificate does not match the server name")
	case errors.As(err, &invalid) && invalid.Reason == x509.Expired:
		if invalid.Cert != nil && time.Now().Before(invalid.Cert.NotBefore) {
			return failure("tls-not-yet-valid", "TLS certificate is not yet valid")
		}
		return failure("tls-expired", "TLS certificate has expired")
	case errors.As(err, &authority):
		return failure("tls-untrusted", "TLS certificate is not trusted")
	case errors.As(err, &invalid), errors.As(err, &verification):
		return failure("tls-certificate", "TLS certificate verification failed")
	case errors.Is(err, outbound.ErrAuthentication), isKnownAuthenticationError(err):
		return failure("proxy-auth", "upstream proxy authentication failed")
	case errors.Is(err, outbound.ErrTargetRefused), isKnownSOCKSRefusal(err):
		stage = trace.StageUpstream
		return failure("target-refused", "proxy target connection refused")
	case errors.As(err, &httpStatus):
		return failure("probe-http-status", fmt.Sprintf("probe returned HTTP %d", httpStatus))
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, syscall.ETIMEDOUT):
		if stage == trace.StageDNS {
			return failure("dns-timeout", "DNS lookup timed out")
		}
		return failure("timeout", "timed out")
	case errors.As(err, &dnsError):
		if stage != trace.StageUpstream {
			stage = trace.StageDNS
		}
		switch {
		case dnsError.IsTimeout:
			return failure("dns-timeout", "DNS lookup timed out")
		case dnsError.IsNotFound:
			return failure("dns-not-found", "DNS returned no address")
		default:
			return failure("dns-unavailable", "DNS resolver could not answer")
		}
	case errors.Is(err, syscall.ECONNREFUSED):
		return failure("connection-refused", "connection refused")
	case errors.Is(err, syscall.ECONNRESET):
		return failure("connection-reset", "connection reset by peer")
	case errors.Is(err, syscall.EPIPE):
		return failure("broken-pipe", "broken pipe")
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETDOWN):
		return failure("unreachable", "network or host unreachable")
	case errors.Is(err, net.ErrClosed), errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return failure("connection-closed", "connection closed before completion")
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		if stage == trace.StageDNS {
			return failure("dns-timeout", "DNS lookup timed out")
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return failure("timeout", os.ErrDeadlineExceeded.Error())
		}
		return failure("timeout", "timed out")
	}
	switch stage {
	case trace.StageDNS:
		return failure("dns-unavailable", "DNS resolver could not answer")
	case trace.StageConnect:
		return failure("connect-failed", "could not open connection")
	case trace.StageHandshake:
		return failure("handshake-failed", "proxy handshake failed")
	default:
		return failure("network-failed", "network operation failed")
	}
}

func isKnownAuthenticationError(err error) bool {
	if err == nil {
		return false
	}
	// sing's SOCKS and HTTP clients return untyped errors for these replies.
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "socks5: incorrect user name or password") ||
		strings.Contains(message, "socks5: unsupported auth method: 255") ||
		message == "authentication required" || strings.HasSuffix(message, ": authentication required")
}

func isKnownSOCKSRefusal(err error) bool {
	return err != nil && strings.HasSuffix(err.Error(), "socks5: request rejected, code=5")
}
