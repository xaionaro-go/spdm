// Package status defines SPDM library error types and sentinel errors
// matching the codes in libspdm spdm_return_status.h (DSP0274 Appendix A).
package status

import (
	"errors"
	"fmt"
)

// Severity levels from spdm_return_status.h.
type Severity uint8

const (
	SeveritySuccess Severity = 0x0
	SeverityWarning Severity = 0x4
	SeverityError   Severity = 0x8
)

func (s Severity) String() string {
	switch s {
	case SeveritySuccess:
		return "success"
	case SeverityWarning:
		return "warning"
	case SeverityError:
		return "error"
	default:
		return fmt.Sprintf("Severity(0x%X)", uint8(s))
	}
}

// Source identifies the subsystem that produced the error.
type Source uint8

const (
	SourceSuccess     Source = 0x00
	SourceCore        Source = 0x01
	SourceCrypto      Source = 0x02
	SourceCertParse   Source = 0x03
	SourceTransport   Source = 0x04
	SourceMeasCollect Source = 0x05
	SourceRNG         Source = 0x06
)

func (s Source) String() string {
	switch s {
	case SourceSuccess:
		return "success"
	case SourceCore:
		return "core"
	case SourceCrypto:
		return "crypto"
	case SourceCertParse:
		return "cert_parse"
	case SourceTransport:
		return "transport"
	case SourceMeasCollect:
		return "meas_collect"
	case SourceRNG:
		return "rng"
	default:
		return fmt.Sprintf("Source(0x%02X)", uint8(s))
	}
}

// Code is the specific error code within a source.
type Code uint16

// Error represents an SPDM library error.
type Error struct {
	Severity Severity
	Source   Source
	Code     Code
	Msg      string
}

func (e *Error) Error() string {
	if e.Msg != "" {
		return fmt.Sprintf("spdm %s [%s:0x%04X]: %s", e.Severity, e.Source, uint16(e.Code), e.Msg)
	}
	return fmt.Sprintf("spdm %s [%s:0x%04X]", e.Severity, e.Source, uint16(e.Code))
}

func (e *Error) Is(target error) bool {
	var t *Error
	if !errors.As(target, &t) {
		return false
	}
	return e.Severity == t.Severity && e.Source == t.Source && e.Code == t.Code
}

func (e *Error) Unwrap() error { return nil }

// Sentinel errors -- core subsystem.
var (
	ErrInvalidParameter    = &Error{SeverityError, SourceCore, 0x0001, "invalid parameter"}
	ErrUnsupportedCap      = &Error{SeverityError, SourceCore, 0x0002, "unsupported capability"}
	ErrInvalidStateLocal   = &Error{SeverityError, SourceCore, 0x0003, "invalid local state"}
	ErrInvalidStatePeer    = &Error{SeverityError, SourceCore, 0x0004, "invalid peer state"}
	ErrInvalidMsgField     = &Error{SeverityError, SourceCore, 0x0005, "invalid message field"}
	ErrInvalidMsgSize      = &Error{SeverityError, SourceCore, 0x0006, "invalid message size"}
	ErrNegotiationFail     = &Error{SeverityError, SourceCore, 0x0007, "negotiation failure"}
	ErrBusyPeer            = &Error{SeverityError, SourceCore, 0x0008, "peer busy"}
	ErrNotReadyPeer        = &Error{SeverityError, SourceCore, 0x0009, "peer not ready"}
	ErrErrorPeer           = &Error{SeverityError, SourceCore, 0x000A, "unexpected peer error"}
	ErrResynchPeer         = &Error{SeverityError, SourceCore, 0x000B, "peer requested resynch"}
	ErrBufferFull          = &Error{SeverityError, SourceCore, 0x000C, "buffer full"}
	ErrBufferTooSmall      = &Error{SeverityError, SourceCore, 0x000D, "buffer too small"}
	ErrSessionNumberExceed = &Error{SeverityError, SourceCore, 0x000E, "session number exceeded"}
	ErrSessionMsgError     = &Error{SeverityError, SourceCore, 0x000F, "session message error"}
	ErrAcquireFail         = &Error{SeverityError, SourceCore, 0x0010, "acquire fail"}
	ErrResetRequiredPeer   = &Error{SeverityError, SourceCore, 0x0012, "peer requires reset"}
	ErrPeerBufferTooSmall  = &Error{SeverityError, SourceCore, 0x0013, "peer buffer too small"}
)

// Sentinel errors -- crypto subsystem.
var (
	ErrCryptoError            = &Error{SeverityError, SourceCrypto, 0x0000, "crypto error"}
	ErrVerifFail              = &Error{SeverityError, SourceCrypto, 0x0001, "verification failed"}
	ErrSequenceNumberOverflow = &Error{SeverityError, SourceCrypto, 0x0002, "sequence number overflow"}
	ErrFIPSFail               = &Error{SeverityError, SourceCrypto, 0x0004, "FIPS test failed"}
	WarnVerifNoAuthority      = &Error{SeverityWarning, SourceCrypto, 0x0003, "cert valid but not authoritative"}
	WarnOverriddenParameter   = &Error{SeverityWarning, SourceCore, 0x0014, "parameter overridden"}
)

// Sentinel errors -- other subsystems.
var (
	ErrInvalidCert       = &Error{SeverityError, SourceCertParse, 0x0000, "invalid certificate"}
	ErrSendFail          = &Error{SeverityError, SourceTransport, 0x0000, "send failed"}
	ErrReceiveFail       = &Error{SeverityError, SourceTransport, 0x0001, "receive failed"}
	ErrMeasInvalidIndex  = &Error{SeverityError, SourceMeasCollect, 0x0000, "invalid measurement index"}
	ErrMeasInternalError = &Error{SeverityError, SourceMeasCollect, 0x0001, "measurement internal error"}
	ErrLowEntropy        = &Error{SeverityError, SourceRNG, 0x0000, "low entropy"}
)

// ProtocolError wraps an SPDM ERROR response received from a peer.
type ProtocolError struct {
	ErrorCode uint8
	ErrorData uint8
	ExtData   []byte
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("spdm protocol error: code=0x%02X data=0x%02X", e.ErrorCode, e.ErrorData)
}
