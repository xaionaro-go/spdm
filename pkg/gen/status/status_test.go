package status

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorIs_SameSentinel(t *testing.T) {
	sentinels := []*Error{
		ErrInvalidParameter, ErrUnsupportedCap, ErrInvalidStateLocal,
		ErrInvalidStatePeer, ErrInvalidMsgField, ErrInvalidMsgSize,
		ErrNegotiationFail, ErrBusyPeer, ErrNotReadyPeer,
		ErrErrorPeer, ErrResynchPeer, ErrBufferFull,
		ErrBufferTooSmall, ErrSessionNumberExceed, ErrSessionMsgError,
		ErrAcquireFail, ErrResetRequiredPeer, ErrPeerBufferTooSmall,
		ErrCryptoError, ErrVerifFail, ErrSequenceNumberOverflow,
		ErrFIPSFail, WarnVerifNoAuthority, WarnOverriddenParameter,
		ErrInvalidCert, ErrSendFail, ErrReceiveFail,
		ErrMeasInvalidIndex, ErrMeasInternalError, ErrLowEntropy,
	}

	for _, s := range sentinels {
		// A freshly constructed Error with the same fields must match via Is.
		clone := &Error{Severity: s.Severity, Source: s.Source, Code: s.Code, Msg: "different msg"}
		assert.True(t, errors.Is(clone, s), "errors.Is(clone, %v) = false, want true", s)
		assert.True(t, errors.Is(s, clone), "errors.Is(%v, clone) = false, want true", s)
	}
}

func TestErrorIs_Different(t *testing.T) {
	assert.False(t, errors.Is(ErrInvalidParameter, ErrUnsupportedCap),
		"ErrInvalidParameter should not match ErrUnsupportedCap")
	assert.False(t, errors.Is(ErrCryptoError, ErrVerifFail),
		"ErrCryptoError should not match ErrVerifFail")
	assert.False(t, errors.Is(ErrSendFail, ErrReceiveFail),
		"ErrSendFail should not match ErrReceiveFail")
	// Different severity, same source+code.
	warn := &Error{SeverityWarning, SourceCore, 0x0001, ""}
	assert.False(t, errors.Is(warn, ErrInvalidParameter),
		"warning-severity should not match error-severity with same code")
}

func TestErrorAs(t *testing.T) {
	var sErr *Error
	require.True(t, errors.As(ErrInvalidParameter, &sErr), "errors.As should succeed for *Error")
	assert.Equal(t, Code(0x0001), sErr.Code)

	pe := &ProtocolError{ErrorCode: 0x42, ErrorData: 0x01}
	var pErr *ProtocolError
	require.True(t, errors.As(pe, &pErr), "errors.As should succeed for *ProtocolError")
	assert.Equal(t, uint8(0x42), pErr.ErrorCode)
}

func TestErrorMessage(t *testing.T) {
	msg := ErrInvalidParameter.Error()
	for _, want := range []string{"error", "core", "0x0001", "invalid parameter"} {
		assert.Contains(t, msg, want)
	}

	// Error without message.
	e := &Error{SeverityError, SourceCrypto, 0x00FF, ""}
	msg = e.Error()
	assert.False(t, strings.Contains(msg, ": "),
		"empty-msg Error() should not contain trailing colon-space, got %q", msg)
}

func TestProtocolErrorMessage(t *testing.T) {
	pe := &ProtocolError{ErrorCode: 0xAB, ErrorData: 0xCD, ExtData: []byte{1, 2}}
	msg := pe.Error()
	assert.Contains(t, msg, "0xAB")
	assert.Contains(t, msg, "0xCD")
	assert.Contains(t, msg, "spdm protocol error")
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		s    Severity
		want string
	}{
		{SeveritySuccess, "success"},
		{SeverityWarning, "warning"},
		{SeverityError, "error"},
		{Severity(0xF), "Severity(0xF)"},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, tc.s.String(), "Severity(0x%X).String()", uint8(tc.s))
	}
}

func TestSourceString(t *testing.T) {
	tests := []struct {
		s    Source
		want string
	}{
		{SourceSuccess, "success"},
		{SourceCore, "core"},
		{SourceCrypto, "crypto"},
		{SourceCertParse, "cert_parse"},
		{SourceTransport, "transport"},
		{SourceMeasCollect, "meas_collect"},
		{SourceRNG, "rng"},
		{Source(0xFF), "Source(0xFF)"},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, tc.s.String(), "Source(0x%02X).String()", uint8(tc.s))
	}
}

func TestWrappedErrorPreservesIs(t *testing.T) {
	wrapped := fmt.Errorf("context: %w", ErrVerifFail)

	assert.True(t, errors.Is(wrapped, ErrVerifFail),
		"errors.Is through fmt.Errorf %%w should find ErrVerifFail")

	// Double wrap.
	double := fmt.Errorf("outer: %w", wrapped)
	assert.True(t, errors.Is(double, ErrVerifFail),
		"errors.Is through double wrap should find ErrVerifFail")

	// Wrapped error should not match a different sentinel.
	assert.False(t, errors.Is(wrapped, ErrCryptoError),
		"wrapped ErrVerifFail should not match ErrCryptoError")
}

func TestErrorAs_ThroughWrap(t *testing.T) {
	wrapped := fmt.Errorf("context: %w", ErrBufferFull)
	var sErr *Error
	require.True(t, errors.As(wrapped, &sErr), "errors.As should unwrap through fmt.Errorf")
	assert.Equal(t, ErrBufferFull.Code, sErr.Code)
}
