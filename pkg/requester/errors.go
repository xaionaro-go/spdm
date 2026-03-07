package requester

import (
	"fmt"

	"github.com/xaionaro-go/spdm/pkg/gen/status"
)

// --- Protocol step errors ---

// ErrGetVersion wraps errors from the GET_VERSION step.
type ErrGetVersion struct{ Err error }

func (e *ErrGetVersion) Error() string { return "get_version: " + e.Err.Error() }
func (e *ErrGetVersion) Unwrap() error { return e.Err }

// ErrGetCapabilities wraps errors from the GET_CAPABILITIES step.
type ErrGetCapabilities struct{ Err error }

func (e *ErrGetCapabilities) Error() string { return "get_capabilities: " + e.Err.Error() }
func (e *ErrGetCapabilities) Unwrap() error { return e.Err }

// ErrNegotiateAlgorithms wraps errors from the NEGOTIATE_ALGORITHMS step.
type ErrNegotiateAlgorithms struct{ Err error }

func (e *ErrNegotiateAlgorithms) Error() string { return "negotiate_algorithms: " + e.Err.Error() }
func (e *ErrNegotiateAlgorithms) Unwrap() error { return e.Err }

// ErrMarshalRequest wraps marshal failures for SPDM requests.
type ErrMarshalRequest struct{ Err error }

func (e *ErrMarshalRequest) Error() string { return "marshal request: " + e.Err.Error() }
func (e *ErrMarshalRequest) Unwrap() error { return e.Err }

// ErrSend wraps transport send failures.
type ErrSend struct{ Err error }

func (e *ErrSend) Error() string { return "send: " + e.Err.Error() }
func (e *ErrSend) Unwrap() error { return e.Err }

// ErrReceive wraps transport receive failures.
type ErrReceive struct{ Err error }

func (e *ErrReceive) Error() string { return "receive: " + e.Err.Error() }
func (e *ErrReceive) Unwrap() error { return e.Err }

// ErrSendSecured wraps transport send failures for secured messages.
type ErrSendSecured struct{ Err error }

func (e *ErrSendSecured) Error() string { return "send secured: " + e.Err.Error() }
func (e *ErrSendSecured) Unwrap() error { return e.Err }

// ErrReceiveSecured wraps transport receive failures for secured messages.
type ErrReceiveSecured struct{ Err error }

func (e *ErrReceiveSecured) Error() string { return "receive secured: " + e.Err.Error() }
func (e *ErrReceiveSecured) Unwrap() error { return e.Err }

// ErrUnmarshalResponse wraps unmarshal failures for SPDM responses.
type ErrUnmarshalResponse struct{ Err error }

func (e *ErrUnmarshalResponse) Error() string { return "unmarshal: " + e.Err.Error() }
func (e *ErrUnmarshalResponse) Unwrap() error { return e.Err }

// ErrUnmarshalErrorResponse wraps unmarshal failures for SPDM ERROR responses.
type ErrUnmarshalErrorResponse struct{ Err error }

func (e *ErrUnmarshalErrorResponse) Error() string {
	return "unmarshal error response: " + e.Err.Error()
}
func (e *ErrUnmarshalErrorResponse) Unwrap() error { return e.Err }

// ErrRespondIfReady wraps errors from the RESPOND_IF_READY request.
type ErrRespondIfReady struct{ Err error }

func (e *ErrRespondIfReady) Error() string { return "respond_if_ready: " + e.Err.Error() }
func (e *ErrRespondIfReady) Unwrap() error { return e.Err }

// --- Version/Capabilities/Algorithms validation errors ---

// ErrVersionResponseInvalid indicates the VERSION response has an unexpected SPDMVersion.
type ErrVersionResponseInvalid struct {
	SPDMVersion uint8
}

func (e *ErrVersionResponseInvalid) Error() string {
	return fmt.Sprintf("VERSION response SPDMVersion=0x%02X, expected 0x10", e.SPDMVersion)
}
func (e *ErrVersionResponseInvalid) Unwrap() error { return status.ErrInvalidMsgField }

// ErrVersionResponseEmpty indicates the VERSION response contains no version entries.
type ErrVersionResponseEmpty struct{}

func (e *ErrVersionResponseEmpty) Error() string { return "VERSION response has 0 entries" }
func (e *ErrVersionResponseEmpty) Unwrap() error { return status.ErrInvalidMsgField }

// ErrInvalidPeerCapabilities wraps peer capability validation failures.
type ErrInvalidPeerCapabilities struct{ Err error }

func (e *ErrInvalidPeerCapabilities) Error() string {
	return "invalid peer capabilities: " + e.Err.Error()
}
func (e *ErrInvalidPeerCapabilities) Unwrap() error { return e.Err }

// ErrAlgorithmsNegotiationFail indicates an ALGORITHMS response validation failure.
type ErrAlgorithmsNegotiationFail struct {
	Reason string
	Err    error
}

func (e *ErrAlgorithmsNegotiationFail) Error() string { return e.Reason }
func (e *ErrAlgorithmsNegotiationFail) Unwrap() error { return e.Err }

// --- Session errors ---

// ErrGenerateDHEKeypair wraps DHE keypair generation failures.
type ErrGenerateDHEKeypair struct{ Err error }

func (e *ErrGenerateDHEKeypair) Error() string { return "generate DHE keypair: " + e.Err.Error() }
func (e *ErrGenerateDHEKeypair) Unwrap() error { return e.Err }

// ErrGenerateRandomData wraps random data generation failures.
type ErrGenerateRandomData struct{ Err error }

func (e *ErrGenerateRandomData) Error() string { return "generate random data: " + e.Err.Error() }
func (e *ErrGenerateRandomData) Unwrap() error { return e.Err }

// ErrGenerateSessionID wraps session ID generation failures.
type ErrGenerateSessionID struct{ Err error }

func (e *ErrGenerateSessionID) Error() string { return "generate session ID: " + e.Err.Error() }
func (e *ErrGenerateSessionID) Unwrap() error { return e.Err }

// ErrGenerateContext wraps PSK context generation failures.
type ErrGenerateContext struct{ Err error }

func (e *ErrGenerateContext) Error() string { return "generate context: " + e.Err.Error() }
func (e *ErrGenerateContext) Unwrap() error { return e.Err }

// ErrMarshalKeyExchange wraps KEY_EXCHANGE marshal failures.
type ErrMarshalKeyExchange struct{ Err error }

func (e *ErrMarshalKeyExchange) Error() string { return "marshal key exchange: " + e.Err.Error() }
func (e *ErrMarshalKeyExchange) Unwrap() error { return e.Err }

// ErrComputeDHESharedSecret wraps DHE shared secret computation failures.
type ErrComputeDHESharedSecret struct{ Err error }

func (e *ErrComputeDHESharedSecret) Error() string {
	return "compute DHE shared secret: " + e.Err.Error()
}
func (e *ErrComputeDHESharedSecret) Unwrap() error { return e.Err }

// ErrDeriveHandshakeSecret wraps handshake secret derivation failures.
type ErrDeriveHandshakeSecret struct{ Err error }

func (e *ErrDeriveHandshakeSecret) Error() string {
	return "derive handshake secret: " + e.Err.Error()
}
func (e *ErrDeriveHandshakeSecret) Unwrap() error { return e.Err }

// ErrDeriveHandshakeKeys wraps handshake key derivation failures.
type ErrDeriveHandshakeKeys struct{ Err error }

func (e *ErrDeriveHandshakeKeys) Error() string { return "derive handshake keys: " + e.Err.Error() }
func (e *ErrDeriveHandshakeKeys) Unwrap() error { return e.Err }

// ErrDeriveMasterSecret wraps master secret derivation failures.
type ErrDeriveMasterSecret struct{ Err error }

func (e *ErrDeriveMasterSecret) Error() string { return "derive master secret: " + e.Err.Error() }
func (e *ErrDeriveMasterSecret) Unwrap() error { return e.Err }

// ErrDeriveDataKeys wraps data key derivation failures.
type ErrDeriveDataKeys struct{ Err error }

func (e *ErrDeriveDataKeys) Error() string { return "derive data keys: " + e.Err.Error() }
func (e *ErrDeriveDataKeys) Unwrap() error { return e.Err }

// ErrUnmarshalHeader wraps header unmarshal failures.
type ErrUnmarshalHeader struct{ Err error }

func (e *ErrUnmarshalHeader) Error() string { return "unmarshal header: " + e.Err.Error() }
func (e *ErrUnmarshalHeader) Unwrap() error { return e.Err }

// ErrResponseTooShort indicates a response is too short for a specific field.
type ErrResponseTooShort struct {
	Field string
}

func (e *ErrResponseTooShort) Error() string {
	return "response too short for " + e.Field
}
func (e *ErrResponseTooShort) Unwrap() error { return nil }

// ErrSessionNotFound indicates a session ID was not found.
type ErrSessionNotFound struct {
	SessionID uint32
}

func (e *ErrSessionNotFound) Error() string {
	return fmt.Sprintf("session 0x%08x: invalid parameter", e.SessionID)
}
func (e *ErrSessionNotFound) Unwrap() error { return status.ErrInvalidParameter }

// ErrSessionInvalidState indicates a session is in an unexpected state.
type ErrSessionInvalidState struct {
	SessionID uint32
	State     string
}

func (e *ErrSessionInvalidState) Error() string {
	return fmt.Sprintf("session %d in state %s: invalid state", e.SessionID, e.State)
}
func (e *ErrSessionInvalidState) Unwrap() error { return status.ErrInvalidStateLocal }

// --- Secured message errors ---

// ErrEncodeSecuredMessage wraps secured message encoding failures.
type ErrEncodeSecuredMessage struct{ Err error }

func (e *ErrEncodeSecuredMessage) Error() string {
	return "encode secured message: " + e.Err.Error()
}
func (e *ErrEncodeSecuredMessage) Unwrap() error { return e.Err }

// ErrDecodeSecuredMessage wraps secured message decoding failures.
type ErrDecodeSecuredMessage struct{ Err error }

func (e *ErrDecodeSecuredMessage) Error() string {
	return "decode secured message: " + e.Err.Error()
}
func (e *ErrDecodeSecuredMessage) Unwrap() error { return e.Err }

// ErrRequestSequenceNumber wraps request sequence number failures.
type ErrRequestSequenceNumber struct{ Err error }

func (e *ErrRequestSequenceNumber) Error() string {
	return "request sequence number: " + e.Err.Error()
}
func (e *ErrRequestSequenceNumber) Unwrap() error { return e.Err }

// ErrResponseSequenceNumber wraps response sequence number failures.
type ErrResponseSequenceNumber struct{ Err error }

func (e *ErrResponseSequenceNumber) Error() string {
	return "response sequence number: " + e.Err.Error()
}
func (e *ErrResponseSequenceNumber) Unwrap() error { return e.Err }

// --- PSK errors ---

// ErrPSKNotConfigured indicates no PSKProvider is configured.
type ErrPSKNotConfigured struct{}

func (e *ErrPSKNotConfigured) Error() string { return "PSKProvider not configured" }
func (e *ErrPSKNotConfigured) Unwrap() error { return nil }

// ErrPSKLookup wraps PSK lookup failures.
type ErrPSKLookup struct{ Err error }

func (e *ErrPSKLookup) Error() string { return "PSK lookup: " + e.Err.Error() }
func (e *ErrPSKLookup) Unwrap() error { return e.Err }

// ErrPSKVerifyDataMismatch indicates PSK_EXCHANGE_RSP verify data does not match.
type ErrPSKVerifyDataMismatch struct{}

func (e *ErrPSKVerifyDataMismatch) Error() string { return "PSK_EXCHANGE_RSP verify data mismatch" }
func (e *ErrPSKVerifyDataMismatch) Unwrap() error { return nil }

// ErrMarshalPSKExchange wraps PSK_EXCHANGE marshal failures.
type ErrMarshalPSKExchange struct{ Err error }

func (e *ErrMarshalPSKExchange) Error() string { return "marshal PSK exchange: " + e.Err.Error() }
func (e *ErrMarshalPSKExchange) Unwrap() error { return e.Err }

// ErrUnmarshalPSKExchangeResponse wraps PSK_EXCHANGE_RSP unmarshal failures.
type ErrUnmarshalPSKExchangeResponse struct{ Err error }

func (e *ErrUnmarshalPSKExchangeResponse) Error() string {
	return "unmarshal PSK exchange response: " + e.Err.Error()
}
func (e *ErrUnmarshalPSKExchangeResponse) Unwrap() error { return e.Err }

// ErrPSKFinish wraps PSK_FINISH request failures.
type ErrPSKFinish struct{ Err error }

func (e *ErrPSKFinish) Error() string { return "PSK finish: " + e.Err.Error() }
func (e *ErrPSKFinish) Unwrap() error { return e.Err }

// ErrUnmarshalPSKFinishResponse wraps PSK_FINISH_RSP unmarshal failures.
type ErrUnmarshalPSKFinishResponse struct{ Err error }

func (e *ErrUnmarshalPSKFinishResponse) Error() string {
	return "unmarshal PSK finish response: " + e.Err.Error()
}
func (e *ErrUnmarshalPSKFinishResponse) Unwrap() error { return e.Err }

// --- Finish errors ---

// ErrFinish wraps FINISH request failures.
type ErrFinish struct{ Err error }

func (e *ErrFinish) Error() string { return "finish: " + e.Err.Error() }
func (e *ErrFinish) Unwrap() error { return e.Err }

// ErrUnmarshalFinishResponse wraps FINISH_RSP unmarshal failures.
type ErrUnmarshalFinishResponse struct{ Err error }

func (e *ErrUnmarshalFinishResponse) Error() string {
	return "unmarshal finish response: " + e.Err.Error()
}
func (e *ErrUnmarshalFinishResponse) Unwrap() error { return e.Err }

// --- Certificate/Auth errors ---

// ErrGenerateNonce wraps nonce generation failures.
type ErrGenerateNonce struct{ Err error }

func (e *ErrGenerateNonce) Error() string { return "generate nonce: " + e.Err.Error() }
func (e *ErrGenerateNonce) Unwrap() error { return e.Err }

// ErrCertChainValidation wraps certificate chain validation failures.
type ErrCertChainValidation struct{ Err error }

func (e *ErrCertChainValidation) Error() string {
	return "certificate chain validation: " + e.Err.Error()
}
func (e *ErrCertChainValidation) Unwrap() error { return e.Err }

// ErrCertChainTooShort indicates a certificate chain is shorter than expected.
type ErrCertChainTooShort struct {
	Size    int
	MinSize int
}

func (e *ErrCertChainTooShort) Error() string {
	return fmt.Sprintf("chain too short: %d bytes, need at least %d", e.Size, e.MinSize)
}
func (e *ErrCertChainTooShort) Unwrap() error { return nil }

// ErrParseCertificates wraps certificate parsing failures.
type ErrParseCertificates struct{ Err error }

func (e *ErrParseCertificates) Error() string { return "parse certificates: " + e.Err.Error() }
func (e *ErrParseCertificates) Unwrap() error { return e.Err }

// ErrNoCertificatesInChain indicates no certificates were found in a chain.
type ErrNoCertificatesInChain struct{}

func (e *ErrNoCertificatesInChain) Error() string { return "no certificates in chain" }
func (e *ErrNoCertificatesInChain) Unwrap() error { return nil }

// ErrVerifyLeafCertificate wraps leaf certificate verification failures.
type ErrVerifyLeafCertificate struct{ Err error }

func (e *ErrVerifyLeafCertificate) Error() string {
	return "verify leaf certificate: " + e.Err.Error()
}
func (e *ErrVerifyLeafCertificate) Unwrap() error { return e.Err }

// ErrSignatureVerification wraps signature verification failures.
type ErrSignatureVerification struct{ Err error }

func (e *ErrSignatureVerification) Error() string {
	return "signature verification: " + e.Err.Error()
}
func (e *ErrSignatureVerification) Unwrap() error { return e.Err }

// ErrExtractPeerPublicKey wraps peer public key extraction failures.
type ErrExtractPeerPublicKey struct{ Err error }

func (e *ErrExtractPeerPublicKey) Error() string {
	return "extract peer public key: " + e.Err.Error()
}
func (e *ErrExtractPeerPublicKey) Unwrap() error { return e.Err }

// ErrVerify wraps cryptographic verify failures.
type ErrVerify struct{ Err error }

func (e *ErrVerify) Error() string { return "verify: " + e.Err.Error() }
func (e *ErrVerify) Unwrap() error { return e.Err }

// ErrNoPeerCertChain indicates no peer certificate chain is available.
type ErrNoPeerCertChain struct{}

func (e *ErrNoPeerCertChain) Error() string { return "no peer certificate chain available" }
func (e *ErrNoPeerCertChain) Unwrap() error { return nil }

// ErrPeerCertChainTooShort indicates the peer cert chain is too short.
type ErrPeerCertChainTooShort struct {
	Size    int
	MinSize int
}

func (e *ErrPeerCertChainTooShort) Error() string {
	return fmt.Sprintf("peer cert chain too short: %d bytes, need at least %d", e.Size, e.MinSize)
}
func (e *ErrPeerCertChainTooShort) Unwrap() error { return nil }

// ErrNoCertificatesFoundInChain indicates no certificates were found during extraction.
type ErrNoCertificatesFoundInChain struct{}

func (e *ErrNoCertificatesFoundInChain) Error() string { return "no certificates found in chain" }
func (e *ErrNoCertificatesFoundInChain) Unwrap() error { return nil }

// ErrDetermineCertLengthAtOffset wraps DER certificate length determination failures.
type ErrDetermineCertLengthAtOffset struct {
	Offset int
	Err    error
}

func (e *ErrDetermineCertLengthAtOffset) Error() string {
	return fmt.Sprintf("determine certificate length at offset %d: %v", e.Offset, e.Err)
}
func (e *ErrDetermineCertLengthAtOffset) Unwrap() error { return e.Err }

// ErrParseCertificateAtOffset wraps certificate parsing failures at a specific offset.
type ErrParseCertificateAtOffset struct {
	Offset int
	Err    error
}

func (e *ErrParseCertificateAtOffset) Error() string {
	return fmt.Sprintf("parse certificate at offset %d: %v", e.Offset, e.Err)
}
func (e *ErrParseCertificateAtOffset) Unwrap() error { return e.Err }

// ErrInvalidDER indicates invalid DER-encoded data.
type ErrInvalidDER struct {
	Reason string
}

func (e *ErrInvalidDER) Error() string { return e.Reason }
func (e *ErrInvalidDER) Unwrap() error { return nil }

// --- Chunk errors ---

// ErrChunkDataTransferSizeTooSmall indicates DataTransferSize is too small for chunking.
type ErrChunkDataTransferSizeTooSmall struct{}

func (e *ErrChunkDataTransferSizeTooSmall) Error() string {
	return "chunk_send: DataTransferSize too small for chunking"
}
func (e *ErrChunkDataTransferSizeTooSmall) Unwrap() error { return nil }

// ErrChunkSend wraps chunk send failures at a specific sequence number.
type ErrChunkSend struct {
	SeqNo uint16
	Err   error
}

func (e *ErrChunkSend) Error() string {
	return fmt.Sprintf("chunk_send: seq=%d: %v", e.SeqNo, e.Err)
}
func (e *ErrChunkSend) Unwrap() error { return e.Err }

// ErrChunkSendUnexpectedResponseCode indicates an unexpected response during chunk send.
type ErrChunkSendUnexpectedResponseCode struct {
	Code  uint8
	SeqNo uint16
}

func (e *ErrChunkSendUnexpectedResponseCode) Error() string {
	return fmt.Sprintf("chunk_send: unexpected response code 0x%02X at seq=%d", e.Code, e.SeqNo)
}
func (e *ErrChunkSendUnexpectedResponseCode) Unwrap() error { return nil }

// ErrChunkUnmarshalAck wraps chunk send ACK unmarshal failures.
type ErrChunkUnmarshalAck struct{ Err error }

func (e *ErrChunkUnmarshalAck) Error() string {
	return "chunk_send: unmarshal ack: " + e.Err.Error()
}
func (e *ErrChunkUnmarshalAck) Unwrap() error { return e.Err }

// ErrChunkSendEarlyError indicates an early error during chunk send.
type ErrChunkSendEarlyError struct {
	SeqNo uint16
}

func (e *ErrChunkSendEarlyError) Error() string {
	return fmt.Sprintf("chunk_send: early error at seq=%d", e.SeqNo)
}
func (e *ErrChunkSendEarlyError) Unwrap() error { return nil }

// ErrChunkGet wraps chunk get failures at a specific sequence number.
type ErrChunkGet struct {
	SeqNo uint16
	Err   error
}

func (e *ErrChunkGet) Error() string {
	return fmt.Sprintf("chunk_get: seq=%d: %v", e.SeqNo, e.Err)
}
func (e *ErrChunkGet) Unwrap() error { return e.Err }

// ErrChunkGetUnexpectedResponseCode indicates an unexpected response during chunk get.
type ErrChunkGetUnexpectedResponseCode struct {
	Code  uint8
	SeqNo uint16
}

func (e *ErrChunkGetUnexpectedResponseCode) Error() string {
	return fmt.Sprintf("chunk_get: unexpected response code 0x%02X at seq=%d", e.Code, e.SeqNo)
}
func (e *ErrChunkGetUnexpectedResponseCode) Unwrap() error { return nil }

// ErrChunkUnmarshalResponse wraps chunk get response unmarshal failures.
type ErrChunkUnmarshalResponse struct{ Err error }

func (e *ErrChunkUnmarshalResponse) Error() string {
	return "chunk_get: unmarshal: " + e.Err.Error()
}
func (e *ErrChunkUnmarshalResponse) Unwrap() error { return e.Err }

// --- Per-request-type errors ---

// ErrHeartbeat wraps heartbeat request failures.
type ErrHeartbeat struct{ Err error }

func (e *ErrHeartbeat) Error() string { return "heartbeat: " + e.Err.Error() }
func (e *ErrHeartbeat) Unwrap() error { return e.Err }

// ErrHeartbeatMarshal wraps heartbeat marshal failures.
type ErrHeartbeatMarshal struct{ Err error }

func (e *ErrHeartbeatMarshal) Error() string { return "heartbeat: marshal: " + e.Err.Error() }
func (e *ErrHeartbeatMarshal) Unwrap() error { return e.Err }

// ErrHeartbeatUnexpectedResponseCode indicates unexpected heartbeat response code.
type ErrHeartbeatUnexpectedResponseCode struct{ Code uint8 }

func (e *ErrHeartbeatUnexpectedResponseCode) Error() string {
	return fmt.Sprintf("heartbeat: unexpected response code 0x%02X", e.Code)
}
func (e *ErrHeartbeatUnexpectedResponseCode) Unwrap() error { return nil }

// ErrKeyUpdate wraps key update request failures.
type ErrKeyUpdate struct{ Err error }

func (e *ErrKeyUpdate) Error() string { return "key_update: " + e.Err.Error() }
func (e *ErrKeyUpdate) Unwrap() error { return e.Err }

// ErrKeyUpdateInvalidOp indicates an invalid key update operation.
type ErrKeyUpdateInvalidOp struct{ Operation uint8 }

func (e *ErrKeyUpdateInvalidOp) Error() string {
	return fmt.Sprintf("key_update: invalid operation %d", e.Operation)
}
func (e *ErrKeyUpdateInvalidOp) Unwrap() error { return nil }

// ErrKeyUpdateRequestKeys wraps key update request-direction key rotation failures.
type ErrKeyUpdateRequestKeys struct{ Err error }

func (e *ErrKeyUpdateRequestKeys) Error() string {
	return "key_update: update request keys: " + e.Err.Error()
}
func (e *ErrKeyUpdateRequestKeys) Unwrap() error { return e.Err }

// ErrKeyUpdateResponseKeys wraps key update response-direction key rotation failures.
type ErrKeyUpdateResponseKeys struct{ Err error }

func (e *ErrKeyUpdateResponseKeys) Error() string {
	return "key_update: update response keys: " + e.Err.Error()
}
func (e *ErrKeyUpdateResponseKeys) Unwrap() error { return e.Err }

// ErrKeyUpdateMarshal wraps key update marshal failures.
type ErrKeyUpdateMarshal struct{ Err error }

func (e *ErrKeyUpdateMarshal) Error() string { return "key_update: marshal: " + e.Err.Error() }
func (e *ErrKeyUpdateMarshal) Unwrap() error { return e.Err }

// ErrKeyUpdateUnexpectedResponseCode indicates unexpected key update response code.
type ErrKeyUpdateUnexpectedResponseCode struct{ Code uint8 }

func (e *ErrKeyUpdateUnexpectedResponseCode) Error() string {
	return fmt.Sprintf("key_update: unexpected response code 0x%02X", e.Code)
}
func (e *ErrKeyUpdateUnexpectedResponseCode) Unwrap() error { return nil }

// ErrEndSession wraps end session request failures.
type ErrEndSession struct{ Err error }

func (e *ErrEndSession) Error() string { return "end_session: " + e.Err.Error() }
func (e *ErrEndSession) Unwrap() error { return e.Err }

// ErrEndSessionMarshal wraps end session marshal failures.
type ErrEndSessionMarshal struct{ Err error }

func (e *ErrEndSessionMarshal) Error() string { return "end_session: marshal: " + e.Err.Error() }
func (e *ErrEndSessionMarshal) Unwrap() error { return e.Err }

// ErrEndSessionUnexpectedResponseCode indicates unexpected end session response code.
type ErrEndSessionUnexpectedResponseCode struct{ Code uint8 }

func (e *ErrEndSessionUnexpectedResponseCode) Error() string {
	return fmt.Sprintf("end_session: unexpected response code 0x%02X", e.Code)
}
func (e *ErrEndSessionUnexpectedResponseCode) Unwrap() error { return nil }

// ErrGetCSR wraps GET_CSR request failures.
type ErrGetCSR struct{ Err error }

func (e *ErrGetCSR) Error() string { return "get_csr: " + e.Err.Error() }
func (e *ErrGetCSR) Unwrap() error { return e.Err }

// ErrGetCSRUnexpectedResponseCode indicates unexpected GET_CSR response code.
type ErrGetCSRUnexpectedResponseCode struct{ Code uint8 }

func (e *ErrGetCSRUnexpectedResponseCode) Error() string {
	return fmt.Sprintf("get_csr: unexpected response code 0x%02X", e.Code)
}
func (e *ErrGetCSRUnexpectedResponseCode) Unwrap() error { return nil }

// ErrGetEndpointInfo wraps GET_ENDPOINT_INFO request failures.
type ErrGetEndpointInfo struct{ Err error }

func (e *ErrGetEndpointInfo) Error() string { return "get_endpoint_info: " + e.Err.Error() }
func (e *ErrGetEndpointInfo) Unwrap() error { return e.Err }

// ErrGetEndpointInfoUnexpectedResponseCode indicates unexpected GET_ENDPOINT_INFO response code.
type ErrGetEndpointInfoUnexpectedResponseCode struct{ Code uint8 }

func (e *ErrGetEndpointInfoUnexpectedResponseCode) Error() string {
	return fmt.Sprintf("get_endpoint_info: unexpected response code 0x%02X", e.Code)
}
func (e *ErrGetEndpointInfoUnexpectedResponseCode) Unwrap() error { return nil }

// ErrGetMEL wraps GET_MEASUREMENT_EXTENSION_LOG request failures.
type ErrGetMEL struct{ Err error }

func (e *ErrGetMEL) Error() string { return "get_mel: " + e.Err.Error() }
func (e *ErrGetMEL) Unwrap() error { return e.Err }

// ErrGetMELUnexpectedResponseCode indicates unexpected GET_MEL response code.
type ErrGetMELUnexpectedResponseCode struct{ Code uint8 }

func (e *ErrGetMELUnexpectedResponseCode) Error() string {
	return fmt.Sprintf("get_mel: unexpected response code 0x%02X", e.Code)
}
func (e *ErrGetMELUnexpectedResponseCode) Unwrap() error { return nil }

// ErrGetKeyPairInfo wraps GET_KEY_PAIR_INFO request failures.
type ErrGetKeyPairInfo struct{ Err error }

func (e *ErrGetKeyPairInfo) Error() string { return "get_key_pair_info: " + e.Err.Error() }
func (e *ErrGetKeyPairInfo) Unwrap() error { return e.Err }

// ErrGetKeyPairInfoUnexpectedResponseCode indicates unexpected GET_KEY_PAIR_INFO response code.
type ErrGetKeyPairInfoUnexpectedResponseCode struct{ Code uint8 }

func (e *ErrGetKeyPairInfoUnexpectedResponseCode) Error() string {
	return fmt.Sprintf("get_key_pair_info: unexpected response code 0x%02X", e.Code)
}
func (e *ErrGetKeyPairInfoUnexpectedResponseCode) Unwrap() error { return nil }

// ErrSetCertificate wraps SET_CERTIFICATE request failures.
type ErrSetCertificate struct{ Err error }

func (e *ErrSetCertificate) Error() string { return "set_certificate: " + e.Err.Error() }
func (e *ErrSetCertificate) Unwrap() error { return e.Err }

// ErrSetCertificateUnexpectedResponseCode indicates unexpected SET_CERTIFICATE response code.
type ErrSetCertificateUnexpectedResponseCode struct{ Code uint8 }

func (e *ErrSetCertificateUnexpectedResponseCode) Error() string {
	return fmt.Sprintf("set_certificate: unexpected response code 0x%02X", e.Code)
}
func (e *ErrSetCertificateUnexpectedResponseCode) Unwrap() error { return nil }

// ErrSetKeyPairInfo wraps SET_KEY_PAIR_INFO request failures.
type ErrSetKeyPairInfo struct{ Err error }

func (e *ErrSetKeyPairInfo) Error() string { return "set_key_pair_info: " + e.Err.Error() }
func (e *ErrSetKeyPairInfo) Unwrap() error { return e.Err }

// ErrSetKeyPairInfoUnexpectedResponseCode indicates unexpected SET_KEY_PAIR_INFO response code.
type ErrSetKeyPairInfoUnexpectedResponseCode struct{ Code uint8 }

func (e *ErrSetKeyPairInfoUnexpectedResponseCode) Error() string {
	return fmt.Sprintf("set_key_pair_info: unexpected response code 0x%02X", e.Code)
}
func (e *ErrSetKeyPairInfoUnexpectedResponseCode) Unwrap() error { return nil }

// ErrVendorDefined wraps VENDOR_DEFINED_REQUEST failures.
type ErrVendorDefined struct{ Err error }

func (e *ErrVendorDefined) Error() string { return "vendor_defined: " + e.Err.Error() }
func (e *ErrVendorDefined) Unwrap() error { return e.Err }

// ErrVendorDefinedUnexpectedResponseCode indicates unexpected VENDOR_DEFINED response code.
type ErrVendorDefinedUnexpectedResponseCode struct{ Code uint8 }

func (e *ErrVendorDefinedUnexpectedResponseCode) Error() string {
	return fmt.Sprintf("vendor_defined: unexpected response code 0x%02X", e.Code)
}
func (e *ErrVendorDefinedUnexpectedResponseCode) Unwrap() error { return nil }

// ErrGetEncapsulatedRequest wraps GET_ENCAPSULATED_REQUEST failures.
type ErrGetEncapsulatedRequest struct{ Err error }

func (e *ErrGetEncapsulatedRequest) Error() string {
	return "get_encapsulated_request: " + e.Err.Error()
}
func (e *ErrGetEncapsulatedRequest) Unwrap() error { return e.Err }

// ErrGetEncapsulatedRequestUnexpectedResponseCode indicates unexpected encapsulated request response code.
type ErrGetEncapsulatedRequestUnexpectedResponseCode struct{ Code uint8 }

func (e *ErrGetEncapsulatedRequestUnexpectedResponseCode) Error() string {
	return fmt.Sprintf("get_encapsulated_request: unexpected response code 0x%02X", e.Code)
}
func (e *ErrGetEncapsulatedRequestUnexpectedResponseCode) Unwrap() error { return nil }

// ErrDeliverEncapsulatedResponse wraps DELIVER_ENCAPSULATED_RESPONSE failures.
type ErrDeliverEncapsulatedResponse struct{ Err error }

func (e *ErrDeliverEncapsulatedResponse) Error() string {
	return "deliver_encapsulated_response: " + e.Err.Error()
}
func (e *ErrDeliverEncapsulatedResponse) Unwrap() error { return e.Err }

// ErrDeliverEncapsulatedResponseUnexpectedResponseCode indicates unexpected encapsulated response ACK code.
type ErrDeliverEncapsulatedResponseUnexpectedResponseCode struct{ Code uint8 }

func (e *ErrDeliverEncapsulatedResponseUnexpectedResponseCode) Error() string {
	return fmt.Sprintf("deliver_encapsulated_response: unexpected response code 0x%02X", e.Code)
}
func (e *ErrDeliverEncapsulatedResponseUnexpectedResponseCode) Unwrap() error { return nil }

// ErrGetSupportedEventTypes wraps GET_SUPPORTED_EVENT_TYPES failures.
type ErrGetSupportedEventTypes struct{ Err error }

func (e *ErrGetSupportedEventTypes) Error() string {
	return "get_supported_event_types: " + e.Err.Error()
}
func (e *ErrGetSupportedEventTypes) Unwrap() error { return e.Err }

// ErrGetSupportedEventTypesUnexpectedResponseCode indicates unexpected event types response code.
type ErrGetSupportedEventTypesUnexpectedResponseCode struct{ Code uint8 }

func (e *ErrGetSupportedEventTypesUnexpectedResponseCode) Error() string {
	return fmt.Sprintf("get_supported_event_types: unexpected response code 0x%02X", e.Code)
}
func (e *ErrGetSupportedEventTypesUnexpectedResponseCode) Unwrap() error { return nil }

// ErrSubscribeEventTypes wraps SUBSCRIBE_EVENT_TYPES failures.
type ErrSubscribeEventTypes struct{ Err error }

func (e *ErrSubscribeEventTypes) Error() string {
	return "subscribe_event_types: " + e.Err.Error()
}
func (e *ErrSubscribeEventTypes) Unwrap() error { return e.Err }

// ErrSubscribeEventTypesUnexpectedResponseCode indicates unexpected subscribe event types response code.
type ErrSubscribeEventTypesUnexpectedResponseCode struct{ Code uint8 }

func (e *ErrSubscribeEventTypesUnexpectedResponseCode) Error() string {
	return fmt.Sprintf("subscribe_event_types: unexpected response code 0x%02X", e.Code)
}
func (e *ErrSubscribeEventTypesUnexpectedResponseCode) Unwrap() error { return nil }

// ErrSendEvent wraps SEND_EVENT failures.
type ErrSendEvent struct{ Err error }

func (e *ErrSendEvent) Error() string { return "send_event: " + e.Err.Error() }
func (e *ErrSendEvent) Unwrap() error { return e.Err }

// ErrSendEventUnexpectedResponseCode indicates unexpected send event response code.
type ErrSendEventUnexpectedResponseCode struct{ Code uint8 }

func (e *ErrSendEventUnexpectedResponseCode) Error() string {
	return fmt.Sprintf("send_event: unexpected response code 0x%02X", e.Code)
}
func (e *ErrSendEventUnexpectedResponseCode) Unwrap() error { return nil }
