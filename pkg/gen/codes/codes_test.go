package codes

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allRequestCodes lists every defined RequestCode constant.
var allRequestCodes = []RequestCode{
	RequestGetDigests,
	RequestGetCertificate,
	RequestChallenge,
	RequestGetVersion,
	RequestChunkSend,
	RequestChunkGet,
	RequestGetEndpointInfo,
	RequestGetMeasurements,
	RequestGetCapabilities,
	RequestGetSupportedEventTypes,
	RequestNegotiateAlgorithms,
	RequestKeyExchange,
	RequestFinish,
	RequestPSKExchange,
	RequestPSKFinish,
	RequestHeartbeat,
	RequestKeyUpdate,
	RequestGetEncapsulatedRequest,
	RequestDeliverEncapsulatedResponse,
	RequestEndSession,
	RequestGetCSR,
	RequestSetCertificate,
	RequestGetMeasurementExtensionLog,
	RequestSubscribeEventTypes,
	RequestSendEvent,
	RequestGetKeyPairInfo,
	RequestSetKeyPairInfo,
	RequestVendorDefined,
	RequestRespondIfReady,
}

// allResponseCodes lists every defined ResponseCode constant.
var allResponseCodes = []ResponseCode{
	ResponseDigests,
	ResponseCertificate,
	ResponseChallengeAuth,
	ResponseVersion,
	ResponseChunkSendAck,
	ResponseChunkResponse,
	ResponseEndpointInfo,
	ResponseMeasurements,
	ResponseCapabilities,
	ResponseSupportedEventTypes,
	ResponseAlgorithms,
	ResponseKeyExchangeRsp,
	ResponseFinishRsp,
	ResponsePSKExchangeRsp,
	ResponsePSKFinishRsp,
	ResponseHeartbeatAck,
	ResponseKeyUpdateAck,
	ResponseEncapsulatedRequest,
	ResponseEncapsulatedResponseAck,
	ResponseEndSessionAck,
	ResponseCSR,
	ResponseSetCertificateRsp,
	ResponseMeasurementExtensionLog,
	ResponseSubscribeEventTypesAck,
	ResponseEventAck,
	ResponseKeyPairInfo,
	ResponseSetKeyPairInfoAck,
	ResponseVendorDefined,
	ResponseError,
}

// allErrorCodes lists every defined SPDMErrorCode constant.
var allErrorCodes = []SPDMErrorCode{
	ErrorInvalidRequest,
	ErrorBusy,
	ErrorUnexpectedRequest,
	ErrorUnspecified,
	ErrorDecryptError,
	ErrorUnsupportedRequest,
	ErrorRequestInFlight,
	ErrorInvalidResponseCode,
	ErrorSessionLimitExceeded,
	ErrorSessionRequired,
	ErrorResetRequired,
	ErrorResponseTooLarge,
	ErrorRequestTooLarge,
	ErrorLargeResponse,
	ErrorMessageLost,
	ErrorInvalidPolicy,
	ErrorVersionMismatch,
	ErrorResponseNotReady,
	ErrorRequestResynch,
	ErrorOperationFailed,
	ErrorNoPendingRequests,
	ErrorVendorDefined,
}

func TestRequestCodeString(t *testing.T) {
	for _, code := range allRequestCodes {
		t.Run(code.String(), func(t *testing.T) {
			s := code.String()
			assert.NotEmpty(t, s, "RequestCode(0x%02X).String() returned empty string", uint8(code))
			assert.False(t, strings.HasPrefix(s, "RequestCode("),
				"RequestCode(0x%02X).String() returned unknown format: %s", uint8(code), s)
		})
	}
}

func TestResponseCodeString(t *testing.T) {
	for _, code := range allResponseCodes {
		t.Run(code.String(), func(t *testing.T) {
			s := code.String()
			assert.NotEmpty(t, s, "ResponseCode(0x%02X).String() returned empty string", uint8(code))
			assert.False(t, strings.HasPrefix(s, "ResponseCode("),
				"ResponseCode(0x%02X).String() returned unknown format: %s", uint8(code), s)
		})
	}
}

func TestSPDMErrorCodeString(t *testing.T) {
	for _, code := range allErrorCodes {
		t.Run(code.String(), func(t *testing.T) {
			s := code.String()
			assert.NotEmpty(t, s, "SPDMErrorCode(0x%02X).String() returned empty string", uint8(code))
			assert.False(t, strings.HasPrefix(s, "SPDMErrorCode("),
				"SPDMErrorCode(0x%02X).String() returned unknown format: %s", uint8(code), s)
		})
	}
}

func TestRequestCodeNoDuplicates(t *testing.T) {
	seen := make(map[RequestCode]bool)
	for _, code := range allRequestCodes {
		assert.False(t, seen[code], "duplicate RequestCode value: 0x%02X", uint8(code))
		seen[code] = true
	}
}

func TestResponseCodeNoDuplicates(t *testing.T) {
	seen := make(map[ResponseCode]bool)
	for _, code := range allResponseCodes {
		assert.False(t, seen[code], "duplicate ResponseCode value: 0x%02X", uint8(code))
		seen[code] = true
	}
}

func TestSPDMErrorCodeNoDuplicates(t *testing.T) {
	seen := make(map[SPDMErrorCode]bool)
	for _, code := range allErrorCodes {
		assert.False(t, seen[code], "duplicate SPDMErrorCode value: 0x%02X", uint8(code))
		seen[code] = true
	}
}

func TestUnknownRequestCodeString(t *testing.T) {
	unknown := RequestCode(0x00)
	s := unknown.String()
	assert.True(t, strings.HasPrefix(s, "RequestCode("), "unknown RequestCode.String() = %q, want prefix 'RequestCode('", s)
	assert.Equal(t, "RequestCode(0x00)", s)
}

func TestUnknownResponseCodeString(t *testing.T) {
	unknown := ResponseCode(0xAA)
	s := unknown.String()
	assert.True(t, strings.HasPrefix(s, "ResponseCode("), "unknown ResponseCode.String() = %q, want prefix 'ResponseCode('", s)
	assert.Equal(t, "ResponseCode(0xAA)", s)
}

func TestUnknownSPDMErrorCodeString(t *testing.T) {
	unknown := SPDMErrorCode(0xBB)
	s := unknown.String()
	assert.True(t, strings.HasPrefix(s, "SPDMErrorCode("), "unknown SPDMErrorCode.String() = %q, want prefix 'SPDMErrorCode('", s)
	assert.Equal(t, "SPDMErrorCode(0xBB)", s)
}

// mappedRequestCodes are requests that have a corresponding response.
// RequestRespondIfReady is excluded because it doesn't map to a fixed response.
var mappedRequestCodes = []struct {
	req  RequestCode
	resp ResponseCode
}{
	{RequestGetDigests, ResponseDigests},
	{RequestGetCertificate, ResponseCertificate},
	{RequestChallenge, ResponseChallengeAuth},
	{RequestGetVersion, ResponseVersion},
	{RequestChunkSend, ResponseChunkSendAck},
	{RequestChunkGet, ResponseChunkResponse},
	{RequestGetEndpointInfo, ResponseEndpointInfo},
	{RequestGetMeasurements, ResponseMeasurements},
	{RequestGetCapabilities, ResponseCapabilities},
	{RequestGetSupportedEventTypes, ResponseSupportedEventTypes},
	{RequestNegotiateAlgorithms, ResponseAlgorithms},
	{RequestKeyExchange, ResponseKeyExchangeRsp},
	{RequestFinish, ResponseFinishRsp},
	{RequestPSKExchange, ResponsePSKExchangeRsp},
	{RequestPSKFinish, ResponsePSKFinishRsp},
	{RequestHeartbeat, ResponseHeartbeatAck},
	{RequestKeyUpdate, ResponseKeyUpdateAck},
	{RequestGetEncapsulatedRequest, ResponseEncapsulatedRequest},
	{RequestDeliverEncapsulatedResponse, ResponseEncapsulatedResponseAck},
	{RequestEndSession, ResponseEndSessionAck},
	{RequestGetCSR, ResponseCSR},
	{RequestSetCertificate, ResponseSetCertificateRsp},
	{RequestGetMeasurementExtensionLog, ResponseMeasurementExtensionLog},
	{RequestSubscribeEventTypes, ResponseSubscribeEventTypesAck},
	{RequestSendEvent, ResponseEventAck},
	{RequestGetKeyPairInfo, ResponseKeyPairInfo},
	{RequestSetKeyPairInfo, ResponseSetKeyPairInfoAck},
	{RequestVendorDefined, ResponseVendorDefined},
}

func TestResponseForRequest(t *testing.T) {
	for _, tc := range mappedRequestCodes {
		t.Run(tc.req.String(), func(t *testing.T) {
			got, ok := ResponseForRequest(tc.req)
			require.True(t, ok, "ResponseForRequest(%s) returned ok=false", tc.req)
			assert.Equal(t, tc.resp, got, "ResponseForRequest(%s)", tc.req)
		})
	}
}

func TestRequestForResponse(t *testing.T) {
	for _, tc := range mappedRequestCodes {
		t.Run(tc.resp.String(), func(t *testing.T) {
			got, ok := RequestForResponse(tc.resp)
			require.True(t, ok, "RequestForResponse(%s) returned ok=false", tc.resp)
			assert.Equal(t, tc.req, got, "RequestForResponse(%s)", tc.resp)
		})
	}
}

func TestRoundTrip(t *testing.T) {
	for _, tc := range mappedRequestCodes {
		t.Run(tc.req.String(), func(t *testing.T) {
			resp, ok := ResponseForRequest(tc.req)
			require.True(t, ok, "ResponseForRequest(%s) returned ok=false", tc.req)
			req, ok := RequestForResponse(resp)
			require.True(t, ok, "RequestForResponse(%s) returned ok=false", resp)
			assert.Equal(t, tc.req, req, "round-trip failed: %s -> %s -> %s", tc.req, resp, req)
		})
	}
}

func TestRespondIfReadyHasNoMapping(t *testing.T) {
	_, ok := ResponseForRequest(RequestRespondIfReady)
	assert.False(t, ok, "ResponseForRequest(RequestRespondIfReady) should return ok=false")
}

func TestResponseErrorHasNoMapping(t *testing.T) {
	_, ok := RequestForResponse(ResponseError)
	assert.False(t, ok, "RequestForResponse(ResponseError) should return ok=false")
}
