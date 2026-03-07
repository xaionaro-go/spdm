package main

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/xaionaro-go/spdm/internal/cheader"
)

// requestCodeMapping maps C #define names to Go constant names and String() values.
// The order matches the expected output in request.go.
var requestCodeMapping = []struct {
	cName     string
	goName    string
	stringVal string
}{
	{"SPDM_GET_DIGESTS", "RequestGetDigests", "GET_DIGESTS"},
	{"SPDM_GET_CERTIFICATE", "RequestGetCertificate", "GET_CERTIFICATE"},
	{"SPDM_CHALLENGE", "RequestChallenge", "CHALLENGE"},
	{"SPDM_GET_VERSION", "RequestGetVersion", "GET_VERSION"},
	{"SPDM_CHUNK_SEND", "RequestChunkSend", "CHUNK_SEND"},
	{"SPDM_CHUNK_GET", "RequestChunkGet", "CHUNK_GET"},
	{"SPDM_GET_ENDPOINT_INFO", "RequestGetEndpointInfo", "GET_ENDPOINT_INFO"},
	{"SPDM_GET_MEASUREMENTS", "RequestGetMeasurements", "GET_MEASUREMENTS"},
	{"SPDM_GET_CAPABILITIES", "RequestGetCapabilities", "GET_CAPABILITIES"},
	{"SPDM_GET_SUPPORTED_EVENT_TYPES", "RequestGetSupportedEventTypes", "GET_SUPPORTED_EVENT_TYPES"},
	{"SPDM_NEGOTIATE_ALGORITHMS", "RequestNegotiateAlgorithms", "NEGOTIATE_ALGORITHMS"},
	{"SPDM_KEY_EXCHANGE", "RequestKeyExchange", "KEY_EXCHANGE"},
	{"SPDM_FINISH", "RequestFinish", "FINISH"},
	{"SPDM_PSK_EXCHANGE", "RequestPSKExchange", "PSK_EXCHANGE"},
	{"SPDM_PSK_FINISH", "RequestPSKFinish", "PSK_FINISH"},
	{"SPDM_HEARTBEAT", "RequestHeartbeat", "HEARTBEAT"},
	{"SPDM_KEY_UPDATE", "RequestKeyUpdate", "KEY_UPDATE"},
	{"SPDM_GET_ENCAPSULATED_REQUEST", "RequestGetEncapsulatedRequest", "GET_ENCAPSULATED_REQUEST"},
	{"SPDM_DELIVER_ENCAPSULATED_RESPONSE", "RequestDeliverEncapsulatedResponse", "DELIVER_ENCAPSULATED_RESPONSE"},
	{"SPDM_END_SESSION", "RequestEndSession", "END_SESSION"},
	{"SPDM_GET_CSR", "RequestGetCSR", "GET_CSR"},
	{"SPDM_SET_CERTIFICATE", "RequestSetCertificate", "SET_CERTIFICATE"},
	{"SPDM_GET_MEASUREMENT_EXTENSION_LOG", "RequestGetMeasurementExtensionLog", "GET_MEASUREMENT_EXTENSION_LOG"},
	{"SPDM_SUBSCRIBE_EVENT_TYPES", "RequestSubscribeEventTypes", "SUBSCRIBE_EVENT_TYPES"},
	{"SPDM_SEND_EVENT", "RequestSendEvent", "SEND_EVENT"},
	{"SPDM_GET_KEY_PAIR_INFO", "RequestGetKeyPairInfo", "GET_KEY_PAIR_INFO"},
	{"SPDM_SET_KEY_PAIR_INFO", "RequestSetKeyPairInfo", "SET_KEY_PAIR_INFO"},
	{"SPDM_VENDOR_DEFINED_REQUEST", "RequestVendorDefined", "VENDOR_DEFINED_REQUEST"},
	{"SPDM_RESPOND_IF_READY", "RequestRespondIfReady", "RESPOND_IF_READY"},
}

// responseCodeMapping maps C #define names to Go constant names and String() values.
var responseCodeMapping = []struct {
	cName     string
	goName    string
	stringVal string
}{
	{"SPDM_DIGESTS", "ResponseDigests", "DIGESTS"},
	{"SPDM_CERTIFICATE", "ResponseCertificate", "CERTIFICATE"},
	{"SPDM_CHALLENGE_AUTH", "ResponseChallengeAuth", "CHALLENGE_AUTH"},
	{"SPDM_VERSION", "ResponseVersion", "VERSION"},
	{"SPDM_CHUNK_SEND_ACK", "ResponseChunkSendAck", "CHUNK_SEND_ACK"},
	{"SPDM_CHUNK_RESPONSE", "ResponseChunkResponse", "CHUNK_RESPONSE"},
	{"SPDM_ENDPOINT_INFO", "ResponseEndpointInfo", "ENDPOINT_INFO"},
	{"SPDM_MEASUREMENTS", "ResponseMeasurements", "MEASUREMENTS"},
	{"SPDM_CAPABILITIES", "ResponseCapabilities", "CAPABILITIES"},
	{"SPDM_SUPPORTED_EVENT_TYPES", "ResponseSupportedEventTypes", "SUPPORTED_EVENT_TYPES"},
	{"SPDM_ALGORITHMS", "ResponseAlgorithms", "ALGORITHMS"},
	{"SPDM_KEY_EXCHANGE_RSP", "ResponseKeyExchangeRsp", "KEY_EXCHANGE_RSP"},
	{"SPDM_FINISH_RSP", "ResponseFinishRsp", "FINISH_RSP"},
	{"SPDM_PSK_EXCHANGE_RSP", "ResponsePSKExchangeRsp", "PSK_EXCHANGE_RSP"},
	{"SPDM_PSK_FINISH_RSP", "ResponsePSKFinishRsp", "PSK_FINISH_RSP"},
	{"SPDM_HEARTBEAT_ACK", "ResponseHeartbeatAck", "HEARTBEAT_ACK"},
	{"SPDM_KEY_UPDATE_ACK", "ResponseKeyUpdateAck", "KEY_UPDATE_ACK"},
	{"SPDM_ENCAPSULATED_REQUEST", "ResponseEncapsulatedRequest", "ENCAPSULATED_REQUEST"},
	{"SPDM_ENCAPSULATED_RESPONSE_ACK", "ResponseEncapsulatedResponseAck", "ENCAPSULATED_RESPONSE_ACK"},
	{"SPDM_END_SESSION_ACK", "ResponseEndSessionAck", "END_SESSION_ACK"},
	{"SPDM_CSR", "ResponseCSR", "CSR"},
	{"SPDM_SET_CERTIFICATE_RSP", "ResponseSetCertificateRsp", "SET_CERTIFICATE_RSP"},
	{"SPDM_MEASUREMENT_EXTENSION_LOG", "ResponseMeasurementExtensionLog", "MEASUREMENT_EXTENSION_LOG"},
	{"SPDM_SUBSCRIBE_EVENT_TYPES_ACK", "ResponseSubscribeEventTypesAck", "SUBSCRIBE_EVENT_TYPES_ACK"},
	{"SPDM_EVENT_ACK", "ResponseEventAck", "EVENT_ACK"},
	{"SPDM_KEY_PAIR_INFO", "ResponseKeyPairInfo", "KEY_PAIR_INFO"},
	{"SPDM_SET_KEY_PAIR_INFO_ACK", "ResponseSetKeyPairInfoAck", "SET_KEY_PAIR_INFO_ACK"},
	{"SPDM_VENDOR_DEFINED_RESPONSE", "ResponseVendorDefined", "VENDOR_DEFINED_RESPONSE"},
	{"SPDM_ERROR", "ResponseError", "ERROR"},
}

// errorCodeMapping maps C error #define names to Go constant names and String() values.
var errorCodeMapping = []struct {
	cName     string
	goName    string
	stringVal string
}{
	{"SPDM_ERROR_CODE_INVALID_REQUEST", "ErrorInvalidRequest", "INVALID_REQUEST"},
	{"SPDM_ERROR_CODE_BUSY", "ErrorBusy", "BUSY"},
	{"SPDM_ERROR_CODE_UNEXPECTED_REQUEST", "ErrorUnexpectedRequest", "UNEXPECTED_REQUEST"},
	{"SPDM_ERROR_CODE_UNSPECIFIED", "ErrorUnspecified", "UNSPECIFIED"},
	{"SPDM_ERROR_CODE_DECRYPT_ERROR", "ErrorDecryptError", "DECRYPT_ERROR"},
	{"SPDM_ERROR_CODE_UNSUPPORTED_REQUEST", "ErrorUnsupportedRequest", "UNSUPPORTED_REQUEST"},
	{"SPDM_ERROR_CODE_REQUEST_IN_FLIGHT", "ErrorRequestInFlight", "REQUEST_IN_FLIGHT"},
	{"SPDM_ERROR_CODE_INVALID_RESPONSE_CODE", "ErrorInvalidResponseCode", "INVALID_RESPONSE_CODE"},
	{"SPDM_ERROR_CODE_SESSION_LIMIT_EXCEEDED", "ErrorSessionLimitExceeded", "SESSION_LIMIT_EXCEEDED"},
	{"SPDM_ERROR_CODE_SESSION_REQUIRED", "ErrorSessionRequired", "SESSION_REQUIRED"},
	{"SPDM_ERROR_CODE_RESET_REQUIRED", "ErrorResetRequired", "RESET_REQUIRED"},
	{"SPDM_ERROR_CODE_RESPONSE_TOO_LARGE", "ErrorResponseTooLarge", "RESPONSE_TOO_LARGE"},
	{"SPDM_ERROR_CODE_REQUEST_TOO_LARGE", "ErrorRequestTooLarge", "REQUEST_TOO_LARGE"},
	{"SPDM_ERROR_CODE_LARGE_RESPONSE", "ErrorLargeResponse", "LARGE_RESPONSE"},
	{"SPDM_ERROR_CODE_MESSAGE_LOST", "ErrorMessageLost", "MESSAGE_LOST"},
	{"SPDM_ERROR_CODE_INVALID_POLICY", "ErrorInvalidPolicy", "INVALID_POLICY"},
	{"SPDM_ERROR_CODE_VERSION_MISMATCH", "ErrorVersionMismatch", "VERSION_MISMATCH"},
	{"SPDM_ERROR_CODE_RESPONSE_NOT_READY", "ErrorResponseNotReady", "RESPONSE_NOT_READY"},
	{"SPDM_ERROR_CODE_REQUEST_RESYNCH", "ErrorRequestResynch", "REQUEST_RESYNCH"},
	{"SPDM_ERROR_CODE_OPERATION_FAILED", "ErrorOperationFailed", "OPERATION_FAILED"},
	{"SPDM_ERROR_CODE_NO_PENDING_REQUESTS", "ErrorNoPendingRequests", "NO_PENDING_REQUESTS"},
	{"SPDM_ERROR_CODE_VENDOR_DEFINED", "ErrorVendorDefined", "VENDOR_DEFINED"},
}

// requestResponsePairMapping maps request Go names to response Go names for mapping.go.
var requestResponsePairMapping = []struct {
	reqGoName  string
	respGoName string
}{
	{"RequestGetDigests", "ResponseDigests"},
	{"RequestGetCertificate", "ResponseCertificate"},
	{"RequestChallenge", "ResponseChallengeAuth"},
	{"RequestGetVersion", "ResponseVersion"},
	{"RequestChunkSend", "ResponseChunkSendAck"},
	{"RequestChunkGet", "ResponseChunkResponse"},
	{"RequestGetEndpointInfo", "ResponseEndpointInfo"},
	{"RequestGetMeasurements", "ResponseMeasurements"},
	{"RequestGetCapabilities", "ResponseCapabilities"},
	{"RequestGetSupportedEventTypes", "ResponseSupportedEventTypes"},
	{"RequestNegotiateAlgorithms", "ResponseAlgorithms"},
	{"RequestKeyExchange", "ResponseKeyExchangeRsp"},
	{"RequestFinish", "ResponseFinishRsp"},
	{"RequestPSKExchange", "ResponsePSKExchangeRsp"},
	{"RequestPSKFinish", "ResponsePSKFinishRsp"},
	{"RequestHeartbeat", "ResponseHeartbeatAck"},
	{"RequestKeyUpdate", "ResponseKeyUpdateAck"},
	{"RequestGetEncapsulatedRequest", "ResponseEncapsulatedRequest"},
	{"RequestDeliverEncapsulatedResponse", "ResponseEncapsulatedResponseAck"},
	{"RequestEndSession", "ResponseEndSessionAck"},
	{"RequestGetCSR", "ResponseCSR"},
	{"RequestSetCertificate", "ResponseSetCertificateRsp"},
	{"RequestGetMeasurementExtensionLog", "ResponseMeasurementExtensionLog"},
	{"RequestSubscribeEventTypes", "ResponseSubscribeEventTypesAck"},
	{"RequestSendEvent", "ResponseEventAck"},
	{"RequestGetKeyPairInfo", "ResponseKeyPairInfo"},
	{"RequestSetKeyPairInfo", "ResponseSetKeyPairInfoAck"},
	{"RequestVendorDefined", "ResponseVendorDefined"},
}

func generateCodes(
	parsed *cheader.ParseResult,
	outDir string,
	verify bool,
) error {
	defineMap := buildDefineMap(parsed)

	if err := generateRequestCodes(defineMap, outDir, verify); err != nil {
		return fmt.Errorf("request.go: %w", err)
	}

	if err := generateResponseCodes(defineMap, outDir, verify); err != nil {
		return fmt.Errorf("response.go: %w", err)
	}

	if err := generateErrorCodes(defineMap, outDir, verify); err != nil {
		return fmt.Errorf("error.go: %w", err)
	}

	if err := generateMapping(outDir, verify); err != nil {
		return fmt.Errorf("mapping.go: %w", err)
	}

	return nil
}

func buildDefineMap(parsed *cheader.ParseResult) map[string]uint64 {
	m := make(map[string]uint64, len(parsed.Defines))
	for _, d := range parsed.Defines {
		m[d.Name] = d.Value
	}
	return m
}

func generateRequestCodes(
	defineMap map[string]uint64,
	outDir string,
	verify bool,
) error {
	var buf bytes.Buffer
	buf.WriteString(generatedHeader)
	buf.WriteString("package codes\n\nimport \"fmt\"\n\n")
	buf.WriteString("// RequestCode represents an SPDM request message code per DSP0274 Table 5.\n")
	buf.WriteString("type RequestCode uint8\n\n")

	buf.WriteString("const (\n")
	for _, m := range requestCodeMapping {
		val, ok := defineMap[m.cName]
		if !ok {
			return fmt.Errorf("missing define %s", m.cName)
		}
		// Compute the longest goName for alignment.
		buf.WriteString(fmt.Sprintf("\t%-41s RequestCode = 0x%02X\n", m.goName, val))
	}
	buf.WriteString(")\n\n")

	buf.WriteString("func (c RequestCode) String() string {\n")
	buf.WriteString("\tswitch c {\n")
	for _, m := range requestCodeMapping {
		buf.WriteString(fmt.Sprintf("\tcase %s:\n\t\treturn %q\n", m.goName, m.stringVal))
	}
	buf.WriteString("\tdefault:\n")
	buf.WriteString("\t\treturn fmt.Sprintf(\"RequestCode(0x%02X)\", uint8(c))\n")
	buf.WriteString("\t}\n}\n")

	return writeOrVerify(filepath.Join(outDir, "request.go"), buf.Bytes(), verify)
}

func generateResponseCodes(
	defineMap map[string]uint64,
	outDir string,
	verify bool,
) error {
	var buf bytes.Buffer
	buf.WriteString(generatedHeader)
	buf.WriteString("package codes\n\nimport \"fmt\"\n\n")
	buf.WriteString("// ResponseCode represents an SPDM response message code per DSP0274 Table 6.\n")
	buf.WriteString("type ResponseCode uint8\n\n")

	buf.WriteString("const (\n")
	for _, m := range responseCodeMapping {
		val, ok := defineMap[m.cName]
		if !ok {
			return fmt.Errorf("missing define %s", m.cName)
		}
		buf.WriteString(fmt.Sprintf("\t%-40s ResponseCode = 0x%02X\n", m.goName, val))
	}
	buf.WriteString(")\n\n")

	buf.WriteString("func (c ResponseCode) String() string {\n")
	buf.WriteString("\tswitch c {\n")
	for _, m := range responseCodeMapping {
		buf.WriteString(fmt.Sprintf("\tcase %s:\n\t\treturn %q\n", m.goName, m.stringVal))
	}
	buf.WriteString("\tdefault:\n")
	buf.WriteString("\t\treturn fmt.Sprintf(\"ResponseCode(0x%02X)\", uint8(c))\n")
	buf.WriteString("\t}\n}\n")

	return writeOrVerify(filepath.Join(outDir, "response.go"), buf.Bytes(), verify)
}

func generateErrorCodes(
	defineMap map[string]uint64,
	outDir string,
	verify bool,
) error {
	var buf bytes.Buffer
	buf.WriteString(generatedHeader)
	buf.WriteString("package codes\n\nimport \"fmt\"\n\n")
	buf.WriteString("// SPDMErrorCode represents an SPDM protocol error code per DSP0274 Table 40.\n")
	buf.WriteString("type SPDMErrorCode uint8\n\n")

	buf.WriteString("const (\n")
	for _, m := range errorCodeMapping {
		val, ok := defineMap[m.cName]
		if !ok {
			return fmt.Errorf("missing define %s", m.cName)
		}
		buf.WriteString(fmt.Sprintf("\t%-29s SPDMErrorCode = 0x%02X\n", m.goName, val))
	}
	buf.WriteString(")\n\n")

	buf.WriteString("func (c SPDMErrorCode) String() string {\n")
	buf.WriteString("\tswitch c {\n")
	for _, m := range errorCodeMapping {
		buf.WriteString(fmt.Sprintf("\tcase %s:\n\t\treturn %q\n", m.goName, m.stringVal))
	}
	buf.WriteString("\tdefault:\n")
	buf.WriteString("\t\treturn fmt.Sprintf(\"SPDMErrorCode(0x%02X)\", uint8(c))\n")
	buf.WriteString("\t}\n}\n")

	return writeOrVerify(filepath.Join(outDir, "error.go"), buf.Bytes(), verify)
}

func generateMapping(
	outDir string,
	verify bool,
) error {
	var buf bytes.Buffer
	buf.WriteString(generatedHeader)
	buf.WriteString("package codes\n\n")

	buf.WriteString("// requestToResponse maps each request code to its corresponding response code per DSP0274 Table 5/6.\n")
	buf.WriteString("var requestToResponse = map[RequestCode]ResponseCode{\n")
	for _, m := range requestResponsePairMapping {
		// Compute padding so the colon aligns.
		padding := 42 - len(m.reqGoName)
		if padding < 1 {
			padding = 1
		}
		buf.WriteString(fmt.Sprintf("\t%s:%s%s,\n", m.reqGoName, strings.Repeat(" ", padding), m.respGoName))
	}
	buf.WriteString("}\n\n")

	buf.WriteString(`// responseToRequest is the reverse mapping, built from requestToResponse.
var responseToRequest map[ResponseCode]RequestCode

func init() {
	responseToRequest = make(map[ResponseCode]RequestCode, len(requestToResponse))
	for req, resp := range requestToResponse {
		responseToRequest[resp] = req
	}
}

// ResponseForRequest returns the expected response code for the given request code.
// The second return value is false if the request code has no mapped response
// (e.g., RequestRespondIfReady does not have a fixed response code).
func ResponseForRequest(req RequestCode) (ResponseCode, bool) {
	resp, ok := requestToResponse[req]
	return resp, ok
}

// RequestForResponse returns the request code that produces the given response code.
// The second return value is false if the response code has no mapped request
// (e.g., ResponseError is not tied to a single request).
func RequestForResponse(resp ResponseCode) (RequestCode, bool) {
	req, ok := responseToRequest[resp]
	return req, ok
}
`)

	return writeOrVerify(filepath.Join(outDir, "mapping.go"), buf.Bytes(), verify)
}
