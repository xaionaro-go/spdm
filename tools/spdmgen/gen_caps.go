package main

import (
	"bytes"
	"fmt"
	"path/filepath"

	"github.com/xaionaro-go/spdm/internal/cheader"
)

type capFlag struct {
	cName    string
	goName   string
	flagName string // for String() output
	accessor string // HasXxxCap() method name, empty if none
}

var reqCapMapping = []capFlag{
	{"SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP", "ReqCertCap", "CERT", "HasCertCap"},
	{"SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP", "ReqChalCap", "CHAL", "HasChalCap"},
	{"SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP", "ReqEncryptCap", "ENCRYPT", "HasEncryptCap"},
	{"SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP", "ReqMACCap", "MAC", "HasMACCap"},
	{"SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP", "ReqMutAuthCap", "MUT_AUTH", "HasMutAuthCap"},
	{"SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP", "ReqKeyExCap", "KEY_EX", "HasKeyExCap"},
	{"SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER", "ReqPSKCapRequester", "PSK", "HasPSKCap"},
	{"SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP", "ReqEncapCap", "ENCAP", "HasEncapCap"},
	{"SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP", "ReqHBeatCap", "HBEAT", "HasHBeatCap"},
	{"SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP", "ReqKeyUpdCap", "KEY_UPD", "HasKeyUpdCap"},
	{"SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP", "ReqHandshakeInTheClearCap", "HANDSHAKE_IN_THE_CLEAR", "HasHandshakeInTheClearCap"},
	{"SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP", "ReqPubKeyIDCap", "PUB_KEY_ID", "HasPubKeyIDCap"},
	{"SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP", "ReqChunkCap", "CHUNK", "HasChunkCap"},
	{"SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_NO_SIG", "ReqEPInfoCapNoSig", "EP_INFO_NO_SIG", ""},
	{"SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG", "ReqEPInfoCapSig", "EP_INFO_SIG", ""},
	{"SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EVENT_CAP", "ReqEventCap", "EVENT", ""},
	{"SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_ONLY", "ReqMultiKeyCapOnly", "MULTI_KEY_ONLY", ""},
	{"SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_NEG", "ReqMultiKeyCapNeg", "MULTI_KEY_NEG", ""},
}

var rspCapMapping = []capFlag{
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP", "RspCacheCap", "CACHE", "HasCacheCap"},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP", "RspCertCap", "CERT", "HasCertCap"},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP", "RspChalCap", "CHAL", "HasChalCap"},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG", "RspMeasCapNoSig", "MEAS_NO_SIG", ""},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG", "RspMeasCapSig", "MEAS_SIG", ""},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP", "RspMeasFreshCap", "MEAS_FRESH", "HasMeasFreshCap"},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP", "RspEncryptCap", "ENCRYPT", "HasEncryptCap"},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP", "RspMACCap", "MAC", "HasMACCap"},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP", "RspMutAuthCap", "MUT_AUTH", "HasMutAuthCap"},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP", "RspKeyExCap", "KEY_EX", "HasKeyExCap"},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER", "RspPSKCapResponder", "PSK", ""},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT", "RspPSKCapResponderWithCtx", "PSK_WITH_CONTEXT", ""},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP", "RspEncapCap", "ENCAP", "HasEncapCap"},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP", "RspHBeatCap", "HBEAT", "HasHBeatCap"},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP", "RspKeyUpdCap", "KEY_UPD", "HasKeyUpdCap"},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP", "RspHandshakeInTheClearCap", "HANDSHAKE_IN_THE_CLEAR", "HasHandshakeInTheClearCap"},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP", "RspPubKeyIDCap", "PUB_KEY_ID", "HasPubKeyIDCap"},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP", "RspChunkCap", "CHUNK", "HasChunkCap"},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP", "RspAliasCertCap", "ALIAS_CERT", "HasAliasCertCap"},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_CERT_CAP", "RspSetCertCap", "SET_CERT", "HasSetCertCap"},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP", "RspCSRCap", "CSR", "HasCSRCap"},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP", "RspCertInstallResetCap", "CERT_INSTALL_RESET", "HasCertInstallResetCap"},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_NO_SIG", "RspEPInfoCapNoSig", "EP_INFO_NO_SIG", ""},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG", "RspEPInfoCapSig", "EP_INFO_SIG", ""},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP", "RspMELCap", "MEL", "HasMELCap"},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EVENT_CAP", "RspEventCap", "EVENT", "HasEventCap"},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP_ONLY", "RspMultiKeyCapOnly", "MULTI_KEY_ONLY", ""},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP_NEG", "RspMultiKeyCapNeg", "MULTI_KEY_NEG", ""},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_GET_KEY_PAIR_INFO_CAP", "RspGetKeyPairInfoCap", "GET_KEY_PAIR_INFO", "HasGetKeyPairInfoCap"},
	{"SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_KEY_PAIR_INFO_CAP", "RspSetKeyPairInfoCap", "SET_KEY_PAIR_INFO", "HasSetKeyPairInfoCap"},
}

func generateCaps(
	parsed *cheader.ParseResult,
	outDir string,
	verify bool,
) error {
	defineMap := buildDefineMap(parsed)

	if err := generateRequesterCaps(defineMap, outDir, verify); err != nil {
		return fmt.Errorf("requester.go: %w", err)
	}

	if err := generateResponderCaps(defineMap, outDir, verify); err != nil {
		return fmt.Errorf("responder.go: %w", err)
	}

	return nil
}

func generateRequesterCaps(
	defineMap map[string]uint64,
	outDir string,
	verify bool,
) error {
	var buf bytes.Buffer
	buf.WriteString(generatedHeader)
	buf.WriteString("package caps\n\nimport \"strings\"\n\n")
	buf.WriteString("// RequesterCaps represents SPDM requester capability flags per DSP0274 Table 14.\n")
	buf.WriteString("type RequesterCaps uint32\n\n")

	buf.WriteString("const (\n")
	for _, m := range reqCapMapping {
		val, ok := defineMap[m.cName]
		if !ok {
			return fmt.Errorf("missing define %s", m.cName)
		}
		buf.WriteString(fmt.Sprintf("\t%-25s RequesterCaps = 0x%08X\n", m.goName, val))
	}
	buf.WriteString(")\n\n")

	// Has, Set, Clear methods.
	buf.WriteString("// Has reports whether all bits in flag are set in c.\n")
	buf.WriteString("func (c RequesterCaps) Has(flag RequesterCaps) bool { return c&flag != 0 }\n\n")
	buf.WriteString("// Set returns c with all bits in flag set.\n")
	buf.WriteString("func (c RequesterCaps) Set(flag RequesterCaps) RequesterCaps { return c | flag }\n\n")
	buf.WriteString("// Clear returns c with all bits in flag cleared.\n")
	buf.WriteString("func (c RequesterCaps) Clear(flag RequesterCaps) RequesterCaps { return c &^ flag }\n\n")

	// Accessor methods.
	for _, m := range reqCapMapping {
		if m.accessor != "" {
			buf.WriteString(fmt.Sprintf("func (c RequesterCaps) %s() bool", m.accessor))
			// Align the opening brace.
			padding := 40 - len(m.accessor) - len("func (c RequesterCaps) () bool")
			if padding < 0 {
				padding = 0
			}
			buf.WriteString(fmt.Sprintf("%*s{ return c.Has(%s) }\n", padding, "", m.goName))
		}
	}
	buf.WriteString("\n")

	// Flag names for String().
	buf.WriteString("var reqFlagNames = []struct {\n\tflag RequesterCaps\n\tname string\n}{\n")
	for _, m := range reqCapMapping {
		buf.WriteString(fmt.Sprintf("\t{%s, %q},\n", m.goName, m.flagName))
	}
	buf.WriteString("}\n\n")

	// String method.
	buf.WriteString(`func (c RequesterCaps) String() string {
	if c == 0 {
		return ""
	}
	var parts []string
	for _, entry := range reqFlagNames {
		if c&entry.flag != 0 {
			parts = append(parts, entry.name)
		}
	}
	return strings.Join(parts, ",")
}
`)

	return writeOrVerify(filepath.Join(outDir, "requester.go"), buf.Bytes(), verify)
}

func generateResponderCaps(
	defineMap map[string]uint64,
	outDir string,
	verify bool,
) error {
	var buf bytes.Buffer
	buf.WriteString(generatedHeader)
	buf.WriteString("package caps\n\nimport \"strings\"\n\n")
	buf.WriteString("// ResponderCaps represents SPDM responder capability flags per DSP0274 Table 15.\n")
	buf.WriteString("type ResponderCaps uint32\n\n")

	buf.WriteString("const (\n")
	for _, m := range rspCapMapping {
		val, ok := defineMap[m.cName]
		if !ok {
			return fmt.Errorf("missing define %s", m.cName)
		}
		buf.WriteString(fmt.Sprintf("\t%-25s ResponderCaps = 0x%08X\n", m.goName, val))
	}
	buf.WriteString(")\n\n")

	// Has, Set, Clear methods.
	buf.WriteString("// Has reports whether all bits in flag are set in c.\n")
	buf.WriteString("func (c ResponderCaps) Has(flag ResponderCaps) bool { return c&flag != 0 }\n\n")
	buf.WriteString("// Set returns c with all bits in flag set.\n")
	buf.WriteString("func (c ResponderCaps) Set(flag ResponderCaps) ResponderCaps { return c | flag }\n\n")
	buf.WriteString("// Clear returns c with all bits in flag cleared.\n")
	buf.WriteString("func (c ResponderCaps) Clear(flag ResponderCaps) ResponderCaps { return c &^ flag }\n\n")

	// Accessor methods. The responder has special combined accessors.
	buf.WriteString("func (c ResponderCaps) HasCacheCap() bool               { return c.Has(RspCacheCap) }\n")
	buf.WriteString("func (c ResponderCaps) HasCertCap() bool                { return c.Has(RspCertCap) }\n")
	buf.WriteString("func (c ResponderCaps) HasChalCap() bool                { return c.Has(RspChalCap) }\n")
	buf.WriteString("func (c ResponderCaps) HasMeasCap() bool                { return c.Has(RspMeasCapNoSig) || c.Has(RspMeasCapSig) }\n")
	buf.WriteString("func (c ResponderCaps) HasMeasFreshCap() bool           { return c.Has(RspMeasFreshCap) }\n")
	buf.WriteString("func (c ResponderCaps) HasEncryptCap() bool             { return c.Has(RspEncryptCap) }\n")
	buf.WriteString("func (c ResponderCaps) HasMACCap() bool                 { return c.Has(RspMACCap) }\n")
	buf.WriteString("func (c ResponderCaps) HasMutAuthCap() bool             { return c.Has(RspMutAuthCap) }\n")
	buf.WriteString("func (c ResponderCaps) HasKeyExCap() bool               { return c.Has(RspKeyExCap) }\n")
	buf.WriteString("func (c ResponderCaps) HasPSKCap() bool                 { return c.Has(RspPSKCapResponder) || c.Has(RspPSKCapResponderWithCtx) }\n")
	buf.WriteString("func (c ResponderCaps) HasEncapCap() bool               { return c.Has(RspEncapCap) }\n")
	buf.WriteString("func (c ResponderCaps) HasHBeatCap() bool               { return c.Has(RspHBeatCap) }\n")
	buf.WriteString("func (c ResponderCaps) HasKeyUpdCap() bool              { return c.Has(RspKeyUpdCap) }\n")
	buf.WriteString("func (c ResponderCaps) HasHandshakeInTheClearCap() bool { return c.Has(RspHandshakeInTheClearCap) }\n")
	buf.WriteString("func (c ResponderCaps) HasPubKeyIDCap() bool            { return c.Has(RspPubKeyIDCap) }\n")
	buf.WriteString("func (c ResponderCaps) HasChunkCap() bool               { return c.Has(RspChunkCap) }\n")
	buf.WriteString("func (c ResponderCaps) HasAliasCertCap() bool           { return c.Has(RspAliasCertCap) }\n")
	buf.WriteString("func (c ResponderCaps) HasSetCertCap() bool             { return c.Has(RspSetCertCap) }\n")
	buf.WriteString("func (c ResponderCaps) HasCSRCap() bool                 { return c.Has(RspCSRCap) }\n")
	buf.WriteString("func (c ResponderCaps) HasCertInstallResetCap() bool    { return c.Has(RspCertInstallResetCap) }\n")
	buf.WriteString("func (c ResponderCaps) HasMELCap() bool                 { return c.Has(RspMELCap) }\n")
	buf.WriteString("func (c ResponderCaps) HasEventCap() bool               { return c.Has(RspEventCap) }\n")
	buf.WriteString("func (c ResponderCaps) HasGetKeyPairInfoCap() bool      { return c.Has(RspGetKeyPairInfoCap) }\n")
	buf.WriteString("func (c ResponderCaps) HasSetKeyPairInfoCap() bool      { return c.Has(RspSetKeyPairInfoCap) }\n")
	buf.WriteString("\n")

	// Flag names for String().
	buf.WriteString("var rspFlagNames = []struct {\n\tflag ResponderCaps\n\tname string\n}{\n")
	for _, m := range rspCapMapping {
		buf.WriteString(fmt.Sprintf("\t{%s, %q},\n", m.goName, m.flagName))
	}
	buf.WriteString("}\n\n")

	// String method.
	buf.WriteString(`func (c ResponderCaps) String() string {
	if c == 0 {
		return ""
	}
	var parts []string
	for _, entry := range rspFlagNames {
		if c&entry.flag != 0 {
			parts = append(parts, entry.name)
		}
	}
	return strings.Join(parts, ",")
}
`)

	return writeOrVerify(filepath.Join(outDir, "responder.go"), buf.Bytes(), verify)
}
