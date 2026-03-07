package responder

import (
	"context"
	"math/bits"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/caps"
	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

// --- helpers ---

// expectError unmarshals resp as an ErrorResponse and asserts the error code matches want.
func expectError(t *testing.T, resp []byte, want codes.SPDMErrorCode) {
	t.Helper()
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	require.Equal(t, uint8(codes.ResponseError), errResp.Header.RequestResponseCode)
	assert.Equal(t, want, errResp.ErrorCode())
}

// doVersion sends GET_VERSION and returns the response.
func doVersion(t *testing.T, r *Responder) []byte {
	t.Helper()
	resp, err := r.ProcessMessage(context.Background(), buildGetVersion())
	require.NoError(t, err)
	return resp
}

// doCapabilities sends GET_CAPABILITIES and returns the response.
func doCapabilities(t *testing.T, r *Responder) []byte {
	t.Helper()
	resp, err := r.ProcessMessage(context.Background(), buildGetCapabilities())
	require.NoError(t, err)
	return resp
}

// doNegotiate sends NEGOTIATE_ALGORITHMS and returns the response.
func doNegotiate(t *testing.T, r *Responder) []byte {
	t.Helper()
	resp, err := r.ProcessMessage(context.Background(), buildNegotiateAlgorithms())
	require.NoError(t, err)
	return resp
}

// doFullNegotiation drives the responder through GET_VERSION, GET_CAPABILITIES, NEGOTIATE_ALGORITHMS.
func doFullNegotiation(t *testing.T, r *Responder) {
	t.Helper()
	doVersion(t, r)
	doCapabilities(t, r)
	doNegotiate(t, r)
}

// buildGetCapabilitiesCustom builds a GET_CAPABILITIES request with custom fields.
func buildGetCapabilitiesCustom(flags uint32, dataTransferSize, maxSPDMmsgSize uint32) []byte {
	req := &msgs.GetCapabilities{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetCapabilities),
		}},
		Flags:            flags,
		DataTransferSize: dataTransferSize,
		MaxSPDMmsgSize:   maxSPDMmsgSize,
	}
	data, _ := req.Marshal()
	return data
}

// --- 1. State Machine Enforcement (DSP0274 Section 9) ---

// TestConformance_CapabilitiesBeforeVersion verifies that sending GET_CAPABILITIES
// before GET_VERSION returns ERROR(UnexpectedRequest) per DSP0274 Section 9.
func TestConformance_CapabilitiesBeforeVersion(t *testing.T) {
	r := newTestResponder()
	resp, err := r.ProcessMessage(context.Background(), buildGetCapabilities())
	require.NoError(t, err)
	expectError(t, resp, codes.ErrorUnexpectedRequest)
}

// TestConformance_AlgorithmsBeforeCapabilities verifies that sending NEGOTIATE_ALGORITHMS
// before GET_CAPABILITIES returns ERROR(UnexpectedRequest) per DSP0274 Section 9.
func TestConformance_AlgorithmsBeforeCapabilities(t *testing.T) {
	r := newTestResponder()
	doVersion(t, r)
	resp, err := r.ProcessMessage(context.Background(), buildNegotiateAlgorithms())
	require.NoError(t, err)
	expectError(t, resp, codes.ErrorUnexpectedRequest)
}

// TestConformance_DigestsBeforeNegotiation verifies that sending GET_DIGESTS
// before algorithm negotiation returns ERROR(UnexpectedRequest) per DSP0274 Section 9.
func TestConformance_DigestsBeforeNegotiation(t *testing.T) {
	r := newTestResponder()
	r.cfg.CertProvider = &mockCertProvider{
		digests: map[uint8][]byte{0: make([]byte, 32)},
	}
	doVersion(t, r)
	doCapabilities(t, r)
	// Skip NEGOTIATE_ALGORITHMS.
	req := &msgs.GetDigests{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetDigests),
		}},
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)
	expectError(t, resp, codes.ErrorUnexpectedRequest)
}

// TestConformance_ChallengeBeforeNegotiation verifies that sending CHALLENGE
// before negotiation returns ERROR(UnexpectedRequest) per DSP0274 Section 9.
func TestConformance_ChallengeBeforeNegotiation(t *testing.T) {
	r := newTestResponder()
	doVersion(t, r)
	doCapabilities(t, r)
	req := &msgs.Challenge{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestChallenge),
			Param1:              0,
			Param2:              0x00,
		}},
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)
	expectError(t, resp, codes.ErrorUnexpectedRequest)
}

// TestConformance_MeasurementsBeforeNegotiation verifies that sending GET_MEASUREMENTS
// before negotiation returns ERROR(UnexpectedRequest) per DSP0274 Section 9.
func TestConformance_MeasurementsBeforeNegotiation(t *testing.T) {
	r := newTestResponder()
	r.cfg.MeasProvider = &mockMeasProvider{
		blocks: []msgs.MeasurementBlock{
			{Index: 1, Spec: 0x01, ValueType: 0x01, Value: []byte("fw")},
		},
	}
	doVersion(t, r)
	doCapabilities(t, r)
	req := &msgs.GetMeasurements{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetMeasurements),
			Param2:              0,
		}},
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)
	expectError(t, resp, codes.ErrorUnexpectedRequest)
}

// TestConformance_GetVersionResetsState verifies that GET_VERSION resets
// connection state from any state per DSP0274 Section 10.3.
func TestConformance_GetVersionResetsState(t *testing.T) {
	r := newTestResponder()

	// Drive to StateNegotiated.
	doFullNegotiation(t, r)
	require.Equal(t, StateNegotiated, r.state)

	// GET_VERSION resets to StateAfterVersion.
	resp := doVersion(t, r)
	var vr msgs.VersionResponse
	require.NoError(t, vr.Unmarshal(resp))
	require.Equal(t, uint8(codes.ResponseVersion), vr.Header.RequestResponseCode)
	assert.Equal(t, StateAfterVersion, r.state)
	assert.False(t, r.negotiated, "expected negotiated=false after GET_VERSION reset")
	assert.Zero(t, r.version, "expected version=0 after GET_VERSION reset")

	// Verify we can't send NEGOTIATE_ALGORITHMS directly (need GET_CAPABILITIES first).
	resp, err := r.ProcessMessage(context.Background(), buildNegotiateAlgorithms())
	require.NoError(t, err)
	expectError(t, resp, codes.ErrorUnexpectedRequest)

	// Full sequence should work again.
	doCapabilities(t, r)
	doNegotiate(t, r)
	assert.Equal(t, StateNegotiated, r.state)
}

// --- 2. Version Response Conformance (DSP0274 Section 10.3) ---

// TestConformance_VersionResponseFieldIs0x10 verifies that the SPDMVersion field
// in VERSION response is always 0x10 regardless of negotiated version per DSP0274 Section 10.3.
func TestConformance_VersionResponseFieldIs0x10(t *testing.T) {
	versions := [][]algo.Version{
		{algo.Version10},
		{algo.Version11},
		{algo.Version12},
		{algo.Version10, algo.Version11, algo.Version12},
	}
	for _, vv := range versions {
		r := New(Config{
			Versions:     vv,
			BaseAsymAlgo: algo.AsymECDSAP256,
			BaseHashAlgo: algo.HashSHA256,
		})
		resp := doVersion(t, r)
		var vr msgs.VersionResponse
		require.NoError(t, vr.Unmarshal(resp))
		assert.Equal(t, uint8(0x10), vr.Header.SPDMVersion)
	}
}

// TestConformance_VersionResponseEntryCountGeOne verifies that VERSION response
// contains at least one version entry per DSP0274 Section 10.3.
func TestConformance_VersionResponseEntryCountGeOne(t *testing.T) {
	r := newTestResponder()
	resp := doVersion(t, r)
	var vr msgs.VersionResponse
	require.NoError(t, vr.Unmarshal(resp))
	assert.GreaterOrEqual(t, len(vr.VersionEntries), 1)
	assert.GreaterOrEqual(t, int(vr.VersionNumberEntryCount), 1)
}

// TestConformance_VersionResponseUniqueEntries verifies that VERSION response
// contains no duplicate entries per DSP0274 Section 10.3.
func TestConformance_VersionResponseUniqueEntries(t *testing.T) {
	r := New(Config{
		Versions:     []algo.Version{algo.Version10, algo.Version11, algo.Version12},
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})
	resp := doVersion(t, r)
	var vr msgs.VersionResponse
	require.NoError(t, vr.Unmarshal(resp))
	seen := make(map[uint16]bool)
	for _, entry := range vr.VersionEntries {
		assert.False(t, seen[entry])
		seen[entry] = true
	}
}

// --- 3. Capability Validation (DSP0274 Section 10.4) ---

// TestConformance_CapabilitiesDataTransferSizeMin42 verifies that DataTransferSize < 42
// returns an error per DSP0274 Section 10.4.
func TestConformance_CapabilitiesDataTransferSizeMin42(t *testing.T) {
	r := newTestResponder()
	doVersion(t, r)

	resp, err := r.ProcessMessage(context.Background(),
		buildGetCapabilitiesCustom(uint32(caps.ReqCertCap), 41, 65536))
	require.NoError(t, err)
	expectError(t, resp, codes.ErrorInvalidRequest)
}

// TestConformance_CapabilitiesIdenticalReplay verifies that sending identical
// GET_CAPABILITIES twice is accepted per DSP0274 Section 10.4.
func TestConformance_CapabilitiesIdenticalReplay(t *testing.T) {
	r := newTestResponder()
	doVersion(t, r)

	capsReq := buildGetCapabilities()

	// First request.
	resp1, err := r.ProcessMessage(context.Background(), capsReq)
	require.NoError(t, err)
	var cr1 msgs.CapabilitiesResponse
	require.NoError(t, cr1.Unmarshal(resp1))
	require.Equal(t, uint8(codes.ResponseCapabilities), cr1.Header.RequestResponseCode)

	// Second identical request.
	resp2, err := r.ProcessMessage(context.Background(), capsReq)
	require.NoError(t, err)
	var cr2 msgs.CapabilitiesResponse
	require.NoError(t, cr2.Unmarshal(resp2))
	assert.Equal(t, uint8(codes.ResponseCapabilities), cr2.Header.RequestResponseCode)
}

// TestConformance_CapabilitiesNonIdenticalReplay verifies that sending a different
// GET_CAPABILITIES after the first returns ERROR(UnexpectedRequest) per DSP0274 Section 10.4.
func TestConformance_CapabilitiesNonIdenticalReplay(t *testing.T) {
	r := newTestResponder()
	doVersion(t, r)

	// First request with one set of flags.
	resp, err := r.ProcessMessage(context.Background(), buildGetCapabilities())
	require.NoError(t, err)
	var cr msgs.CapabilitiesResponse
	require.NoError(t, cr.Unmarshal(resp))
	require.Equal(t, uint8(codes.ResponseCapabilities), cr.Header.RequestResponseCode)

	// Second request with different flags.
	resp, err = r.ProcessMessage(context.Background(),
		buildGetCapabilitiesCustom(uint32(caps.ReqEncryptCap|caps.ReqMACCap), 4096, 65536))
	require.NoError(t, err)
	expectError(t, resp, codes.ErrorUnexpectedRequest)
}

// --- 4. Algorithm Selection Validation (DSP0274 Section 10.5) ---

// TestConformance_AlgorithmSelectionIsSingleBit verifies that each selected algorithm
// in the ALGORITHMS response has exactly one bit set per DSP0274 Section 10.5.
func TestConformance_AlgorithmSelectionIsSingleBit(t *testing.T) {
	r := newTestResponder()
	doVersion(t, r)
	doCapabilities(t, r)
	resp := doNegotiate(t, r)

	var ar msgs.AlgorithmsResponse
	require.NoError(t, ar.Unmarshal(resp))

	// BaseAsymSel must have exactly one bit set.
	assert.Equal(t, 1, bits.OnesCount32(ar.BaseAsymSel))

	// BaseHashSel must have exactly one bit set.
	assert.Equal(t, 1, bits.OnesCount32(ar.BaseHashSel))

	// Each AlgStruct selection must have 0 or 1 bit set.
	for _, a := range ar.AlgStructs {
		assert.LessOrEqual(t, bits.OnesCount16(a.AlgSupported), 1,
			"AlgType=%d: AlgSupported=0x%04X", a.AlgType, a.AlgSupported)
	}
}

// TestConformance_AlgorithmSelectionIsSubset verifies that selected algorithms
// are a subset of the requested algorithms per DSP0274 Section 10.5.
func TestConformance_AlgorithmSelectionIsSubset(t *testing.T) {
	r := newTestResponder()
	doVersion(t, r)
	doCapabilities(t, r)

	reqAlgMsg := buildNegotiateAlgorithms()
	var reqAlg msgs.NegotiateAlgorithms
	require.NoError(t, reqAlg.Unmarshal(reqAlgMsg))

	resp := doNegotiate(t, r)
	var ar msgs.AlgorithmsResponse
	require.NoError(t, ar.Unmarshal(resp))

	// BaseAsymSel must be a subset of requested BaseAsymAlgo.
	assert.Equal(t, ar.BaseAsymSel, ar.BaseAsymSel&reqAlg.BaseAsymAlgo)

	// BaseHashSel must be a subset of requested BaseHashAlgo.
	assert.Equal(t, ar.BaseHashSel, ar.BaseHashSel&reqAlg.BaseHashAlgo)

	// Each AlgStruct selection must be a subset of the corresponding requested.
	for i, a := range ar.AlgStructs {
		if i < len(reqAlg.AlgStructs) {
			reqSupported := reqAlg.AlgStructs[i].AlgSupported
			assert.Equal(t, a.AlgSupported, a.AlgSupported&reqSupported)
		}
	}
}

// TestConformance_NoCommonAlgorithmsError verifies that when no common algorithms
// exist, the responder returns an ERROR response per DSP0274 Section 10.5.
func TestConformance_NoCommonAlgorithmsError(t *testing.T) {
	// Responder only supports ECDSA-P384 + SHA-384; request uses ECDSA-P256 + SHA-256.
	r := New(Config{
		Versions:         []algo.Version{algo.Version12},
		BaseAsymAlgo:     algo.AsymECDSAP384,
		BaseHashAlgo:     algo.HashSHA384,
		DataTransferSize: 4096,
		MaxSPDMmsgSize:   65536,
	})
	doVersion(t, r)
	doCapabilities(t, r)

	// buildNegotiateAlgorithms requests SHA256 + ECDSA-P256, no overlap.
	resp := doNegotiate(t, r)
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	require.Equal(t, uint8(codes.ResponseError), errResp.Header.RequestResponseCode)
}

// --- 5. Version Mismatch (DSP0274 Section 10.3) ---

// TestConformance_WrongVersionAfterNegotiation verifies that any message with
// wrong SPDMVersion after version negotiation returns ERROR(VersionMismatch)
// per DSP0274 Section 10.3.
func TestConformance_WrongVersionAfterNegotiation(t *testing.T) {
	r := newTestResponder()
	doFullNegotiation(t, r)

	// Send GET_DIGESTS with wrong version (0x11 instead of 0x12).
	req := &msgs.GetDigests{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x11,
			RequestResponseCode: uint8(codes.RequestGetDigests),
		}},
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)
	expectError(t, resp, codes.ErrorVersionMismatch)

	// Send GET_CAPABILITIES with wrong version.
	capsReq := &msgs.GetCapabilities{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x11,
			RequestResponseCode: uint8(codes.RequestGetCapabilities),
		}},
		Flags:            uint32(caps.ReqCertCap),
		DataTransferSize: 4096,
		MaxSPDMmsgSize:   65536,
	}
	capsData, _ := capsReq.Marshal()
	resp, err = r.ProcessMessage(context.Background(), capsData)
	require.NoError(t, err)
	expectError(t, resp, codes.ErrorVersionMismatch)

	// Send NEGOTIATE_ALGORITHMS with wrong version.
	algReq := &msgs.NegotiateAlgorithms{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x11,
			RequestResponseCode: uint8(codes.RequestNegotiateAlgorithms),
			Param1:              0,
		}},
		BaseAsymAlgo: uint32(algo.AsymECDSAP256),
		BaseHashAlgo: uint32(algo.HashSHA256),
	}
	algData, _ := algReq.Marshal()
	resp, err = r.ProcessMessage(context.Background(), algData)
	require.NoError(t, err)
	expectError(t, resp, codes.ErrorVersionMismatch)

	// Send CHALLENGE with wrong version.
	chalReq := &msgs.Challenge{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x10,
			RequestResponseCode: uint8(codes.RequestChallenge),
			Param1:              0,
			Param2:              0x00,
		}},
	}
	chalData, _ := chalReq.Marshal()
	resp, err = r.ProcessMessage(context.Background(), chalData)
	require.NoError(t, err)
	expectError(t, resp, codes.ErrorVersionMismatch)
}
