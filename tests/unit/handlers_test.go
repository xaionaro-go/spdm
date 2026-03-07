package unit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/spdm/pkg/crypto/stdlib"
	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/caps"
	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
	"github.com/xaionaro-go/spdm/pkg/responder"
	"github.com/xaionaro-go/spdm/pkg/spdm"
)

// testResponderFixture holds a responder along with its generated credentials.
type testResponderFixture struct {
	rsp       *responder.Responder
	certChain []byte
	digest    []byte
	leafKey   *ecdsa.PrivateKey
}

// newTestResponder creates a responder with ECDSA P-256 certs for unit tests.
func newTestResponder(t *testing.T) *testResponderFixture {
	t.Helper()

	// Generate root CA key and self-signed certificate.
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)

	// Generate leaf key and certificate signed by root.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)

	// Build SPDM cert chain per DSP0274 Section 10.7.1:
	// 4-byte header (Length as uint16 LE + 2 reserved) + root hash (32 bytes for SHA-256) + DER certs.
	hashSize := 32
	certsData := append(rootDER, leafDER...)
	chainLen := msgs.CertChainHeaderSize + hashSize + len(certsData)
	certChain := make([]byte, chainLen)
	binary.LittleEndian.PutUint16(certChain[0:], uint16(chainLen))
	binary.LittleEndian.PutUint16(certChain[2:], 0)
	rootHash := sha256.Sum256(rootDER)
	copy(certChain[msgs.CertChainHeaderSize:], rootHash[:])
	copy(certChain[msgs.CertChainHeaderSize+hashSize:], certsData)

	chainHash := sha256.Sum256(certChain)
	digest := chainHash[:]

	cryptoSuite := stdlib.NewSuite(leafKey, nil)

	rspCaps := caps.RspCertCap | caps.RspChalCap | caps.RspMeasCapSig |
		caps.RspEncryptCap | caps.RspMACCap | caps.RspKeyExCap |
		caps.RspHBeatCap | caps.RspKeyUpdCap | caps.RspHandshakeInTheClearCap

	rsp := responder.New(responder.Config{
		Versions:         []algo.Version{algo.Version12},
		Crypto:           *cryptoSuite,
		Caps:             rspCaps,
		BaseAsymAlgo:     algo.AsymECDSAP256,
		BaseHashAlgo:     algo.HashSHA256,
		DHEGroups:        algo.DHESECP256R1,
		AEADSuites:       algo.AEADAES256GCM,
		DataTransferSize: 4096,
		MaxSPDMmsgSize:   4096,
		CertProvider:     &staticCertProvider{chain: certChain, digest: digest},
		MeasProvider:     &staticMeasProvider{},
		DeviceSigner:     leafKey,
	})

	return &testResponderFixture{
		rsp:       rsp,
		certChain: certChain,
		digest:    digest,
		leafKey:   leafKey,
	}
}

// staticMeasProvider returns a single dummy measurement block.
type staticMeasProvider struct{}

func (p *staticMeasProvider) Collect(_ context.Context, index uint8) ([]msgs.MeasurementBlock, error) {
	return []msgs.MeasurementBlock{
		{
			Index:     1,
			Spec:      0x01,
			ValueType: msgs.MeasTypeMutableFirmware,
			Value:     []byte("test-firmware-v1.0"),
		},
	}, nil
}

func (p *staticMeasProvider) SummaryHash(_ context.Context, hashType uint8) ([]byte, error) {
	return make([]byte, 32), nil
}

// buildGetVersion returns a serialized GET_VERSION request.
func buildGetVersion(t *testing.T) []byte {
	t.Helper()
	req := &msgs.GetVersion{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x10,
			RequestResponseCode: uint8(codes.RequestGetVersion),
		}},
	}
	data, err := req.Marshal()
	require.NoError(t, err)
	return data
}

// buildGetCapabilities returns a serialized GET_CAPABILITIES request for SPDM 1.2.
func buildGetCapabilities(t *testing.T) []byte {
	t.Helper()
	reqCaps := caps.ReqCertCap | caps.ReqChalCap |
		caps.ReqEncryptCap | caps.ReqMACCap | caps.ReqKeyExCap |
		caps.ReqHBeatCap | caps.ReqKeyUpdCap | caps.ReqHandshakeInTheClearCap
	req := &msgs.GetCapabilities{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetCapabilities),
		}},
		CTExponent:       12,
		Flags:            uint32(reqCaps),
		DataTransferSize: 4096,
		MaxSPDMmsgSize:   4096,
	}
	data, err := req.Marshal()
	require.NoError(t, err)
	return data
}

// buildNegotiateAlgorithms returns a serialized NEGOTIATE_ALGORITHMS request.
func buildNegotiateAlgorithms(t *testing.T) []byte {
	t.Helper()
	algStructs := []msgs.AlgStructTable{
		{AlgType: msgs.AlgTypeDHE, AlgCount: 0x20, AlgSupported: uint16(algo.DHESECP256R1)},
		{AlgType: msgs.AlgTypeAEAD, AlgCount: 0x20, AlgSupported: uint16(algo.AEADAES256GCM)},
		{AlgType: msgs.AlgTypeKeySchedule, AlgCount: 0x20, AlgSupported: uint16(algo.KeyScheduleSPDM)},
	}
	req := &msgs.NegotiateAlgorithms{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestNegotiateAlgorithms),
			Param1:              uint8(len(algStructs)),
		}},
		MeasurementSpecification: 0x01,
		OtherParamsSupport:       0x02,
		BaseAsymAlgo:             uint32(algo.AsymECDSAP256),
		BaseHashAlgo:             uint32(algo.HashSHA256),
		AlgStructs:               algStructs,
	}
	data, err := req.Marshal()
	require.NoError(t, err)
	return data
}

// doVCA runs the full VCA sequence (GET_VERSION + GET_CAPABILITIES + NEGOTIATE_ALGORITHMS)
// and returns the responder in the Negotiated state.
func doVCA(t *testing.T, rsp *responder.Responder) {
	t.Helper()
	ctx := context.Background()

	// GET_VERSION
	resp, err := rsp.ProcessMessage(ctx, buildGetVersion(t))
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), msgs.HeaderSize)
	assert.Equal(t, uint8(codes.ResponseVersion), resp[1])

	// GET_CAPABILITIES
	resp, err = rsp.ProcessMessage(ctx, buildGetCapabilities(t))
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), msgs.HeaderSize)
	assert.Equal(t, uint8(codes.ResponseCapabilities), resp[1])

	// NEGOTIATE_ALGORITHMS
	resp, err = rsp.ProcessMessage(ctx, buildNegotiateAlgorithms(t))
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), msgs.HeaderSize)
	assert.Equal(t, uint8(codes.ResponseAlgorithms), resp[1])
}

// parseErrorResponse parses an error response and returns the error code.
func parseErrorResponse(t *testing.T, data []byte) codes.SPDMErrorCode {
	t.Helper()
	require.GreaterOrEqual(t, len(data), msgs.HeaderSize)
	require.Equal(t, uint8(codes.ResponseError), data[1], "expected ERROR response")
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(data))
	return errResp.ErrorCode()
}

// --- Session handler tests ---

func TestHandleHeartbeat(t *testing.T) {
	fix := newTestResponder(t)
	doVCA(t, fix.rsp)
	ctx := context.Background()

	req := &msgs.Heartbeat{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestHeartbeat),
		}},
	}
	data, err := req.Marshal()
	require.NoError(t, err)

	resp, err := fix.rsp.ProcessMessage(ctx, data)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), msgs.HeaderSize)
	assert.Equal(t, uint8(codes.ResponseHeartbeatAck), resp[1])

	var ack msgs.HeartbeatResponse
	require.NoError(t, ack.Unmarshal(resp))
	assert.Equal(t, uint8(0x12), ack.Header.SPDMVersion)
}

func TestHandleKeyUpdate(t *testing.T) {
	fix := newTestResponder(t)
	doVCA(t, fix.rsp)
	ctx := context.Background()

	// Without an active session, KEY_UPDATE returns ERROR.
	req := &msgs.KeyUpdate{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestKeyUpdate),
			Param1:              msgs.KeyUpdateOpUpdateKey,
			Param2:              0x42,
		}},
	}
	data, err := req.Marshal()
	require.NoError(t, err)

	resp, err := fix.rsp.ProcessMessage(ctx, data)
	require.NoError(t, err)

	errCode := parseErrorResponse(t, resp)
	assert.Equal(t, codes.ErrorInvalidRequest, errCode)
}

func TestHandleEndSession(t *testing.T) {
	fix := newTestResponder(t)
	doVCA(t, fix.rsp)
	ctx := context.Background()

	req := &msgs.EndSession{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestEndSession),
		}},
	}
	data, err := req.Marshal()
	require.NoError(t, err)

	resp, err := fix.rsp.ProcessMessage(ctx, data)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), msgs.HeaderSize)
	assert.Equal(t, uint8(codes.ResponseEndSessionAck), resp[1])

	var ack msgs.EndSessionResponse
	require.NoError(t, ack.Unmarshal(resp))
	assert.Equal(t, uint8(0x12), ack.Header.SPDMVersion)
}

func TestHandleVendorDefined(t *testing.T) {
	fix := newTestResponder(t)
	doVCA(t, fix.rsp)
	ctx := context.Background()

	req := &msgs.VendorDefinedRequest{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestVendorDefined),
		}},
		StandardID: 0x0001,
		VendorID:   []byte{0xAA, 0xBB},
		Payload:    []byte{0x01, 0x02, 0x03},
	}
	data, err := req.Marshal()
	require.NoError(t, err)

	resp, err := fix.rsp.ProcessMessage(ctx, data)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), msgs.HeaderSize)
	assert.Equal(t, uint8(codes.ResponseVendorDefined), resp[1])

	var vdr msgs.VendorDefinedResponse
	require.NoError(t, vdr.Unmarshal(resp))
	assert.Equal(t, uint16(0x0001), vdr.StandardID)
	assert.Equal(t, []byte{0xAA, 0xBB}, vdr.VendorID)
}

// --- State machine enforcement tests ---

func TestStateMachine_GetCapsBeforeVersion(t *testing.T) {
	fix := newTestResponder(t)
	ctx := context.Background()

	// Send GET_CAPABILITIES without GET_VERSION first.
	data := buildGetCapabilities(t)
	// Override version byte to 0x10 since no version is negotiated yet.
	data[0] = 0x10
	resp, err := fix.rsp.ProcessMessage(ctx, data)
	require.NoError(t, err)
	errCode := parseErrorResponse(t, resp)
	assert.Equal(t, codes.ErrorUnexpectedRequest, errCode)
}

func TestStateMachine_NegAlgBeforeCaps(t *testing.T) {
	fix := newTestResponder(t)
	ctx := context.Background()

	// Send GET_VERSION first.
	resp, err := fix.rsp.ProcessMessage(ctx, buildGetVersion(t))
	require.NoError(t, err)
	assert.Equal(t, uint8(codes.ResponseVersion), resp[1])

	// Send NEGOTIATE_ALGORITHMS without GET_CAPABILITIES.
	data := buildNegotiateAlgorithms(t)
	resp, err = fix.rsp.ProcessMessage(ctx, data)
	require.NoError(t, err)
	errCode := parseErrorResponse(t, resp)
	assert.Equal(t, codes.ErrorUnexpectedRequest, errCode)
}

func TestStateMachine_UnknownRequestCode(t *testing.T) {
	fix := newTestResponder(t)
	ctx := context.Background()

	// Request code 0xA0 is not a valid SPDM request.
	data := []byte{0x10, 0xA0, 0x00, 0x00}
	resp, err := fix.rsp.ProcessMessage(ctx, data)
	require.NoError(t, err)
	errCode := parseErrorResponse(t, resp)
	assert.Equal(t, codes.ErrorUnsupportedRequest, errCode)
}

func TestStateMachine_TooShortMessage(t *testing.T) {
	fix := newTestResponder(t)
	ctx := context.Background()

	// Less than 4 bytes (HeaderSize).
	resp, err := fix.rsp.ProcessMessage(ctx, []byte{0x10, 0x84})
	require.NoError(t, err)
	errCode := parseErrorResponse(t, resp)
	assert.Equal(t, codes.ErrorInvalidRequest, errCode)
}

func TestStateMachine_VersionMismatch(t *testing.T) {
	fix := newTestResponder(t)
	ctx := context.Background()

	// Run GET_VERSION + GET_CAPABILITIES to negotiate version 1.2.
	resp, err := fix.rsp.ProcessMessage(ctx, buildGetVersion(t))
	require.NoError(t, err)
	assert.Equal(t, uint8(codes.ResponseVersion), resp[1])

	resp, err = fix.rsp.ProcessMessage(ctx, buildGetCapabilities(t))
	require.NoError(t, err)
	assert.Equal(t, uint8(codes.ResponseCapabilities), resp[1])

	// Send NEGOTIATE_ALGORITHMS with wrong version byte (0x11 instead of 0x12).
	algData := buildNegotiateAlgorithms(t)
	algData[0] = 0x11 // wrong version
	resp, err = fix.rsp.ProcessMessage(ctx, algData)
	require.NoError(t, err)
	errCode := parseErrorResponse(t, resp)
	assert.Equal(t, codes.ErrorVersionMismatch, errCode)
}

// --- Algorithm negotiation tests ---

func TestSelectAlgorithm_NoCommonHash(t *testing.T) {
	fix := newTestResponder(t)
	ctx := context.Background()

	// Do GET_VERSION + GET_CAPABILITIES.
	resp, err := fix.rsp.ProcessMessage(ctx, buildGetVersion(t))
	require.NoError(t, err)
	assert.Equal(t, uint8(codes.ResponseVersion), resp[1])

	resp, err = fix.rsp.ProcessMessage(ctx, buildGetCapabilities(t))
	require.NoError(t, err)
	assert.Equal(t, uint8(codes.ResponseCapabilities), resp[1])

	// Send NEGOTIATE_ALGORITHMS with SHA-384 only (responder only supports SHA-256).
	algStructs := []msgs.AlgStructTable{
		{AlgType: msgs.AlgTypeDHE, AlgCount: 0x20, AlgSupported: uint16(algo.DHESECP256R1)},
		{AlgType: msgs.AlgTypeAEAD, AlgCount: 0x20, AlgSupported: uint16(algo.AEADAES256GCM)},
	}
	req := &msgs.NegotiateAlgorithms{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestNegotiateAlgorithms),
			Param1:              uint8(len(algStructs)),
		}},
		MeasurementSpecification: 0x01,
		OtherParamsSupport:       0x02,
		BaseAsymAlgo:             uint32(algo.AsymECDSAP256),
		BaseHashAlgo:             uint32(algo.HashSHA384), // no overlap with responder's SHA-256
		AlgStructs:               algStructs,
	}
	data, err := req.Marshal()
	require.NoError(t, err)

	resp, err = fix.rsp.ProcessMessage(ctx, data)
	require.NoError(t, err)
	// Should return an error since no common hash algorithm exists.
	errCode := parseErrorResponse(t, resp)
	assert.Equal(t, codes.ErrorUnspecified, errCode)
}

// --- buildError format test ---

func TestBuildErrorFormat(t *testing.T) {
	fix := newTestResponder(t)
	ctx := context.Background()

	// Send a too-short message to trigger buildError.
	resp, err := fix.rsp.ProcessMessage(ctx, []byte{0x10})
	require.NoError(t, err)

	// Verify error response format.
	require.GreaterOrEqual(t, len(resp), msgs.HeaderSize)
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, uint8(codes.ResponseError), errResp.Header.RequestResponseCode)
	assert.Equal(t, codes.ErrorInvalidRequest, errResp.ErrorCode())
	assert.Equal(t, uint8(0), errResp.ErrorData())
}

// --- Default values tests ---

func TestDefaultDataTransferSize(t *testing.T) {
	// Create responder with zero DataTransferSize/MaxSPDMmsgSize to test defaults.
	cryptoSuite := stdlib.NewSuite(nil, nil)
	rsp := responder.New(responder.Config{
		Versions:     []algo.Version{algo.Version12},
		Crypto:       *cryptoSuite,
		Caps:         caps.RspCertCap,
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})
	ctx := context.Background()

	// Send GET_VERSION to initialize.
	resp, err := rsp.ProcessMessage(ctx, buildGetVersion(t))
	require.NoError(t, err)
	assert.Equal(t, uint8(codes.ResponseVersion), resp[1])

	// Send GET_CAPABILITIES.
	resp, err = rsp.ProcessMessage(ctx, buildGetCapabilities(t))
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), msgs.HeaderSize+16)

	var capResp msgs.CapabilitiesResponse
	require.NoError(t, capResp.Unmarshal(resp))
	// Defaults per responder.New: DataTransferSize=4096, MaxSPDMmsgSize=65536.
	assert.Equal(t, uint32(4096), capResp.DataTransferSize)
	assert.Equal(t, uint32(65536), capResp.MaxSPDMmsgSize)
}

// --- Nonce non-zero test ---

func TestMeasurementsNonceNonZero(t *testing.T) {
	fix := newTestResponder(t)
	doVCA(t, fix.rsp)
	ctx := context.Background()

	// Build GET_MEASUREMENTS request (unsigned but Nonce always present in 1.2).
	req := &msgs.GetMeasurements{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetMeasurements),
			Param1:              0, // no signature
			Param2:              msgs.MeasOpAllMeasurements,
		}},
	}
	data, err := req.Marshal()
	require.NoError(t, err)

	resp, err := fix.rsp.ProcessMessage(ctx, data)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), msgs.HeaderSize)
	assert.Equal(t, uint8(codes.ResponseMeasurements), resp[1])

	var measResp msgs.MeasurementsResponse
	require.NoError(t, measResp.Unmarshal(resp))

	// Per DSP0274 Table 45: Nonce is always present in SPDM 1.2.
	allZero := true
	for _, b := range measResp.Nonce {
		if b != 0 {
			allZero = false
			break
		}
	}
	assert.False(t, allZero, "nonce should not be all zeros")
}

// --- Full VCA flow test ---

func TestFullVCAFlow(t *testing.T) {
	fix := newTestResponder(t)
	ctx := context.Background()

	// Step 1: GET_VERSION.
	resp, err := fix.rsp.ProcessMessage(ctx, buildGetVersion(t))
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), msgs.HeaderSize+2)
	assert.Equal(t, uint8(codes.ResponseVersion), resp[1])

	var verResp msgs.VersionResponse
	require.NoError(t, verResp.Unmarshal(resp))
	require.NotZero(t, verResp.VersionNumberEntryCount)

	// Verify version 1.2 is offered.
	found12 := false
	for _, entry := range verResp.VersionEntries {
		vn := algo.VersionNumber(entry)
		if vn.Version() == algo.Version12 {
			found12 = true
		}
	}
	assert.True(t, found12, "version 1.2 should be offered")

	// Step 2: GET_CAPABILITIES.
	resp, err = fix.rsp.ProcessMessage(ctx, buildGetCapabilities(t))
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), msgs.HeaderSize+4)
	assert.Equal(t, uint8(codes.ResponseCapabilities), resp[1])

	var capResp msgs.CapabilitiesResponse
	require.NoError(t, capResp.Unmarshal(resp))
	assert.Equal(t, uint8(0x12), capResp.Header.SPDMVersion)
	rspCaps := caps.ResponderCaps(capResp.Flags)
	assert.True(t, rspCaps.HasCertCap())
	assert.True(t, rspCaps.HasChalCap())

	// Step 3: NEGOTIATE_ALGORITHMS.
	resp, err = fix.rsp.ProcessMessage(ctx, buildNegotiateAlgorithms(t))
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), msgs.HeaderSize+32)
	assert.Equal(t, uint8(codes.ResponseAlgorithms), resp[1])

	var algResp msgs.AlgorithmsResponse
	require.NoError(t, algResp.Unmarshal(resp))
	assert.Equal(t, uint32(algo.HashSHA256), algResp.BaseHashSel)
	assert.Equal(t, uint32(algo.AsymECDSAP256), algResp.BaseAsymSel)
}

// --- GET_DIGESTS after negotiation ---

func TestGetDigestsAfterNegotiation(t *testing.T) {
	fix := newTestResponder(t)
	doVCA(t, fix.rsp)
	ctx := context.Background()

	req := &msgs.GetDigests{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetDigests),
		}},
	}
	data, err := req.Marshal()
	require.NoError(t, err)

	resp, err := fix.rsp.ProcessMessage(ctx, data)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), msgs.HeaderSize)
	assert.Equal(t, uint8(codes.ResponseDigests), resp[1])

	var digResp msgs.DigestResponse
	require.NoError(t, digResp.UnmarshalWithDigestSize(resp, 32)) // SHA-256 = 32 bytes
	assert.NotZero(t, digResp.SlotMask(), "expected at least one provisioned slot")
	require.NotEmpty(t, digResp.Digests)
	assert.Len(t, digResp.Digests[0], 32)
}

// --- GET_CERTIFICATE after negotiation ---

func TestGetCertificateAfterNegotiation(t *testing.T) {
	fix := newTestResponder(t)
	doVCA(t, fix.rsp)
	ctx := context.Background()

	req := &msgs.GetCertificate{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetCertificate),
			Param1:              0, // slot 0
		}},
		Offset: 0,
		Length: 0xFFFF, // request maximum
	}
	data, err := req.Marshal()
	require.NoError(t, err)

	resp, err := fix.rsp.ProcessMessage(ctx, data)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), msgs.HeaderSize+4)
	assert.Equal(t, uint8(codes.ResponseCertificate), resp[1])

	var certResp msgs.CertificateResponse
	require.NoError(t, certResp.Unmarshal(resp))
	assert.Equal(t, uint8(0), certResp.SlotID())
	assert.NotZero(t, certResp.PortionLength, "expected non-empty cert chain portion")
	assert.NotEmpty(t, certResp.CertChain)
}

// --- GET_MEASUREMENTS after negotiation ---

func TestGetMeasurementsAfterNegotiation(t *testing.T) {
	fix := newTestResponder(t)
	doVCA(t, fix.rsp)
	ctx := context.Background()

	req := &msgs.GetMeasurements{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetMeasurements),
			Param1:              0, // no signature
			Param2:              msgs.MeasOpAllMeasurements,
		}},
	}
	data, err := req.Marshal()
	require.NoError(t, err)

	resp, err := fix.rsp.ProcessMessage(ctx, data)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), msgs.HeaderSize+4)
	assert.Equal(t, uint8(codes.ResponseMeasurements), resp[1])

	var measResp msgs.MeasurementsResponse
	require.NoError(t, measResp.Unmarshal(resp))
	assert.NotZero(t, measResp.NumberOfBlocks, "expected at least one measurement block")
	assert.NotZero(t, measResp.MeasurementRecordLen)
}

// --- spdm package API tests ---

func TestSpdmPackage_NewResponder_ProcessMessage(t *testing.T) {
	// Test the consumer-facing spdm.NewResponder + ProcessMessage.
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)

	hashSize := 32
	certsData := append(rootDER, leafDER...)
	chainLen := msgs.CertChainHeaderSize + hashSize + len(certsData)
	certChain := make([]byte, chainLen)
	binary.LittleEndian.PutUint16(certChain[0:], uint16(chainLen))
	rootHash := sha256.Sum256(rootDER)
	copy(certChain[msgs.CertChainHeaderSize:], rootHash[:])
	copy(certChain[msgs.CertChainHeaderSize+hashSize:], certsData)
	chainHash := sha256.Sum256(certChain)

	cryptoSuite := stdlib.NewSuite(leafKey, nil)

	rsp := spdm.NewResponder(spdm.ResponderConfig{
		Versions:         []algo.Version{algo.Version12},
		Crypto:           *cryptoSuite,
		Caps:             caps.RspCertCap | caps.RspChalCap | caps.RspMeasCapSig,
		BaseAsymAlgo:     algo.AsymECDSAP256,
		BaseHashAlgo:     algo.HashSHA256,
		DHEGroups:        algo.DHESECP256R1,
		AEADSuites:       algo.AEADAES256GCM,
		DataTransferSize: 4096,
		MaxSPDMmsgSize:   4096,
		CertProvider:     &staticCertProvider{chain: certChain, digest: chainHash[:]},
		MeasProvider:     &staticMeasProvider{},
	})

	ctx := context.Background()

	// GET_VERSION via spdm.Responder.ProcessMessage.
	resp, err := rsp.ProcessMessage(ctx, buildGetVersion(t))
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), msgs.HeaderSize)
	assert.Equal(t, uint8(codes.ResponseVersion), resp[1])

	// GET_CAPABILITIES.
	resp, err = rsp.ProcessMessage(ctx, buildGetCapabilities(t))
	require.NoError(t, err)
	assert.Equal(t, uint8(codes.ResponseCapabilities), resp[1])

	// NEGOTIATE_ALGORITHMS.
	resp, err = rsp.ProcessMessage(ctx, buildNegotiateAlgorithms(t))
	require.NoError(t, err)
	assert.Equal(t, uint8(codes.ResponseAlgorithms), resp[1])

	// GET_DIGESTS via spdm package.
	digestReq := &msgs.GetDigests{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetDigests),
		}},
	}
	data, err := digestReq.Marshal()
	require.NoError(t, err)
	resp, err = rsp.ProcessMessage(ctx, data)
	require.NoError(t, err)
	assert.Equal(t, uint8(codes.ResponseDigests), resp[1])
}

// --- GET_VERSION resets state ---

func TestGetVersionResetsState(t *testing.T) {
	fix := newTestResponder(t)
	ctx := context.Background()

	// Complete VCA.
	doVCA(t, fix.rsp)

	// Send another GET_VERSION to reset state.
	resp, err := fix.rsp.ProcessMessage(ctx, buildGetVersion(t))
	require.NoError(t, err)
	assert.Equal(t, uint8(codes.ResponseVersion), resp[1])

	// Now sending NEGOTIATE_ALGORITHMS should fail (state was reset, need caps first).
	algData := buildNegotiateAlgorithms(t)
	resp, err = fix.rsp.ProcessMessage(ctx, algData)
	require.NoError(t, err)
	errCode := parseErrorResponse(t, resp)
	assert.Equal(t, codes.ErrorUnexpectedRequest, errCode)
}

// --- GET_DIGESTS before negotiation ---

func TestGetDigestsBeforeNegotiation(t *testing.T) {
	fix := newTestResponder(t)
	ctx := context.Background()

	// Only do GET_VERSION + GET_CAPABILITIES (no NEGOTIATE_ALGORITHMS).
	resp, err := fix.rsp.ProcessMessage(ctx, buildGetVersion(t))
	require.NoError(t, err)
	assert.Equal(t, uint8(codes.ResponseVersion), resp[1])

	resp, err = fix.rsp.ProcessMessage(ctx, buildGetCapabilities(t))
	require.NoError(t, err)
	assert.Equal(t, uint8(codes.ResponseCapabilities), resp[1])

	// GET_DIGESTS should fail since algorithms are not yet negotiated.
	digestReq := &msgs.GetDigests{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetDigests),
		}},
	}
	data, err := digestReq.Marshal()
	require.NoError(t, err)
	resp, err = fix.rsp.ProcessMessage(ctx, data)
	require.NoError(t, err)
	errCode := parseErrorResponse(t, resp)
	assert.Equal(t, codes.ErrorUnexpectedRequest, errCode)
}

// --- GET_CERTIFICATE before negotiation ---

func TestGetCertificateBeforeNegotiation(t *testing.T) {
	fix := newTestResponder(t)
	ctx := context.Background()

	resp, err := fix.rsp.ProcessMessage(ctx, buildGetVersion(t))
	require.NoError(t, err)
	assert.Equal(t, uint8(codes.ResponseVersion), resp[1])

	resp, err = fix.rsp.ProcessMessage(ctx, buildGetCapabilities(t))
	require.NoError(t, err)
	assert.Equal(t, uint8(codes.ResponseCapabilities), resp[1])

	// GET_CERTIFICATE should fail.
	certReq := &msgs.GetCertificate{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetCertificate),
		}},
		Offset: 0,
		Length: 0xFFFF,
	}
	data, err := certReq.Marshal()
	require.NoError(t, err)
	resp, err = fix.rsp.ProcessMessage(ctx, data)
	require.NoError(t, err)
	errCode := parseErrorResponse(t, resp)
	assert.Equal(t, codes.ErrorUnexpectedRequest, errCode)
}

// --- Multiple KeyUpdate operations ---

func TestHandleKeyUpdate_AllOps(t *testing.T) {
	fix := newTestResponder(t)
	doVCA(t, fix.rsp)
	ctx := context.Background()

	// Without an active session, all KEY_UPDATE operations return ERROR.
	ops := []struct {
		name string
		op   uint8
		tag  uint8
	}{
		{"UpdateKey", msgs.KeyUpdateOpUpdateKey, 0x01},
		{"UpdateAllKeys", msgs.KeyUpdateOpUpdateAllKeys, 0x02},
		{"VerifyNewKey", msgs.KeyUpdateOpVerifyNewKey, 0x03},
	}

	for _, tc := range ops {
		t.Run(tc.name, func(t *testing.T) {
			req := &msgs.KeyUpdate{
				Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
					SPDMVersion:         0x12,
					RequestResponseCode: uint8(codes.RequestKeyUpdate),
					Param1:              tc.op,
					Param2:              tc.tag,
				}},
			}
			data, err := req.Marshal()
			require.NoError(t, err)

			resp, err := fix.rsp.ProcessMessage(ctx, data)
			require.NoError(t, err)

			errCode := parseErrorResponse(t, resp)
			assert.Equal(t, codes.ErrorInvalidRequest, errCode)
		})
	}
}

// --- VendorDefined with empty payload ---

func TestHandleVendorDefined_EmptyPayload(t *testing.T) {
	fix := newTestResponder(t)
	doVCA(t, fix.rsp)
	ctx := context.Background()

	req := &msgs.VendorDefinedRequest{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestVendorDefined),
		}},
		StandardID: 0x1234,
		VendorID:   []byte{},
		Payload:    []byte{},
	}
	data, err := req.Marshal()
	require.NoError(t, err)

	resp, err := fix.rsp.ProcessMessage(ctx, data)
	require.NoError(t, err)

	var vdr msgs.VendorDefinedResponse
	require.NoError(t, vdr.Unmarshal(resp))
	assert.Equal(t, uint16(0x1234), vdr.StandardID)
	assert.Empty(t, vdr.VendorID)
	// Responder echoes with empty payload.
	assert.Empty(t, vdr.Payload)
}

// --- EndSession with preserve negotiated state ---

func TestHandleEndSession_PreserveNegotiatedState(t *testing.T) {
	fix := newTestResponder(t)
	doVCA(t, fix.rsp)
	ctx := context.Background()

	req := &msgs.EndSession{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestEndSession),
			Param1:              msgs.EndSessionPreserveNegotiatedStateClear,
		}},
	}
	data, err := req.Marshal()
	require.NoError(t, err)

	resp, err := fix.rsp.ProcessMessage(ctx, data)
	require.NoError(t, err)

	var ack msgs.EndSessionResponse
	require.NoError(t, ack.Unmarshal(resp))
	assert.Equal(t, uint8(codes.ResponseEndSessionAck), ack.Header.RequestResponseCode)
}

// --- GET_CERTIFICATE with specific offset ---

func TestGetCertificate_WithOffset(t *testing.T) {
	fix := newTestResponder(t)
	doVCA(t, fix.rsp)
	ctx := context.Background()

	// First request at offset 0 for a small portion.
	req := &msgs.GetCertificate{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetCertificate),
			Param1:              0,
		}},
		Offset: 0,
		Length: 64,
	}
	data, err := req.Marshal()
	require.NoError(t, err)

	resp, err := fix.rsp.ProcessMessage(ctx, data)
	require.NoError(t, err)

	var certResp msgs.CertificateResponse
	require.NoError(t, certResp.Unmarshal(resp))
	assert.Equal(t, uint16(64), certResp.PortionLength)
	assert.NotZero(t, certResp.RemainderLength, "should have remainder")

	// Second request at offset 64.
	req.Offset = 64
	req.Length = 0xFFFF
	data, err = req.Marshal()
	require.NoError(t, err)

	resp, err = fix.rsp.ProcessMessage(ctx, data)
	require.NoError(t, err)

	var certResp2 msgs.CertificateResponse
	require.NoError(t, certResp2.Unmarshal(resp))
	assert.Equal(t, uint16(0), certResp2.RemainderLength, "should have no remainder")
	assert.NotEmpty(t, certResp2.CertChain)
}

// --- Repeated GET_CAPABILITIES (replay detection) ---

func TestRepeatedGetCapabilities_Identical(t *testing.T) {
	fix := newTestResponder(t)
	ctx := context.Background()

	resp, err := fix.rsp.ProcessMessage(ctx, buildGetVersion(t))
	require.NoError(t, err)
	assert.Equal(t, uint8(codes.ResponseVersion), resp[1])

	capsData := buildGetCapabilities(t)

	// First GET_CAPABILITIES.
	resp, err = fix.rsp.ProcessMessage(ctx, capsData)
	require.NoError(t, err)
	assert.Equal(t, uint8(codes.ResponseCapabilities), resp[1])

	// Identical GET_CAPABILITIES should succeed (replay allowed).
	resp, err = fix.rsp.ProcessMessage(ctx, capsData)
	require.NoError(t, err)
	assert.Equal(t, uint8(codes.ResponseCapabilities), resp[1])
}

func TestRepeatedGetCapabilities_Different(t *testing.T) {
	fix := newTestResponder(t)
	ctx := context.Background()

	resp, err := fix.rsp.ProcessMessage(ctx, buildGetVersion(t))
	require.NoError(t, err)
	assert.Equal(t, uint8(codes.ResponseVersion), resp[1])

	// First GET_CAPABILITIES.
	resp, err = fix.rsp.ProcessMessage(ctx, buildGetCapabilities(t))
	require.NoError(t, err)
	assert.Equal(t, uint8(codes.ResponseCapabilities), resp[1])

	// Different GET_CAPABILITIES (different CTExponent).
	diffCaps := &msgs.GetCapabilities{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetCapabilities),
		}},
		CTExponent:       15, // different from the 12 used in buildGetCapabilities
		Flags:            uint32(caps.ReqCertCap | caps.ReqChalCap),
		DataTransferSize: 4096,
		MaxSPDMmsgSize:   4096,
	}
	data, err := diffCaps.Marshal()
	require.NoError(t, err)

	resp, err = fix.rsp.ProcessMessage(ctx, data)
	require.NoError(t, err)
	errCode := parseErrorResponse(t, resp)
	assert.Equal(t, codes.ErrorUnexpectedRequest, errCode)
}
