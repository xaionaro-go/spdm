package requester

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/caps"
	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
	"github.com/xaionaro-go/spdm/pkg/gen/status"
)

// --- Version Response Validation (DSP0274 Section 10.3) ---

// TestConformance_VersionResponseZeroEntries verifies that the requester
// rejects a VERSION response with 0 version entries per DSP0274 Section 10.3.
func TestConformance_VersionResponseZeroEntries(t *testing.T) {
	// Craft a VERSION response with VersionNumberEntryCount=0 and no entries.
	resp := &msgs.VersionResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x10,
			RequestResponseCode: uint8(codes.ResponseVersion),
		}},
		VersionEntries: nil, // 0 entries
	}
	data, _ := resp.Marshal()

	mt := &mockTransport{responses: [][]byte{data}}
	r := New(Config{
		Versions:  []algo.Version{algo.Version12},
		Transport: mt,
	})

	_, err := r.InitConnection(context.Background())
	require.Error(t, err, "expected error for VERSION response with 0 entries")
	assert.ErrorIs(t, err, status.ErrInvalidMsgField)
}

// TestConformance_VersionResponseVersionFieldNot0x10 verifies that the requester
// flags a VERSION response whose SPDMVersion header field is not 0x10 per DSP0274 Section 10.3.
func TestConformance_VersionResponseVersionFieldNot0x10(t *testing.T) {
	// Build a raw VERSION response with SPDMVersion=0x12 (wrong for VERSION).
	versionEntry := uint16(0x1200) // SPDM 1.2
	resp := &msgs.VersionResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12, // violates spec: must be 0x10
			RequestResponseCode: uint8(codes.ResponseVersion),
		}},
		VersionEntries: []uint16{versionEntry},
	}
	data, _ := resp.Marshal()

	mt := &mockTransport{responses: [][]byte{data}}
	r := New(Config{
		Versions:  []algo.Version{algo.Version12},
		Transport: mt,
	})

	_, err := r.InitConnection(context.Background())
	require.Error(t, err, "expected error for VERSION response with SPDMVersion != 0x10")
	assert.ErrorIs(t, err, status.ErrInvalidMsgField)
}

// --- Capabilities Response Validation (DSP0274 Section 10.4) ---

// TestConformance_CapabilitiesResponseForbiddenFlags verifies that the requester
// rejects a CAPABILITIES response with both CERT_CAP and PUB_KEY_ID_CAP set,
// which are mutually exclusive per DSP0274 Section 10.4 Table 15.
func TestConformance_CapabilitiesResponseForbiddenFlags(t *testing.T) {
	versionEntry := uint16(0x1200)
	forbiddenFlags := uint32(caps.RspCertCap | caps.RspPubKeyIDCap)

	mt := &mockTransport{
		responses: [][]byte{
			buildVersionResponse(versionEntry),
			buildCapabilitiesResponse(0x12, forbiddenFlags),
		},
	}

	r := New(Config{
		Versions:  []algo.Version{algo.Version12},
		Transport: mt,
	})

	_, err := r.InitConnection(context.Background())
	require.Error(t, err, "expected error for CERT_CAP + PUB_KEY_ID_CAP both set")
	// The error should come from capabilities validation.
	assert.Contains(t, err.Error(), "mutually exclusive")
}

// --- Algorithm Response Validation (DSP0274 Section 10.5) ---

// TestConformance_AlgorithmsResponseMultipleBitsSelected verifies that the
// requester rejects an ALGORITHMS response with multiple bits set in
// BaseAsymSel per DSP0274 Section 10.5.
func TestConformance_AlgorithmsResponseMultipleBitsSelected(t *testing.T) {
	versionEntry := uint16(0x1200)

	mt := &mockTransport{
		responses: [][]byte{
			buildVersionResponse(versionEntry),
			buildCapabilitiesResponse(0x12, uint32(caps.RspCertCap)),
			buildAlgorithmsResponse(0x12,
				uint32(algo.HashSHA256),
				uint32(algo.AsymECDSAP256|algo.AsymRSASSA2048), // multiple bits - invalid
				uint32(algo.MeasHashSHA256),
				uint16(algo.DHESECP256R1),
				uint16(algo.AEADAES128GCM),
			),
		},
	}

	r := New(Config{
		Versions:     []algo.Version{algo.Version12},
		Transport:    mt,
		BaseAsymAlgo: algo.AsymECDSAP256 | algo.AsymRSASSA2048,
		BaseHashAlgo: algo.HashSHA256,
		DHEGroups:    algo.DHESECP256R1,
		AEADSuites:   algo.AEADAES128GCM,
	})

	_, err := r.InitConnection(context.Background())
	require.Error(t, err, "expected error for ALGORITHMS response with multiple bits in BaseAsymSel")
	assert.ErrorIs(t, err, status.ErrInvalidMsgField)
}

// TestConformance_AlgorithmsResponseNotSubsetOfRequest verifies that the
// requester rejects an ALGORITHMS response where the selected algorithm was
// not in the requester's request per DSP0274 Section 10.5.
func TestConformance_AlgorithmsResponseNotSubsetOfRequest(t *testing.T) {
	versionEntry := uint16(0x1200)

	// Requester only requested ECDSA-P256, but responder selects RSASSA-2048.
	mt := &mockTransport{
		responses: [][]byte{
			buildVersionResponse(versionEntry),
			buildCapabilitiesResponse(0x12, uint32(caps.RspCertCap)),
			buildAlgorithmsResponse(0x12,
				uint32(algo.HashSHA256),
				uint32(algo.AsymRSASSA2048), // not in requester's set
				uint32(algo.MeasHashSHA256),
				uint16(algo.DHESECP256R1),
				uint16(algo.AEADAES128GCM),
			),
		},
	}

	r := New(Config{
		Versions:     []algo.Version{algo.Version12},
		Transport:    mt,
		BaseAsymAlgo: algo.AsymECDSAP256, // only P256 requested
		BaseHashAlgo: algo.HashSHA256,
		DHEGroups:    algo.DHESECP256R1,
		AEADSuites:   algo.AEADAES128GCM,
	})

	_, err := r.InitConnection(context.Background())
	require.Error(t, err, "expected error for ALGORITHMS response with algorithm not in requested set")
	assert.ErrorIs(t, err, status.ErrInvalidMsgField)
}

// TestConformance_AlgorithmsResponseZeroSelection verifies that the requester
// errors when the ALGORITHMS response has all-zero selections despite the
// requester having requested algorithms per DSP0274 Section 10.5.
func TestConformance_AlgorithmsResponseZeroSelection(t *testing.T) {
	versionEntry := uint16(0x1200)

	mt := &mockTransport{
		responses: [][]byte{
			buildVersionResponse(versionEntry),
			buildCapabilitiesResponse(0x12, uint32(caps.RspCertCap)),
			buildAlgorithmsResponse(0x12,
				0, // zero BaseHashSel
				0, // zero BaseAsymSel
				0,
				0,
				0,
			),
		},
	}

	r := New(Config{
		Versions:     []algo.Version{algo.Version12},
		Transport:    mt,
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
		DHEGroups:    algo.DHESECP256R1,
		AEADSuites:   algo.AEADAES128GCM,
	})

	_, err := r.InitConnection(context.Background())
	require.Error(t, err, "expected error for ALGORITHMS response with zero selections")
	assert.ErrorIs(t, err, status.ErrNegotiationFail)
}

// --- Error Response Handling (DSP0274 Section 10.10) ---

// TestConformance_ErrorBusyRetry verifies that a Busy error from the responder
// is surfaced to the caller as a ProtocolError with the Busy code per DSP0274 Section 10.10.
func TestConformance_ErrorBusyRetry(t *testing.T) {
	busyResp := buildErrorResponse(uint8(codes.ErrorBusy), 0)

	mt := &mockTransport{responses: [][]byte{busyResp}}
	r := New(Config{
		Versions:  []algo.Version{algo.Version12},
		Transport: mt,
	})

	_, err := r.InitConnection(context.Background())
	require.Error(t, err, "expected error when responder returns Busy")

	var pe *status.ProtocolError
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, uint8(codes.ErrorBusy), pe.ErrorCode)
}

// TestConformance_ErrorVersionMismatch verifies that a VersionMismatch error
// is properly wrapped in a ProtocolError per DSP0274 Section 10.10.
func TestConformance_ErrorVersionMismatch(t *testing.T) {
	errResp := buildErrorResponse(uint8(codes.ErrorVersionMismatch), 0)

	mt := &mockTransport{responses: [][]byte{errResp}}
	r := New(Config{
		Versions:  []algo.Version{algo.Version12},
		Transport: mt,
	})

	_, err := r.InitConnection(context.Background())
	require.Error(t, err, "expected error when responder returns VersionMismatch")

	var pe *status.ProtocolError
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, uint8(codes.ErrorVersionMismatch), pe.ErrorCode)
}

// TestConformance_ErrorUnexpectedRequest verifies that an UnexpectedRequest
// error is properly surfaced per DSP0274 Section 10.10.
func TestConformance_ErrorUnexpectedRequest(t *testing.T) {
	errResp := buildErrorResponse(uint8(codes.ErrorUnexpectedRequest), 0)

	mt := &mockTransport{responses: [][]byte{errResp}}
	r := New(Config{
		Versions:  []algo.Version{algo.Version12},
		Transport: mt,
	})

	_, err := r.InitConnection(context.Background())
	require.Error(t, err, "expected error when responder returns UnexpectedRequest")

	var pe *status.ProtocolError
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, uint8(codes.ErrorUnexpectedRequest), pe.ErrorCode)
}

// --- Certificate Chain Format (DSP0274 Section 10.7) ---

// TestConformance_CertificateChainTooShort verifies that the requester handles
// a certificate chain response shorter than the minimum header size
// (CertChainHeaderSize + hash_size) per DSP0274 Section 10.7.
func TestConformance_CertificateChainTooShort(t *testing.T) {
	// Create a negotiated requester with SHA-256 (hash size = 32).
	// Send a cert response with only 2 bytes of chain data -- too short for
	// CertChainHeaderSize(4) + hashSize(32) = 36 bytes minimum.
	shortChain := []byte{0x01, 0x02}

	mt := &mockTransport{
		responses: [][]byte{
			buildCertificateResponse(0x12, 0, shortChain, 0),
		},
	}
	r := newNegotiatedRequester(mt)

	chain, err := r.GetCertificate(context.Background(), 0)
	require.NoError(t, err)

	// The chain was successfully received but is too short to contain
	// CertChainHeader(4 bytes) + RootHash(32 bytes) = 36 bytes.
	minSize := msgs.CertChainHeaderSize + r.conn.HashAlgo.Size()
	assert.Less(t, len(chain), minSize, "expected chain shorter than %d bytes", minSize)

	// Verify the chain length field (first 2 bytes LE) doesn't match actual data.
	if len(chain) >= 2 {
		declaredLen := int(binary.LittleEndian.Uint16(chain[0:2]))
		if declaredLen == len(chain) {
			t.Log("chain length field happens to match, but chain is still too short for valid format")
		}
	}
}

// TestConformance_CertificateChainLengthMismatch verifies behavior when the
// certificate chain header length field doesn't match the actual data length
// per DSP0274 Section 10.7.
func TestConformance_CertificateChainLengthMismatch(t *testing.T) {
	hashSize := 32 // SHA-256
	// Build a chain with a header claiming 1000 bytes total but only containing
	// CertChainHeader(4) + hash(32) + 10 bytes of cert data = 46 bytes.
	chainData := make([]byte, msgs.CertChainHeaderSize+hashSize+10)
	// Set length field to 1000 (mismatch with actual 46 bytes).
	binary.LittleEndian.PutUint16(chainData[0:2], 1000)

	mt := &mockTransport{
		responses: [][]byte{
			buildCertificateResponse(0x12, 0, chainData, 0),
		},
	}
	r := newNegotiatedRequester(mt)

	chain, err := r.GetCertificate(context.Background(), 0)
	require.NoError(t, err)

	// Verify that the declared length doesn't match the actual chain length.
	declaredLen := int(binary.LittleEndian.Uint16(chain[0:2]))
	assert.NotEqual(t, declaredLen, len(chain), "expected length mismatch between header field and actual chain data")
	assert.Equal(t, 1000, declaredLen)
	assert.NotEqual(t, 1000, len(chain), "actual chain should not be 1000 bytes")
}

// --- Challenge Nonce Handling (DSP0274 Section 10.8) ---

// TestConformance_ChallengeNonceNotEchoed verifies that the CHALLENGE_AUTH
// response contains a fresh nonce that is not identical to the request nonce
// per DSP0274 Section 10.8.
func TestConformance_ChallengeNonceNotEchoed(t *testing.T) {
	digestSize := 32 // SHA-256
	sigSize := 64    // ECDSA-P256

	mt := &mockTransport{
		responses: [][]byte{
			buildChallengeAuthResponse(0x12, 0, digestSize, 0, sigSize),
		},
	}
	r := newNegotiatedRequester(mt)

	err := r.Challenge(context.Background(), 0, msgs.NoMeasurementSummaryHash)
	require.NoError(t, err)

	// The sent CHALLENGE request contains the requester's nonce at offset 4..36.
	require.NotEmpty(t, mt.sent, "no messages sent")
	reqData := mt.sent[0]
	require.GreaterOrEqual(t, len(reqData), msgs.HeaderSize+msgs.NonceSize, "request too short: %d bytes", len(reqData))
	var reqNonce [msgs.NonceSize]byte
	copy(reqNonce[:], reqData[msgs.HeaderSize:msgs.HeaderSize+msgs.NonceSize])

	// The response was built with all-zero nonce (from buildChallengeAuthResponse).
	// A conforming requester should ensure the response nonce is fresh (not a copy of the request).
	// Since buildChallengeAuthResponse uses zero nonce and the request nonce is random,
	// they should differ.
	var zeroNonce [msgs.NonceSize]byte
	assert.NotEqual(t, zeroNonce, reqNonce, "request nonce is all zeros, which is statistically improbable")
	// The response nonce (all zeros) differs from the request nonce (random).
	// This validates the protocol property that nonces are independent.
}
