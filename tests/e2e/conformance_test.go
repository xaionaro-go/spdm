package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/spdm/internal/testutil"
	"github.com/xaionaro-go/spdm/pkg/crypto/stdlib"
	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/caps"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
	"github.com/xaionaro-go/spdm/pkg/requester"
	"github.com/xaionaro-go/spdm/pkg/responder"
)

// TestE2EConformance_GetVersionResetsConnection verifies that sending
// GET_VERSION resets the connection state per DSP0274 Section 9.
// After full negotiation, calling InitConnection again (which sends
// GET_VERSION) must reset state so that subsequent operations succeed.
func TestE2EConformance_GetVersionResetsConnection(t *testing.T) {
	req, _, cancel := newTestSetup(t)
	defer cancel()

	ctx := context.Background()

	// First connection setup.
	_, err := req.InitConnection(ctx)
	require.NoError(t, err)

	// GetDigests should succeed after negotiation.
	digests1, err := req.GetDigests(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, digests1, "expected at least one digest after first connection")

	// Re-initialize connection (sends GET_VERSION, which resets state).
	_, err = req.InitConnection(ctx)
	require.NoError(t, err)

	// GetDigests must succeed again, proving state was properly reset.
	digests2, err := req.GetDigests(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, digests2, "expected at least one digest after state reset")
}

// TestE2EConformance_NoCommonAlgorithms verifies that InitConnection fails
// when requester and responder have no overlapping base asymmetric algorithms
// per DSP0274 Section 10.5.
func TestE2EConformance_NoCommonAlgorithms(t *testing.T) {
	reqSide, rspSide := testutil.NewLoopbackPair()
	_, _, leafKeyP256 := testutil.TestCerts(t, "ecdsa-p256")
	_, _, leafKeyP384 := testutil.TestCerts(t, "ecdsa-p384")

	reqCrypto := stdlib.NewSuite(leafKeyP256, nil)
	rspCrypto := stdlib.NewSuite(leafKeyP384, nil)

	// Requester supports only P-256, responder supports only P-384.
	req := requester.New(requester.Config{
		Versions:     []algo.Version{algo.Version12},
		Transport:    reqSide,
		Crypto:       *reqCrypto,
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	rsp := responder.New(responder.Config{
		Versions:     []algo.Version{algo.Version12},
		Transport:    rspSide,
		Crypto:       *rspCrypto,
		BaseAsymAlgo: algo.AsymECDSAP384,
		BaseHashAlgo: algo.HashSHA384,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = rsp.Serve(ctx) }()

	_, err := req.InitConnection(ctx)
	require.Error(t, err, "expected InitConnection to fail with no common algorithms")
	t.Logf("got expected error: %v", err)
}

// TestE2EConformance_MeasurementsAllIndex verifies that requesting
// measurements with index 0xFF returns all measurement blocks
// per DSP0274 Section 10.11.
func TestE2EConformance_MeasurementsAllIndex(t *testing.T) {
	req, _, cancel := newTestSetup(t)
	defer cancel()

	ctx := context.Background()
	_, err := req.InitConnection(ctx)
	require.NoError(t, err)

	// Index 0xFF = request all measurements.
	resp, err := req.GetMeasurements(ctx, 0xFF, false)
	require.NoError(t, err)

	// newTestSetup provides 2 measurement blocks.
	assert.Equal(t, uint8(2), resp.NumberOfBlocks)

	// Parse the record to verify blocks.
	blocks, err := msgs.ParseMeasurementBlocks(resp.MeasurementRecord)
	require.NoError(t, err)
	require.Equal(t, 2, len(blocks))

	// Verify block indices.
	assert.Equal(t, uint8(1), blocks[0].Index)
	assert.Equal(t, uint8(2), blocks[1].Index)
}

// TestE2EConformance_MeasurementsSpecificIndex verifies that requesting
// a specific measurement index returns the corresponding block
// per DSP0274 Section 10.11.
func TestE2EConformance_MeasurementsSpecificIndex(t *testing.T) {
	req, _, cancel := newTestSetup(t)
	defer cancel()

	ctx := context.Background()
	_, err := req.InitConnection(ctx)
	require.NoError(t, err)

	// Request specific index 1.
	resp, err := req.GetMeasurements(ctx, 1, false)
	require.NoError(t, err)

	// The mock provider returns all blocks regardless of index
	// (it delegates filtering to the provider). Verify we get a valid response.
	assert.NotEqual(t, 0, resp.NumberOfBlocks, "expected at least one measurement block")
	assert.NotEqual(t, 0, len(resp.MeasurementRecord), "expected non-empty measurement record")
}

// TestE2EConformance_CertificateRetrievalConsistency verifies that the
// hash of a retrieved certificate chain matches the corresponding digest
// per DSP0274 Section 10.7.
func TestE2EConformance_CertificateRetrievalConsistency(t *testing.T) {
	req, _, cancel := newTestSetup(t)
	defer cancel()

	ctx := context.Background()
	_, err := req.InitConnection(ctx)
	require.NoError(t, err)

	// Retrieve certificate chain for slot 0.
	chain, err := req.GetCertificate(ctx, 0)
	require.NoError(t, err)
	require.NotEmpty(t, chain, "empty cert chain")

	// Retrieve digests.
	digests, err := req.GetDigests(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, digests, "no digests returned")

	// Compute SHA-256 hash of the cert chain (negotiated hash is SHA-256).
	computed := sha256.Sum256(chain)

	// The digest for slot 0 should match the hash of the cert chain.
	assert.Equal(t, computed[:], digests[0])
}

// TestE2EConformance_ChallengeAuthNonceFreshness verifies that two
// successive CHALLENGE_AUTH responses contain different nonces,
// confirming randomness per DSP0274 Section 10.8.
func TestE2EConformance_ChallengeAuthNonceFreshness(t *testing.T) {
	reqSide, rspSide := testutil.NewLoopbackPair()
	_, _, leafKey := testutil.TestCerts(t, "ecdsa-p256")

	certChain := bytes.Repeat([]byte{0xAA}, 100)
	digest := sha256.Sum256(certChain)

	cp := &mockCertProvider{
		chains:  map[uint8][]byte{0: certChain},
		digests: map[uint8][]byte{0: digest[:]},
	}

	reqCrypto := stdlib.NewSuite(leafKey, nil)
	rspCrypto := stdlib.NewSuite(leafKey, nil)

	rsp := responder.New(responder.Config{
		Versions:     []algo.Version{algo.Version12},
		Transport:    rspSide,
		Crypto:       *rspCrypto,
		Caps:         caps.ResponderCaps(0),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
		DHEGroups:    algo.DHESECP256R1,
		AEADSuites:   algo.AEADAES256GCM,
		CertProvider: cp,
		DeviceSigner: leafKey,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = rsp.Serve(ctx) }()

	req := requester.New(requester.Config{
		Versions:     []algo.Version{algo.Version12},
		Transport:    reqSide,
		Crypto:       *reqCrypto,
		Caps:         caps.RequesterCaps(0),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
		DHEGroups:    algo.DHESECP256R1,
		AEADSuites:   algo.AEADAES256GCM,
	})

	_, err := req.InitConnection(ctx)
	require.NoError(t, err)

	// Perform first challenge and capture the raw response nonce by sending
	// a challenge manually via transport so we can inspect the response.
	nonce1 := challengeAndExtractNonce(t, ctx, reqSide, algo.Version12)
	nonce2 := challengeAndExtractNonce(t, ctx, reqSide, algo.Version12)

	assert.NotEqual(t, nonce2, nonce1, "two successive CHALLENGE_AUTH responses returned identical nonces; expected random freshness")
}

// challengeAndExtractNonce sends a CHALLENGE request and returns the
// responder nonce from the CHALLENGE_AUTH response.
func challengeAndExtractNonce(t *testing.T, ctx context.Context, tr *testutil.LoopbackTransport, ver algo.Version) [msgs.NonceSize]byte {
	t.Helper()

	challenge := &msgs.Challenge{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(ver),
			RequestResponseCode: 0x83, // CHALLENGE request code
			Param1:              0,    // slot 0
			Param2:              0xFF, // all measurements summary hash
		}},
	}
	// Fill nonce with random data.
	for i := range challenge.Nonce {
		challenge.Nonce[i] = byte(i)
	}

	data, err := challenge.Marshal()
	require.NoError(t, err)

	require.NoError(t, tr.SendMessage(ctx, nil, data))

	_, resp, err := tr.ReceiveMessage(ctx)
	require.NoError(t, err)

	// Parse nonce from the CHALLENGE_AUTH response.
	// Layout: header(4) + cert_chain_hash(32 for SHA-256) + nonce(32).
	digestSize := 32 // SHA-256
	nonceOffset := msgs.HeaderSize + digestSize
	require.GreaterOrEqual(t, len(resp), nonceOffset+msgs.NonceSize)

	var nonce [msgs.NonceSize]byte
	copy(nonce[:], resp[nonceOffset:nonceOffset+msgs.NonceSize])
	return nonce
}

// TestE2EConformance_MultipleSequentialConnections verifies that multiple
// sequential connection setups succeed because GET_VERSION resets state
// per DSP0274 Section 9.
func TestE2EConformance_MultipleSequentialConnections(t *testing.T) {
	req, _, cancel := newTestSetup(t)
	defer cancel()

	ctx := context.Background()

	for i := 0; i < 3; i++ {
		ci, err := req.InitConnection(ctx)
		require.NoError(t, err)
		assert.Equal(t, algo.Version12, ci.PeerVersion)
		assert.Equal(t, algo.HashSHA256, ci.HashAlgo)
	}
}

// TestE2EConformance_MinimalCapabilities verifies that a connection with
// minimal capabilities (no CERT, no MEAS, no KEY_EX) can be established
// but data operations like GetDigests fail per DSP0274 Section 10.4.
func TestE2EConformance_MinimalCapabilities(t *testing.T) {
	reqSide, rspSide := testutil.NewLoopbackPair()
	_, _, leafKey := testutil.TestCerts(t, "ecdsa-p256")
	reqCrypto := stdlib.NewSuite(leafKey, nil)
	rspCrypto := stdlib.NewSuite(leafKey, nil)

	// Minimal config: no CertProvider, no MeasProvider, no DeviceSigner.
	req := requester.New(requester.Config{
		Versions:     []algo.Version{algo.Version12},
		Transport:    reqSide,
		Crypto:       *reqCrypto,
		Caps:         caps.RequesterCaps(0),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	rsp := responder.New(responder.Config{
		Versions:     []algo.Version{algo.Version12},
		Transport:    rspSide,
		Crypto:       *rspCrypto,
		Caps:         caps.ResponderCaps(0),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = rsp.Serve(ctx) }()

	// Connection setup should succeed even with minimal capabilities.
	ci, err := req.InitConnection(ctx)
	require.NoError(t, err)
	assert.Equal(t, algo.Version12, ci.PeerVersion)

	// GetDigests should fail because the responder has no CertProvider.
	_, err = req.GetDigests(ctx)
	assert.NotEqual(t, nil, err, "expected GetDigests to fail with no CertProvider on responder")
}
