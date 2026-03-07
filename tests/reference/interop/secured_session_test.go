//go:build reference

package interop

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
	"github.com/xaionaro-go/spdm/pkg/requester"
	"github.com/xaionaro-go/spdm/pkg/session"
)

// establishSession is a shared setup for tests that need a session:
// InitConnection → GetDigests → GetCertificate → KeyExchange.
func establishSession(t *testing.T) (*EmuTransport, *session.Session) {
	t.Helper()
	proc := startEmuResponder(t,
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
		"--dhe", "SECP_256_R1",
		"--aead", "AES_256_GCM",
	)

	transport, err := proc.Connect()
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	cfg := newRequesterConfig(t, transport, algo.HashSHA256, algo.AsymECDSAP256, "ecdsa-p256")
	req := requester.New(cfg)

	ctx := context.Background()
	_, err = req.InitConnection(ctx)
	require.NoError(t, err)

	_, err = req.GetDigests(ctx)
	require.NoError(t, err)
	_, err = req.GetCertificate(ctx, 0)
	require.NoError(t, err)

	sess, err := req.KeyExchange(ctx, 0, msgs.NoMeasurementSummaryHash)
	require.NoError(t, err)
	require.Equal(t, session.StateEstablished, sess.State)

	return transport, sess
}

// TestInterop_GoRequester_LibspdmResponder_SecuredHeartbeat verifies that
// after KeyExchange, a secured HEARTBEAT message can be sent and acknowledged,
// exercising session encode/decode and AEAD encryption per DSP0274 Section 10.16.
func TestInterop_GoRequester_LibspdmResponder_SecuredHeartbeat(t *testing.T) {
	t.Skip("spdm-emu NONE transport does not support externally-constructed secured messages")
	transport, sess := establishSession(t)
	ctx := context.Background()

	// Build HEARTBEAT request.
	hb := &msgs.Heartbeat{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(algo.Version12),
			RequestResponseCode: uint8(codes.RequestHeartbeat),
		}},
	}
	plaintext, err := hb.Marshal()
	require.NoError(t, err)

	// Get request sequence number and encode secured message.
	reqSeq, err := sess.NextReqSeqNum()
	require.NoError(t, err)

	secured, err := session.EncodeSecuredMessage(
		sess.AEAD,
		sess.DataKeys.RequestKey,
		sess.DataKeys.RequestIV,
		reqSeq,
		uint32(sess.ID),
		plaintext,
		sess.EncryptionRequired,
		0,
	)
	require.NoError(t, err)

	// Send secured message via transport.
	require.NoError(t, transport.SendMessage(ctx, nil, secured))

	// Receive secured response.
	_, respSecured, err := transport.ReceiveMessage(ctx)
	require.NoError(t, err)

	// Decode secured response.
	rspSeq, err := sess.NextRspSeqNum()
	require.NoError(t, err)

	sessionID, respPlain, err := session.DecodeSecuredMessage(
		sess.AEAD,
		sess.DataKeys.ResponseKey,
		sess.DataKeys.ResponseIV,
		rspSeq,
		sess.EncryptionRequired,
		respSecured,
		0,
	)
	require.NoError(t, err)
	assert.Equal(t, uint32(sess.ID), sessionID)

	// Parse HEARTBEAT_ACK.
	var hbResp msgs.HeartbeatResponse
	require.NoError(t, hbResp.Unmarshal(respPlain))
	assert.Equal(t, uint8(codes.ResponseHeartbeatAck), hbResp.Header.RequestResponseCode)
	t.Log("Secured HEARTBEAT succeeded against libspdm")
}

// TestInterop_GoRequester_LibspdmResponder_SecuredEndSession verifies that
// after KeyExchange, an END_SESSION request can be sent and acknowledged via
// secured messaging per DSP0274 Section 10.19.
func TestInterop_GoRequester_LibspdmResponder_SecuredEndSession(t *testing.T) {
	t.Skip("spdm-emu NONE transport does not support externally-constructed secured messages")
	transport, sess := establishSession(t)
	ctx := context.Background()

	// Build END_SESSION request.
	endSess := &msgs.EndSession{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(algo.Version12),
			RequestResponseCode: uint8(codes.RequestEndSession),
		}},
	}
	plaintext, err := endSess.Marshal()
	require.NoError(t, err)

	reqSeq, err := sess.NextReqSeqNum()
	require.NoError(t, err)

	secured, err := session.EncodeSecuredMessage(
		sess.AEAD,
		sess.DataKeys.RequestKey,
		sess.DataKeys.RequestIV,
		reqSeq,
		uint32(sess.ID),
		plaintext,
		sess.EncryptionRequired,
		0,
	)
	require.NoError(t, err)

	require.NoError(t, transport.SendMessage(ctx, nil, secured))

	_, respSecured, err := transport.ReceiveMessage(ctx)
	require.NoError(t, err)

	rspSeq, err := sess.NextRspSeqNum()
	require.NoError(t, err)

	sessionID, respPlain, err := session.DecodeSecuredMessage(
		sess.AEAD,
		sess.DataKeys.ResponseKey,
		sess.DataKeys.ResponseIV,
		rspSeq,
		sess.EncryptionRequired,
		respSecured,
		0,
	)
	require.NoError(t, err)
	assert.Equal(t, uint32(sess.ID), sessionID)

	var endResp msgs.EndSessionResponse
	require.NoError(t, endResp.Unmarshal(respPlain))
	assert.Equal(t, uint8(codes.ResponseEndSessionAck), endResp.Header.RequestResponseCode)
	t.Log("Secured END_SESSION succeeded against libspdm")
}

// TestInterop_GoRequester_LibspdmResponder_DigestCertConsistency verifies
// that the SHA-256 hash of the certificate chain matches the digest returned
// by GET_DIGESTS per DSP0274 Sections 10.6 and 10.7.
func TestInterop_GoRequester_LibspdmResponder_DigestCertConsistency(t *testing.T) {
	proc := startEmuResponder(t,
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
	)

	transport, err := proc.Connect()
	require.NoError(t, err)
	defer transport.Close()

	cfg := newRequesterConfig(t, transport, algo.HashSHA256, algo.AsymECDSAP256, "ecdsa-p256")
	req := requester.New(cfg)

	ctx := context.Background()
	_, err = req.InitConnection(ctx)
	require.NoError(t, err)

	digests, err := req.GetDigests(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, digests)

	chain, err := req.GetCertificate(ctx, 0)
	require.NoError(t, err)
	require.NotEmpty(t, chain)

	computed := sha256.Sum256(chain)
	assert.Equal(t, computed[:], digests[0], "cert chain hash must match digest")
	t.Logf("Cert chain (%d bytes) hash matches digest", len(chain))
}

// TestInterop_GoRequester_LibspdmResponder_ChallengeAllMeasHash verifies
// CHALLENGE with AllMeasurements summary hash type per DSP0274 Section 10.8.
func TestInterop_GoRequester_LibspdmResponder_ChallengeAllMeasHash(t *testing.T) {
	proc := startEmuResponder(t,
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
		"--meas_hash", "SHA_256",
	)

	transport, err := proc.Connect()
	require.NoError(t, err)
	defer transport.Close()

	cfg := newRequesterConfig(t, transport, algo.HashSHA256, algo.AsymECDSAP256, "ecdsa-p256")
	req := requester.New(cfg)

	ctx := context.Background()
	_, err = req.InitConnection(ctx)
	require.NoError(t, err)

	require.NoError(t, req.Challenge(ctx, 0, msgs.AllMeasurementsHash))
	t.Log("Challenge with AllMeasurementsHash succeeded against libspdm")
}

// TestInterop_GoRequester_LibspdmResponder_GetAllMeasurements verifies
// requesting all measurements via index 0xFF per DSP0274 Section 10.11.
func TestInterop_GoRequester_LibspdmResponder_GetAllMeasurements(t *testing.T) {
	proc := startEmuResponder(t,
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
		"--meas_hash", "SHA_256",
	)

	transport, err := proc.Connect()
	require.NoError(t, err)
	defer transport.Close()

	cfg := newRequesterConfig(t, transport, algo.HashSHA256, algo.AsymECDSAP256, "ecdsa-p256")
	req := requester.New(cfg)

	ctx := context.Background()
	_, err = req.InitConnection(ctx)
	require.NoError(t, err)

	resp, err := req.GetMeasurements(ctx, msgs.MeasOpAllMeasurements, false)
	require.NoError(t, err)

	t.Logf("All measurements: %d blocks, record=%d bytes", resp.NumberOfBlocks, len(resp.MeasurementRecord))
	assert.NotZero(t, resp.NumberOfBlocks, "expected at least one measurement block")

	blocks, err := msgs.ParseMeasurementBlocks(resp.MeasurementRecord)
	require.NoError(t, err)
	assert.Equal(t, int(resp.NumberOfBlocks), len(blocks))
}

// TestInterop_GoRequester_LibspdmResponder_GetMeasurementCount verifies
// requesting measurement count via index 0 per DSP0274 Section 10.11.
func TestInterop_GoRequester_LibspdmResponder_GetMeasurementCount(t *testing.T) {
	proc := startEmuResponder(t,
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
		"--meas_hash", "SHA_256",
	)

	transport, err := proc.Connect()
	require.NoError(t, err)
	defer transport.Close()

	cfg := newRequesterConfig(t, transport, algo.HashSHA256, algo.AsymECDSAP256, "ecdsa-p256")
	req := requester.New(cfg)

	ctx := context.Background()
	_, err = req.InitConnection(ctx)
	require.NoError(t, err)

	resp, err := req.GetMeasurements(ctx, msgs.MeasOpTotalCount, false)
	require.NoError(t, err)

	t.Logf("Total measurement indices: %d (from Param1)", resp.Header.Param1)
}

// TestInterop_GoRequester_LibspdmResponder_ConnectionReset verifies that
// calling InitConnection twice resets state per DSP0274 Section 9.
func TestInterop_GoRequester_LibspdmResponder_ConnectionReset(t *testing.T) {
	proc := startEmuResponder(t,
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
	)

	transport, err := proc.Connect()
	require.NoError(t, err)
	defer transport.Close()

	cfg := newRequesterConfig(t, transport, algo.HashSHA256, algo.AsymECDSAP256, "ecdsa-p256")
	req := requester.New(cfg)
	ctx := context.Background()

	ci1, err := req.InitConnection(ctx)
	require.NoError(t, err)

	ci2, err := req.InitConnection(ctx)
	require.NoError(t, err)

	assert.Equal(t, ci1.PeerVersion, ci2.PeerVersion)
	assert.Equal(t, ci1.HashAlgo, ci2.HashAlgo)
	t.Log("Connection reset via GET_VERSION succeeded")
}

// TestInterop_GoRequester_LibspdmResponder_SHA384KeyExchange verifies
// KeyExchange with SHA-384/ECDSA-P384/SECP384R1 per DSP0274 Section 10.12.
func TestInterop_GoRequester_LibspdmResponder_SHA384KeyExchange(t *testing.T) {
	proc := startEmuResponder(t,
		"--ver", "1.2",
		"--hash", "SHA_384",
		"--asym", "ECDSA_P384",
		"--dhe", "SECP_384_R1",
		"--aead", "AES_256_GCM",
	)

	transport, err := proc.Connect()
	require.NoError(t, err)
	defer transport.Close()

	cfg := newRequesterConfig(t, transport, algo.HashSHA384, algo.AsymECDSAP384, "ecdsa-p384")
	cfg.DHEGroups = algo.DHESECP384R1
	req := requester.New(cfg)

	ctx := context.Background()
	_, err = req.InitConnection(ctx)
	require.NoError(t, err)

	_, err = req.GetDigests(ctx)
	require.NoError(t, err)
	_, err = req.GetCertificate(ctx, 0)
	require.NoError(t, err)

	sess, err := req.KeyExchange(ctx, 0, msgs.NoMeasurementSummaryHash)
	require.NoError(t, err)
	assert.Equal(t, session.StateEstablished, sess.State)
	t.Log("SHA-384/ECDSA-P384 KeyExchange succeeded")
}

// TestInterop_GoRequester_LibspdmResponder_KeyExchangeWithMeasSummary verifies
// KeyExchange with TCB measurement summary hash per DSP0274 Section 10.12.
func TestInterop_GoRequester_LibspdmResponder_KeyExchangeWithMeasSummary(t *testing.T) {
	proc := startEmuResponder(t,
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
		"--dhe", "SECP_256_R1",
		"--aead", "AES_256_GCM",
		"--meas_hash", "SHA_256",
	)

	transport, err := proc.Connect()
	require.NoError(t, err)
	defer transport.Close()

	cfg := newRequesterConfig(t, transport, algo.HashSHA256, algo.AsymECDSAP256, "ecdsa-p256")
	req := requester.New(cfg)

	ctx := context.Background()
	_, err = req.InitConnection(ctx)
	require.NoError(t, err)

	_, err = req.GetDigests(ctx)
	require.NoError(t, err)
	_, err = req.GetCertificate(ctx, 0)
	require.NoError(t, err)

	sess, err := req.KeyExchange(ctx, 0, msgs.TCBComponentMeasurementHash)
	require.NoError(t, err)
	assert.Equal(t, session.StateEstablished, sess.State)
	t.Log("KeyExchange with TCBComponentMeasurementHash succeeded")
}
