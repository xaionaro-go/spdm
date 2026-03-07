//go:build reference

package interop

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/caps"
	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
	"github.com/xaionaro-go/spdm/pkg/requester"
	"github.com/xaionaro-go/spdm/pkg/session"
)

// --- Go Requester session operations ---

// TestInterop_GoRequester_LibspdmResponder_KeyUpdate verifies KEY_UPDATE
// over a secured session per DSP0274 Section 10.17.
func TestInterop_GoRequester_LibspdmResponder_KeyUpdate(t *testing.T) {
	t.Skip("spdm-emu NONE transport does not support externally-constructed secured messages")
	transport, sess := establishSession(t)
	ctx := context.Background()

	// Build KEY_UPDATE request with UpdateKey operation.
	ku := &msgs.KeyUpdate{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(algo.Version12),
			RequestResponseCode: uint8(codes.RequestKeyUpdate),
			Param1:              1, // UpdateKey
			Param2:              1, // Tag
		}},
	}
	plaintext, err := ku.Marshal()
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

	var kuResp msgs.KeyUpdateResponse
	require.NoError(t, kuResp.Unmarshal(respPlain))
	assert.Equal(t, uint8(codes.ResponseKeyUpdateAck), kuResp.Header.RequestResponseCode)
	t.Log("Secured KEY_UPDATE succeeded against libspdm")
}

// TestInterop_GoRequester_LibspdmResponder_SecuredMeasurements verifies
// GET_MEASUREMENTS over a secured session per DSP0274 Section 10.11.
func TestInterop_GoRequester_LibspdmResponder_SecuredMeasurements(t *testing.T) {
	t.Skip("spdm-emu NONE transport does not support externally-constructed secured messages")
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

	// Send GET_MEASUREMENTS over the secured session.
	getMeas := &msgs.GetMeasurements{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(algo.Version12),
			RequestResponseCode: uint8(codes.RequestGetMeasurements),
			Param1:              0, // no sig requested
			Param2:              msgs.MeasOpTotalCount,
		}},
	}
	plaintext, err := getMeas.Marshal()
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

	_, respPlain, err := session.DecodeSecuredMessage(
		sess.AEAD,
		sess.DataKeys.ResponseKey,
		sess.DataKeys.ResponseIV,
		rspSeq,
		sess.EncryptionRequired,
		respSecured,
		0,
	)
	require.NoError(t, err)

	var measResp msgs.MeasurementsResponse
	require.NoError(t, measResp.Unmarshal(respPlain))
	assert.Equal(t, uint8(codes.ResponseMeasurements), measResp.Header.RequestResponseCode)
	t.Logf("Secured GET_MEASUREMENTS: %d measurement indices", measResp.Header.Param1)
}

// --- Go Requester algorithm variants ---

// TestInterop_GoRequester_LibspdmResponder_AEADAES128GCM verifies session
// establishment with AES-128-GCM AEAD per DSP0274 Section 10.12.
func TestInterop_GoRequester_LibspdmResponder_AEADAES128GCM(t *testing.T) {
	proc := startEmuResponder(t,
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
		"--dhe", "SECP_256_R1",
		"--aead", "AES_128_GCM",
	)

	transport, err := proc.Connect()
	require.NoError(t, err)
	defer transport.Close()

	cfg := newRequesterConfig(t, transport, algo.HashSHA256, algo.AsymECDSAP256, "ecdsa-p256")
	cfg.AEADSuites = algo.AEADAES128GCM
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
	t.Log("AES-128-GCM KeyExchange succeeded against libspdm")
}

// --- Go Responder algorithm variants ---

// TestInterop_LibspdmRequester_GoResponder_MeasurementsSigned verifies
// signed measurements from our Go responder.
func TestInterop_LibspdmRequester_GoResponder_MeasurementsSigned(t *testing.T) {
	skipIfNoEmu(t)

	rspCaps := caps.RspCertCap | caps.RspChalCap | caps.RspMeasCapSig |
		caps.RspEncryptCap | caps.RspMACCap | caps.RspKeyExCap |
		caps.RspHBeatCap | caps.RspKeyUpdCap | caps.RspHandshakeInTheClearCap

	measBlocks := []msgs.MeasurementBlock{
		{Index: 1, Spec: 0x01, ValueType: msgs.MeasTypeImmutableROM, Value: []byte("firmware-signed")},
		{Index: 2, Spec: 0x01, ValueType: msgs.MeasTypeMutableFirmware, Value: []byte("config-signed")},
		{Index: 3, Spec: 0x01, ValueType: msgs.MeasTypeImmutableROM, Value: []byte("bootloader-signed")},
	}

	serverErr := startGoResponderFull(t, goResponderConfig{
		rspCaps:      rspCaps,
		asymAlgo:     algo.AsymECDSAP256,
		hashAlgo:     algo.HashSHA256,
		dheGroups:    algo.DHESECP256R1,
		aeadSuites:   algo.AEADAES256GCM,
		measProvider: &staticMeasProvider{blocks: measBlocks},
	})

	output, err := runLibspdmRequester(t,
		"--trans", "NONE",
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
		"--meas_hash", "SHA_256",
		"--exe_conn", "DIGEST,CERT,CHAL,MEAS",
	)
	t.Logf("requester output:\n%s", output)

	assert.NoError(t, err)
	select {
	case srvErr := <-serverErr:
		assert.NoError(t, srvErr)
	default:
	}
}

// --- Error path coverage ---

// TestInterop_GoRequester_LibspdmResponder_SignedMeasurementsAllBlocks verifies
// requesting all measurements with signature from libspdm.
func TestInterop_GoRequester_LibspdmResponder_SignedMeasurementsAllBlocks(t *testing.T) {
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

	// Request all measurements with signature.
	resp, err := req.GetMeasurements(ctx, msgs.MeasOpAllMeasurements, true)
	require.NoError(t, err)
	assert.NotZero(t, resp.NumberOfBlocks)

	blocks, err := msgs.ParseMeasurementBlocks(resp.MeasurementRecord)
	require.NoError(t, err)
	assert.Equal(t, int(resp.NumberOfBlocks), len(blocks))
	t.Logf("Signed measurements: %d blocks", len(blocks))
}

// TestInterop_GoRequester_LibspdmResponder_MultipleGetMeasurements verifies
// requesting individual measurement indices in sequence.
func TestInterop_GoRequester_LibspdmResponder_MultipleGetMeasurements(t *testing.T) {
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

	// Get count first.
	countResp, err := req.GetMeasurements(ctx, msgs.MeasOpTotalCount, false)
	require.NoError(t, err)
	count := int(countResp.Header.Param1)
	t.Logf("Total measurement indices: %d", count)

	// Get individual measurements.
	for i := 1; i <= count && i <= 4; i++ {
		resp, err := req.GetMeasurements(ctx, uint8(i), false)
		require.NoError(t, err, "failed to get measurement index %d", i)
		assert.Equal(t, uint8(1), resp.NumberOfBlocks, "expected 1 block for index %d", i)
	}
}

// TestInterop_GoRequester_LibspdmResponder_KeyExchangeWithAllMeasSummary
// verifies KeyExchange with AllMeasurementsHash summary type.
func TestInterop_GoRequester_LibspdmResponder_KeyExchangeWithAllMeasSummary(t *testing.T) {
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

	sess, err := req.KeyExchange(ctx, 0, msgs.AllMeasurementsHash)
	require.NoError(t, err)
	assert.Equal(t, session.StateEstablished, sess.State)
	t.Log("KeyExchange with AllMeasurementsHash succeeded")
}
