package requester

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/spdm/pkg/crypto"
	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/caps"
	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
	"github.com/xaionaro-go/spdm/pkg/gen/status"
)

// mockTransport is a test transport that returns canned responses in order.
type mockTransport struct {
	sent      [][]byte // recorded sent messages
	responses [][]byte // canned responses to return
	idx       int
	sendErr   error
	recvErr   error
}

func (m *mockTransport) SendMessage(_ context.Context, _ *uint32, msg []byte) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	cp := make([]byte, len(msg))
	copy(cp, msg)
	m.sent = append(m.sent, cp)
	return nil
}

func (m *mockTransport) ReceiveMessage(_ context.Context) (*uint32, []byte, error) {
	if m.recvErr != nil {
		return nil, nil, m.recvErr
	}
	if m.idx >= len(m.responses) {
		return nil, nil, errors.New("no more responses")
	}
	resp := m.responses[m.idx]
	m.idx++
	return nil, resp, nil
}

func (m *mockTransport) HeaderSize() int { return 0 }

// mockKeyAgreement implements crypto.KeyAgreement for testing.
type mockKeyAgreement struct {
	pubKey       []byte
	sharedSecret []byte
	genErr       error
	computeErr   error
}

func (m *mockKeyAgreement) GenerateDHE(_ algo.DHENamedGroup) (interface{}, []byte, error) {
	if m.genErr != nil {
		return nil, nil, m.genErr
	}
	return "privkey", m.pubKey, nil
}

func (m *mockKeyAgreement) ComputeDHE(_ algo.DHENamedGroup, _ interface{}, _ []byte) ([]byte, error) {
	if m.computeErr != nil {
		return nil, m.computeErr
	}
	return m.sharedSecret, nil
}

// buildVersionResponse builds a canned VERSION response with the given version entries.
func buildVersionResponse(versions ...uint16) []byte {
	resp := &msgs.VersionResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x10,
			RequestResponseCode: uint8(codes.ResponseVersion),
		}},
		VersionEntries: versions,
	}
	data, _ := resp.Marshal()
	return data
}

// buildCapabilitiesResponse builds a canned CAPABILITIES response.
func buildCapabilitiesResponse(ver uint8, flags uint32) []byte {
	resp := &msgs.CapabilitiesResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.ResponseCapabilities),
		}},
		Flags:            flags,
		DataTransferSize: 4096,
		MaxSPDMmsgSize:   65536,
	}
	data, _ := resp.Marshal()
	return data
}

// buildAlgorithmsResponse builds a canned ALGORITHMS response.
func buildAlgorithmsResponse(ver uint8, hashSel, asymSel, measHashAlgo uint32, dheGroup, aeadSuite uint16) []byte {
	algStructs := []msgs.AlgStructTable{
		{AlgType: msgs.AlgTypeDHE, AlgCount: 0x20, AlgSupported: dheGroup},
		{AlgType: msgs.AlgTypeAEAD, AlgCount: 0x20, AlgSupported: aeadSuite},
	}
	resp := &msgs.AlgorithmsResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.ResponseAlgorithms),
			Param1:              uint8(len(algStructs)),
		}},
		MeasurementSpecificationSel: uint8(algo.MeasurementSpecDMTF),
		MeasurementHashAlgo:         measHashAlgo,
		BaseAsymSel:                 asymSel,
		BaseHashSel:                 hashSel,
		AlgStructs:                  algStructs,
	}
	data, _ := resp.Marshal()
	return data
}

// buildDigestResponse builds a canned DIGESTS response.
func buildDigestResponse(ver uint8, slotMask uint8, digests [][]byte) []byte {
	resp := &msgs.DigestResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.ResponseDigests),
			Param2:              slotMask,
		}},
		Digests: digests,
	}
	data, _ := resp.Marshal()
	return data
}

// buildErrorResponse builds a canned ERROR response.
func buildErrorResponse(errCode uint8, errData uint8) []byte {
	resp := &msgs.ErrorResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseError),
			Param1:              errCode,
			Param2:              errData,
		}},
	}
	data, _ := resp.Marshal()
	return data
}

// buildCertificateResponse builds a canned CERTIFICATE response.
func buildCertificateResponse(ver uint8, slotID uint8, portion []byte, remainder uint16) []byte {
	resp := &msgs.CertificateResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.ResponseCertificate),
			Param1:              slotID,
		}},
		PortionLength:   uint16(len(portion)),
		RemainderLength: remainder,
		CertChain:       portion,
	}
	data, _ := resp.Marshal()
	return data
}

// buildChallengeAuthResponse builds a canned CHALLENGE_AUTH response.
func buildChallengeAuthResponse(ver uint8, slotID uint8, digestSize int, measHashSize int, sigSize int) []byte {
	resp := &msgs.ChallengeAuthResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.ResponseChallengeAuth),
			Param1:              slotID,
			Param2:              1 << slotID,
		}},
		CertChainHash:          make([]byte, digestSize),
		MeasurementSummaryHash: make([]byte, measHashSize),
		Signature:              make([]byte, sigSize),
	}
	data, _ := resp.Marshal()
	return data
}

// buildMeasurementsResponse builds a canned MEASUREMENTS response.
func buildMeasurementsResponse(ver uint8, numBlocks uint8, record []byte) []byte {
	resp := &msgs.MeasurementsResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.ResponseMeasurements),
			Param1:              numBlocks,
		}},
		NumberOfBlocks:       numBlocks,
		MeasurementRecordLen: uint32(len(record)),
		MeasurementRecord:    record,
	}
	data, _ := resp.Marshal()
	return data
}

// buildKeyExchangeResponse builds a KEY_EXCHANGE_RSP response with proper binary layout.
func buildKeyExchangeResponse(ver uint8, rspSessionID uint16, dhePublic []byte, measHash []byte, sigSize int, hashSize int) []byte {
	resp := &msgs.KeyExchangeResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.ResponseKeyExchangeRsp),
		}},
		RspSessionID:           rspSessionID,
		ExchangeData:           dhePublic,
		MeasurementSummaryHash: measHash,
		Signature:              make([]byte, sigSize),
		VerifyData:             make([]byte, hashSize),
	}
	data, _ := resp.Marshal()
	return data
}

// buildFinishResponse builds a canned FINISH_RSP response.
func buildFinishResponse(ver uint8) []byte {
	resp := &msgs.FinishResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.ResponseFinishRsp),
		}},
	}
	data, _ := resp.Marshal()
	return data
}

// newNegotiatedRequester creates a requester that has completed algorithm negotiation.
func newNegotiatedRequester(mt *mockTransport) *Requester {
	r := New(Config{
		Versions:     []algo.Version{algo.Version12},
		Transport:    mt,
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
		DHEGroups:    algo.DHESECP256R1,
		AEADSuites:   algo.AEADAES128GCM,
	})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256
	r.conn.AsymAlgo = algo.AsymECDSAP256
	r.conn.DHEGroup = algo.DHESECP256R1
	r.conn.AEADSuite = algo.AEADAES128GCM
	r.state = StateAfterAlgorithms
	return r
}

// --- New() tests ---

func TestNewDefaultDataTransferSize(t *testing.T) {
	r := New(Config{})
	assert.Equal(t, uint32(4096), r.cfg.DataTransferSize)
	assert.Equal(t, uint32(65536), r.cfg.MaxSPDMmsgSize)
}

func TestNewCustomSizes(t *testing.T) {
	r := New(Config{DataTransferSize: 1024, MaxSPDMmsgSize: 2048})
	assert.Equal(t, uint32(1024), r.cfg.DataTransferSize)
	assert.Equal(t, uint32(2048), r.cfg.MaxSPDMmsgSize)
}

func TestConnectionInfo(t *testing.T) {
	r := New(Config{})
	r.conn.PeerVersion = algo.Version12
	info := r.ConnectionInfo()
	assert.Equal(t, algo.Version12, info.PeerVersion)
}

// --- sendReceive error handling tests ---

func TestSendReceiveSendError(t *testing.T) {
	mt := &mockTransport{sendErr: fmt.Errorf("send failed")}
	r := New(Config{Transport: mt})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256

	_, err := r.GetDigests(context.Background())
	require.Error(t, err, "expected error from send failure")
	assert.ErrorIs(t, err, mt.sendErr)
}

func TestSendReceiveRecvError(t *testing.T) {
	mt := &mockTransport{recvErr: fmt.Errorf("recv failed")}
	r := New(Config{Transport: mt})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256

	_, err := r.GetDigests(context.Background())
	require.Error(t, err, "expected error from receive failure")
}

func TestSendReceiveShortResponse(t *testing.T) {
	mt := &mockTransport{
		responses: [][]byte{{0x12, 0x01}}, // too short (< HeaderSize=4)
	}
	r := New(Config{Transport: mt})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256

	_, err := r.GetDigests(context.Background())
	require.Error(t, err, "expected error from short response")
	assert.ErrorIs(t, err, status.ErrInvalidMsgSize)
}

// --- InitConnection tests ---

func TestInitConnection(t *testing.T) {
	versionEntry := uint16(0x1200)

	mt := &mockTransport{
		responses: [][]byte{
			buildVersionResponse(versionEntry),
			buildCapabilitiesResponse(0x12, uint32(caps.RspCertCap|caps.RspChalCap|caps.RspMeasCapSig)),
			buildAlgorithmsResponse(0x12,
				uint32(algo.HashSHA256),
				uint32(algo.AsymECDSAP256),
				uint32(algo.MeasHashSHA256),
				uint16(algo.DHESECP256R1),
				uint16(algo.AEADAES128GCM),
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

	ctx := context.Background()
	info, err := r.InitConnection(ctx)
	require.NoError(t, err)

	assert.Equal(t, algo.Version12, info.PeerVersion)
	assert.Equal(t, algo.HashSHA256, info.HashAlgo)
	assert.Equal(t, algo.AsymECDSAP256, info.AsymAlgo)
	assert.Equal(t, algo.DHESECP256R1, info.DHEGroup)
	assert.Equal(t, algo.AEADAES128GCM, info.AEADSuite)
	assert.Equal(t, algo.MeasHashSHA256, info.MeasHashAlgo)
	assert.Equal(t, StateAfterAlgorithms, r.State())
	assert.Len(t, mt.sent, 3)
}

func TestInitConnectionNoCommonVersion(t *testing.T) {
	versionEntry := uint16(0x1000)

	mt := &mockTransport{
		responses: [][]byte{
			buildVersionResponse(versionEntry),
		},
	}

	r := New(Config{
		Versions:  []algo.Version{algo.Version12},
		Transport: mt,
	})

	ctx := context.Background()
	_, err := r.InitConnection(ctx)
	require.Error(t, err, "expected error for no common version")
}

func TestInitConnectionPicksHighestVersion(t *testing.T) {
	mt := &mockTransport{
		responses: [][]byte{
			buildVersionResponse(0x1000, 0x1200, 0x1300),
			buildCapabilitiesResponse(0x13, uint32(caps.RspCertCap)),
			buildAlgorithmsResponse(0x13,
				uint32(algo.HashSHA384),
				uint32(algo.AsymECDSAP384),
				uint32(algo.MeasHashSHA384),
				uint16(algo.DHESECP384R1),
				uint16(algo.AEADAES256GCM),
			),
		},
	}

	r := New(Config{
		Versions:     []algo.Version{algo.Version12, algo.Version13},
		Transport:    mt,
		BaseAsymAlgo: algo.AsymECDSAP384,
		BaseHashAlgo: algo.HashSHA384,
		DHEGroups:    algo.DHESECP384R1,
		AEADSuites:   algo.AEADAES256GCM,
	})

	ctx := context.Background()
	info, err := r.InitConnection(ctx)
	require.NoError(t, err)
	assert.Equal(t, algo.Version13, info.PeerVersion)
}

func TestInitConnectionCapabilitiesError(t *testing.T) {
	mt := &mockTransport{
		responses: [][]byte{
			buildVersionResponse(0x1200),
			buildErrorResponse(uint8(codes.ErrorBusy), 0),
		},
	}

	r := New(Config{
		Versions:  []algo.Version{algo.Version12},
		Transport: mt,
	})

	_, err := r.InitConnection(context.Background())
	require.Error(t, err, "expected error from capabilities step")
}

func TestInitConnectionAlgorithmsError(t *testing.T) {
	mt := &mockTransport{
		responses: [][]byte{
			buildVersionResponse(0x1200),
			buildCapabilitiesResponse(0x12, uint32(caps.RspCertCap)),
			buildErrorResponse(uint8(codes.ErrorUnspecified), 0),
		},
	}

	r := New(Config{
		Versions:     []algo.Version{algo.Version12},
		Transport:    mt,
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	_, err := r.InitConnection(context.Background())
	require.Error(t, err, "expected error from algorithms step")
}

func TestNegotiateAlgorithmsZeroHashFails(t *testing.T) {
	mt := &mockTransport{
		responses: [][]byte{
			buildVersionResponse(0x1200),
			buildCapabilitiesResponse(0x12, uint32(caps.RspCertCap)),
			buildAlgorithmsResponse(0x12, 0, uint32(algo.AsymECDSAP256), 0, 0, 0),
		},
	}

	r := New(Config{
		Versions:     []algo.Version{algo.Version12},
		Transport:    mt,
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	_, err := r.InitConnection(context.Background())
	require.Error(t, err, "expected negotiation failure for zero hash selection")
}

func TestNegotiateAlgorithmsNoDHEOrAEAD(t *testing.T) {
	// No DHEGroups or AEADSuites configured: should still negotiate base algorithms.
	mt := &mockTransport{
		responses: [][]byte{
			buildVersionResponse(0x1200),
			buildCapabilitiesResponse(0x12, uint32(caps.RspCertCap)),
			buildAlgorithmsResponse(0x12,
				uint32(algo.HashSHA256),
				uint32(algo.AsymECDSAP256),
				uint32(algo.MeasHashSHA256),
				0, 0,
			),
		},
	}

	r := New(Config{
		Versions:     []algo.Version{algo.Version12},
		Transport:    mt,
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	info, err := r.InitConnection(context.Background())
	require.NoError(t, err)
	assert.Equal(t, algo.DHENamedGroup(0), info.DHEGroup)
	assert.Equal(t, algo.AEADCipherSuite(0), info.AEADSuite)
}

// --- GetDigests tests ---

func TestGetDigests(t *testing.T) {
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}

	mt := &mockTransport{
		responses: [][]byte{
			buildDigestResponse(0x12, 0x01, [][]byte{digest}),
		},
	}

	r := New(Config{Transport: mt})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256
	r.state = StateAfterAlgorithms

	ctx := context.Background()
	digests, err := r.GetDigests(ctx)
	require.NoError(t, err)

	require.Len(t, digests, 1)
	assert.Equal(t, digest, digests[0])
}

func TestErrorResponseHandling(t *testing.T) {
	mt := &mockTransport{
		responses: [][]byte{
			buildErrorResponse(uint8(codes.ErrorBusy), 0x00),
		},
	}

	r := New(Config{Transport: mt})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256

	ctx := context.Background()
	_, err := r.GetDigests(ctx)
	require.Error(t, err, "expected error from ERROR response")

	var pe *status.ProtocolError
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, uint8(codes.ErrorBusy), pe.ErrorCode)
}

func TestGetDigestsMultipleSlots(t *testing.T) {
	d0 := make([]byte, 32)
	d1 := make([]byte, 32)
	for i := range d0 {
		d0[i] = byte(i)
		d1[i] = byte(i + 0x80)
	}

	mt := &mockTransport{
		responses: [][]byte{
			buildDigestResponse(0x12, 0x03, [][]byte{d0, d1}),
		},
	}

	r := New(Config{Transport: mt})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256

	ctx := context.Background()
	digests, err := r.GetDigests(ctx)
	require.NoError(t, err)
	require.Len(t, digests, 2)
}

// --- GetCertificate tests ---

func TestGetCertificateSingleChunk(t *testing.T) {
	chain := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	mt := &mockTransport{
		responses: [][]byte{
			buildCertificateResponse(0x12, 0, chain, 0),
		},
	}

	r := newNegotiatedRequester(mt)

	result, err := r.GetCertificate(context.Background(), 0)
	require.NoError(t, err)
	assert.Equal(t, chain, result)
}

func TestGetCertificateMultiChunk(t *testing.T) {
	chunk1 := []byte{0x01, 0x02, 0x03}
	chunk2 := []byte{0x04, 0x05}

	mt := &mockTransport{
		responses: [][]byte{
			buildCertificateResponse(0x12, 0, chunk1, uint16(len(chunk2))),
			buildCertificateResponse(0x12, 0, chunk2, 0),
		},
	}

	r := newNegotiatedRequester(mt)

	result, err := r.GetCertificate(context.Background(), 0)
	require.NoError(t, err)
	expected := append(chunk1, chunk2...)
	assert.Equal(t, expected, result)
	assert.Len(t, mt.sent, 2)
}

func TestGetCertificateErrorResponse(t *testing.T) {
	mt := &mockTransport{
		responses: [][]byte{
			buildErrorResponse(uint8(codes.ErrorUnspecified), 0),
		},
	}

	r := newNegotiatedRequester(mt)

	_, err := r.GetCertificate(context.Background(), 0)
	require.Error(t, err, "expected error")
	var pe *status.ProtocolError
	require.ErrorAs(t, err, &pe)
}

func TestGetCertificateSlotID(t *testing.T) {
	chain := []byte{0xAA}
	mt := &mockTransport{
		responses: [][]byte{
			buildCertificateResponse(0x12, 3, chain, 0),
		},
	}

	r := newNegotiatedRequester(mt)
	_, err := r.GetCertificate(context.Background(), 3)
	require.NoError(t, err)

	// Verify the sent request has correct slotID.
	var req msgs.GetCertificate
	require.NoError(t, req.Unmarshal(mt.sent[0]))
	assert.Equal(t, uint8(3), req.SlotID())
}

// --- Challenge tests ---

func TestChallengeNoMeasurementHash(t *testing.T) {
	digestSize := algo.HashSHA256.Size()
	sigSize := algo.AsymECDSAP256.SignatureSize()

	mt := &mockTransport{
		responses: [][]byte{
			buildChallengeAuthResponse(0x12, 0, digestSize, 0, sigSize),
		},
	}

	r := newNegotiatedRequester(mt)

	err := r.Challenge(context.Background(), 0, msgs.NoMeasurementSummaryHash)
	require.NoError(t, err)
	assert.Equal(t, StateAuthenticated, r.State())
}

func TestChallengeWithMeasurementHash(t *testing.T) {
	digestSize := algo.HashSHA256.Size()
	sigSize := algo.AsymECDSAP256.SignatureSize()

	mt := &mockTransport{
		responses: [][]byte{
			buildChallengeAuthResponse(0x12, 0, digestSize, digestSize, sigSize),
		},
	}

	r := newNegotiatedRequester(mt)

	err := r.Challenge(context.Background(), 0, msgs.TCBComponentMeasurementHash)
	require.NoError(t, err)
	assert.Equal(t, StateAuthenticated, r.State())
}

func TestChallengeErrorResponse(t *testing.T) {
	mt := &mockTransport{
		responses: [][]byte{
			buildErrorResponse(uint8(codes.ErrorUnspecified), 0),
		},
	}

	r := newNegotiatedRequester(mt)

	err := r.Challenge(context.Background(), 0, msgs.NoMeasurementSummaryHash)
	require.Error(t, err, "expected error")
}

func TestChallengeAllMeasurementsHash(t *testing.T) {
	digestSize := algo.HashSHA256.Size()
	sigSize := algo.AsymECDSAP256.SignatureSize()

	mt := &mockTransport{
		responses: [][]byte{
			buildChallengeAuthResponse(0x12, 1, digestSize, digestSize, sigSize),
		},
	}

	r := newNegotiatedRequester(mt)

	err := r.Challenge(context.Background(), 1, msgs.AllMeasurementsHash)
	require.NoError(t, err)
}

// --- GetMeasurements tests ---

func TestGetMeasurementsNoSignature(t *testing.T) {
	mt := &mockTransport{
		responses: [][]byte{
			buildMeasurementsResponse(0x12, 2, []byte{0xAA, 0xBB}),
		},
	}

	r := newNegotiatedRequester(mt)

	mr, err := r.GetMeasurements(context.Background(), 0xFF, false)
	require.NoError(t, err)
	assert.Equal(t, uint8(2), mr.NumberOfBlocks)
	// Verify no signature attribute in request.
	var req msgs.GetMeasurements
	require.NoError(t, req.Unmarshal(mt.sent[0]))
	assert.Zero(t, req.Header.Param1&msgs.MeasAttrGenerateSignature, "expected no signature attribute")
}

func TestGetMeasurementsWithSignature(t *testing.T) {
	mt := &mockTransport{
		responses: [][]byte{
			buildMeasurementsResponse(0x12, 1, nil),
		},
	}

	r := newNegotiatedRequester(mt)

	mr, err := r.GetMeasurements(context.Background(), 1, true)
	require.NoError(t, err)
	assert.Equal(t, uint8(1), mr.NumberOfBlocks)
	// Verify signature attribute in request.
	var req msgs.GetMeasurements
	require.NoError(t, req.Unmarshal(mt.sent[0]))
	assert.NotEqual(t, uint8(0), req.Header.Param1&uint8(msgs.MeasAttrGenerateSignature), "expected signature attribute set")
	assert.Equal(t, uint8(1), req.Header.Param2)
}

func TestGetMeasurementsErrorResponse(t *testing.T) {
	mt := &mockTransport{
		responses: [][]byte{
			buildErrorResponse(uint8(codes.ErrorUnsupportedRequest), 0),
		},
	}

	r := newNegotiatedRequester(mt)

	_, err := r.GetMeasurements(context.Background(), 0, false)
	require.Error(t, err, "expected error")
	var pe *status.ProtocolError
	require.ErrorAs(t, err, &pe)
}

// --- KeyExchange tests ---

func TestKeyExchange(t *testing.T) {
	dheSize := 32 // mock DHE public key size
	pubKey := make([]byte, dheSize)
	for i := range pubKey {
		pubKey[i] = byte(i)
	}
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 0x80)
	}

	digestSize := algo.HashSHA256.Size()
	sigSize := algo.AsymECDSAP256.SignatureSize()

	mt := &mockTransport{
		responses: [][]byte{
			buildKeyExchangeResponse(0x12, 0xBBBB, pubKey, nil, sigSize, digestSize),
			buildFinishResponse(0x12),
		},
	}

	ka := &mockKeyAgreement{pubKey: pubKey, sharedSecret: sharedSecret}

	r := New(Config{
		Versions:     []algo.Version{algo.Version12},
		Transport:    mt,
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
		DHEGroups:    algo.DHESECP256R1,
		AEADSuites:   algo.AEADAES128GCM,
		Crypto:       crypto.Suite{KeyAgreement: ka},
	})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256
	r.conn.AsymAlgo = algo.AsymECDSAP256
	r.conn.DHEGroup = algo.DHESECP256R1
	r.conn.AEADSuite = algo.AEADAES128GCM
	r.state = StateAfterAlgorithms

	sess, err := r.KeyExchange(context.Background(), 0, msgs.NoMeasurementSummaryHash)
	require.NoError(t, err)
	require.NotNil(t, sess, "session is nil")
	assert.Len(t, mt.sent, 2)
}

func TestKeyExchangeWithMeasHash(t *testing.T) {
	dheSize := 32
	pubKey := make([]byte, dheSize)
	sharedSecret := make([]byte, 32)

	digestSize := algo.HashSHA256.Size()
	sigSize := algo.AsymECDSAP256.SignatureSize()
	measHash := make([]byte, digestSize)

	mt := &mockTransport{
		responses: [][]byte{
			buildKeyExchangeResponse(0x12, 0xCCCC, pubKey, measHash, sigSize, digestSize),
			buildFinishResponse(0x12),
		},
	}

	ka := &mockKeyAgreement{pubKey: pubKey, sharedSecret: sharedSecret}

	r := New(Config{
		Versions:     []algo.Version{algo.Version12},
		Transport:    mt,
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
		DHEGroups:    algo.DHESECP256R1,
		AEADSuites:   algo.AEADAES128GCM,
		Crypto:       crypto.Suite{KeyAgreement: ka},
	})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256
	r.conn.AsymAlgo = algo.AsymECDSAP256
	r.conn.DHEGroup = algo.DHESECP256R1
	r.conn.AEADSuite = algo.AEADAES128GCM
	r.state = StateAfterAlgorithms

	sess, err := r.KeyExchange(context.Background(), 0, msgs.TCBComponentMeasurementHash)
	require.NoError(t, err)
	require.NotNil(t, sess, "session is nil")
}

func TestKeyExchangeGenerateDHEError(t *testing.T) {
	mt := &mockTransport{}
	ka := &mockKeyAgreement{genErr: fmt.Errorf("keygen failed")}

	r := New(Config{
		Transport: mt,
		Crypto:    crypto.Suite{KeyAgreement: ka},
	})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256
	r.conn.AsymAlgo = algo.AsymECDSAP256
	r.conn.DHEGroup = algo.DHESECP256R1
	r.conn.AEADSuite = algo.AEADAES128GCM

	_, err := r.KeyExchange(context.Background(), 0, msgs.NoMeasurementSummaryHash)
	require.Error(t, err, "expected error from DHE key generation")
}

func TestKeyExchangeComputeDHEError(t *testing.T) {
	dheSize := 32
	pubKey := make([]byte, dheSize)

	digestSize := algo.HashSHA256.Size()
	sigSize := algo.AsymECDSAP256.SignatureSize()

	mt := &mockTransport{
		responses: [][]byte{
			buildKeyExchangeResponse(0x12, 0xAAAA, pubKey, nil, sigSize, digestSize),
		},
	}

	ka := &mockKeyAgreement{
		pubKey:     pubKey,
		computeErr: fmt.Errorf("compute failed"),
	}

	r := New(Config{
		Transport: mt,
		Crypto:    crypto.Suite{KeyAgreement: ka},
	})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256
	r.conn.AsymAlgo = algo.AsymECDSAP256
	r.conn.DHEGroup = algo.DHESECP256R1
	r.conn.AEADSuite = algo.AEADAES128GCM

	_, err := r.KeyExchange(context.Background(), 0, msgs.NoMeasurementSummaryHash)
	require.Error(t, err, "expected error from DHE compute")
}

func TestKeyExchangeSendReceiveError(t *testing.T) {
	pubKey := make([]byte, 32)
	mt := &mockTransport{
		responses: [][]byte{
			buildErrorResponse(uint8(codes.ErrorBusy), 0),
		},
	}
	ka := &mockKeyAgreement{pubKey: pubKey, sharedSecret: make([]byte, 32)}

	r := New(Config{
		Transport: mt,
		Crypto:    crypto.Suite{KeyAgreement: ka},
	})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256
	r.conn.AsymAlgo = algo.AsymECDSAP256
	r.conn.DHEGroup = algo.DHESECP256R1
	r.conn.AEADSuite = algo.AEADAES128GCM

	_, err := r.KeyExchange(context.Background(), 0, msgs.NoMeasurementSummaryHash)
	require.Error(t, err, "expected error")
}

func TestKeyExchangeFinishError(t *testing.T) {
	dheSize := 32
	pubKey := make([]byte, dheSize)
	sharedSecret := make([]byte, 32)
	digestSize := algo.HashSHA256.Size()
	sigSize := algo.AsymECDSAP256.SignatureSize()

	mt := &mockTransport{
		responses: [][]byte{
			buildKeyExchangeResponse(0x12, 0xDDDD, pubKey, nil, sigSize, digestSize),
			buildErrorResponse(uint8(codes.ErrorUnspecified), 0),
		},
	}

	ka := &mockKeyAgreement{pubKey: pubKey, sharedSecret: sharedSecret}

	r := New(Config{
		Transport: mt,
		Crypto:    crypto.Suite{KeyAgreement: ka},
	})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256
	r.conn.AsymAlgo = algo.AsymECDSAP256
	r.conn.DHEGroup = algo.DHESECP256R1
	r.conn.AEADSuite = algo.AEADAES128GCM

	_, err := r.KeyExchange(context.Background(), 0, msgs.NoMeasurementSummaryHash)
	require.Error(t, err, "expected error from finish step")
}

// --- sendReceive additional error paths ---

// mockFailRequest is a request message whose Marshal always fails.
type mockFailRequest struct {
	msgs.MessageHeader
}

func (m *mockFailRequest) Marshal() ([]byte, error) {
	return nil, errors.New("marshal failed")
}

func (m *mockFailRequest) Unmarshal(data []byte) error {
	return m.MessageHeader.Unmarshal(data)
}

func (m *mockFailRequest) RequestCode() codes.RequestCode {
	return codes.RequestCode(m.RequestResponseCode)
}

func TestSendReceiveMarshalError(t *testing.T) {
	mt := &mockTransport{}
	r := New(Config{Transport: mt})

	_, err := r.sendReceive(context.Background(), &mockFailRequest{})
	require.Error(t, err, "expected marshal error")
	assert.Contains(t, err.Error(), "marshal request")
}

func TestSendReceiveErrorResponseUnmarshalError(t *testing.T) {
	// Response has error response code (byte[1]) but is too short to unmarshal.
	// Header is exactly 4 bytes with error code, but ErrorResponse.Unmarshal
	// delegates to Header.Unmarshal which only needs 4 bytes. To trigger the
	// unmarshal error, we need a response where byte[1] == ResponseError but
	// len(data) < HeaderSize (4). However, sendReceive already checks
	// len(resp) < HeaderSize before checking for error code.
	// So we cannot directly reach the unmarshal error on ErrorResponse in the
	// current code because the header check comes first.
	//
	// Instead, test a valid error response that is exactly header-sized (4 bytes).
	resp := []byte{0x12, uint8(codes.ResponseError), 0x01, 0x00}
	mt := &mockTransport{responses: [][]byte{resp}}
	r := New(Config{Transport: mt})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256

	_, err := r.GetDigests(context.Background())
	require.Error(t, err, "expected error from error response")
	var pe *status.ProtocolError
	require.ErrorAs(t, err, &pe)
}

// --- GetDigests unmarshal error ---

func TestGetDigestsUnmarshalError(t *testing.T) {
	// Build a response with DIGESTS response code but too short for the
	// digest data indicated by the slot mask. Param2 (slot mask) = 0x01
	// means 1 slot, so UnmarshalWithDigestSize expects HeaderSize + 32 bytes,
	// but we only provide HeaderSize bytes.
	resp := []byte{
		0x12, uint8(codes.ResponseDigests), 0x00, 0x01, // header with slot mask = 1
	}
	mt := &mockTransport{responses: [][]byte{resp}}
	r := New(Config{Transport: mt})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256

	_, err := r.GetDigests(context.Background())
	require.Error(t, err, "expected unmarshal error")
	assert.ErrorIs(t, err, msgs.ErrShortBuffer)
}

// --- GetCertificate unmarshal error ---

func TestGetCertificateUnmarshalError(t *testing.T) {
	// Response with CERTIFICATE code but too short for the certificate fields.
	resp := []byte{
		0x12, uint8(codes.ResponseCertificate), 0x00, 0x00,
		// Missing PortionLength and RemainderLength fields (need 4 more bytes).
	}
	mt := &mockTransport{responses: [][]byte{resp}}
	r := newNegotiatedRequester(mt)

	_, err := r.GetCertificate(context.Background(), 0)
	require.Error(t, err, "expected unmarshal error")
	assert.ErrorIs(t, err, msgs.ErrShortBuffer)
}

// --- Challenge unmarshal error ---

func TestChallengeUnmarshalError(t *testing.T) {
	// Response with CHALLENGE_AUTH code but too short for cert chain hash.
	resp := []byte{
		0x12, uint8(codes.ResponseChallengeAuth), 0x00, 0x01,
		// Missing cert_chain_hash (need 32 bytes for SHA256).
	}
	mt := &mockTransport{responses: [][]byte{resp}}
	r := newNegotiatedRequester(mt)

	err := r.Challenge(context.Background(), 0, msgs.NoMeasurementSummaryHash)
	require.Error(t, err, "expected unmarshal error")
	assert.ErrorIs(t, err, msgs.ErrShortBuffer)
}

// --- GetMeasurements unmarshal error ---

func TestGetMeasurementsUnmarshalError(t *testing.T) {
	// Response with MEASUREMENTS code but too short for the measurement fields.
	resp := []byte{
		0x12, uint8(codes.ResponseMeasurements), 0x01, 0x00,
		// Missing NumberOfBlocks and MeasurementRecordLen (need 4 more bytes).
	}
	mt := &mockTransport{responses: [][]byte{resp}}
	r := newNegotiatedRequester(mt)

	_, err := r.GetMeasurements(context.Background(), 1, false)
	require.Error(t, err, "expected unmarshal error")
	assert.ErrorIs(t, err, msgs.ErrShortBuffer)
}

// --- getVersion unmarshal error ---

func TestGetVersionUnmarshalError(t *testing.T) {
	// Response with VERSION code but too short.
	resp := []byte{
		0x10, uint8(codes.ResponseVersion), 0x00, 0x00,
		// Missing VersionNumberEntryCount (need 2 more bytes).
	}
	mt := &mockTransport{responses: [][]byte{resp}}
	r := New(Config{
		Versions:  []algo.Version{algo.Version12},
		Transport: mt,
	})

	_, err := r.InitConnection(context.Background())
	require.Error(t, err, "expected unmarshal error")
}

// --- getCapabilities unmarshal error ---

func TestGetCapabilitiesUnmarshalError(t *testing.T) {
	// First response is a valid VERSION, second is a short CAPABILITIES.
	resp := []byte{
		0x12, uint8(codes.ResponseCapabilities), 0x00, 0x00,
		// Missing Flags etc (need 4+ more bytes).
	}
	mt := &mockTransport{
		responses: [][]byte{
			buildVersionResponse(0x1200),
			resp,
		},
	}
	r := New(Config{
		Versions:  []algo.Version{algo.Version12},
		Transport: mt,
	})

	_, err := r.InitConnection(context.Background())
	require.Error(t, err, "expected unmarshal error")
}

// --- KeyExchange additional short response errors ---

func TestKeyExchangeShortResponseForRandomData(t *testing.T) {
	pubKey := make([]byte, 32)
	sharedSecret := make([]byte, 32)

	// Build a response that has header + session fields (4 bytes) but no random data.
	hdr := []byte{0x12, uint8(codes.ResponseKeyExchangeRsp), 0x00, 0x00}
	sessionFields := []byte{0xBB, 0xBB, 0x00, 0x00} // RspSessionID, MutAuth, ReqSlotID
	resp := append(hdr, sessionFields...)

	mt := &mockTransport{responses: [][]byte{resp}}
	ka := &mockKeyAgreement{pubKey: pubKey, sharedSecret: sharedSecret}
	r := New(Config{
		Transport: mt,
		Crypto:    crypto.Suite{KeyAgreement: ka},
	})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256
	r.conn.AsymAlgo = algo.AsymECDSAP256
	r.conn.DHEGroup = algo.DHESECP256R1
	r.conn.AEADSuite = algo.AEADAES128GCM

	_, err := r.KeyExchange(context.Background(), 0, msgs.NoMeasurementSummaryHash)
	require.Error(t, err, "expected error for short response (random data)")
}

func TestKeyExchangeShortResponseForExchangeData(t *testing.T) {
	pubKey := make([]byte, 32)
	sharedSecret := make([]byte, 32)

	// Header + session fields + random data, but no exchange data.
	hdr := []byte{0x12, uint8(codes.ResponseKeyExchangeRsp), 0x00, 0x00}
	sessionFields := []byte{0xBB, 0xBB, 0x00, 0x00}
	randomData := make([]byte, msgs.RandomDataSize)
	resp := append(hdr, sessionFields...)
	resp = append(resp, randomData...)

	mt := &mockTransport{responses: [][]byte{resp}}
	ka := &mockKeyAgreement{pubKey: pubKey, sharedSecret: sharedSecret}
	r := New(Config{
		Transport: mt,
		Crypto:    crypto.Suite{KeyAgreement: ka},
	})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256
	r.conn.AsymAlgo = algo.AsymECDSAP256
	r.conn.DHEGroup = algo.DHESECP256R1
	r.conn.AEADSuite = algo.AEADAES128GCM

	_, err := r.KeyExchange(context.Background(), 0, msgs.NoMeasurementSummaryHash)
	require.Error(t, err, "expected error for short response (exchange data)")
}

func TestKeyExchangeShortResponseForMeasHash(t *testing.T) {
	pubKey := make([]byte, 32)
	sharedSecret := make([]byte, 32)

	// Header + session fields + random data + exchange data, but no measurement hash.
	hdr := []byte{0x12, uint8(codes.ResponseKeyExchangeRsp), 0x00, 0x00}
	sessionFields := []byte{0xBB, 0xBB, 0x00, 0x00}
	randomData := make([]byte, msgs.RandomDataSize)
	exchangeData := make([]byte, len(pubKey))
	resp := append(hdr, sessionFields...)
	resp = append(resp, randomData...)
	resp = append(resp, exchangeData...)
	// No measurement hash, but we request one with TCBComponentMeasurementHash.

	mt := &mockTransport{responses: [][]byte{resp}}
	ka := &mockKeyAgreement{pubKey: pubKey, sharedSecret: sharedSecret}
	r := New(Config{
		Transport: mt,
		Crypto:    crypto.Suite{KeyAgreement: ka},
	})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256
	r.conn.AsymAlgo = algo.AsymECDSAP256
	r.conn.DHEGroup = algo.DHESECP256R1
	r.conn.AEADSuite = algo.AEADAES128GCM

	_, err := r.KeyExchange(context.Background(), 0, msgs.TCBComponentMeasurementHash)
	require.Error(t, err, "expected error for short response (measurement hash)")
}

func TestKeyExchangeShortResponseForOpaqueLength(t *testing.T) {
	pubKey := make([]byte, 32)
	sharedSecret := make([]byte, 32)

	// Header + session fields + random data + exchange data, but no opaque length.
	hdr := []byte{0x12, uint8(codes.ResponseKeyExchangeRsp), 0x00, 0x00}
	sessionFields := []byte{0xBB, 0xBB, 0x00, 0x00}
	randomData := make([]byte, msgs.RandomDataSize)
	exchangeData := make([]byte, len(pubKey))
	resp := append(hdr, sessionFields...)
	resp = append(resp, randomData...)
	resp = append(resp, exchangeData...)
	// No opaque length field.

	mt := &mockTransport{responses: [][]byte{resp}}
	ka := &mockKeyAgreement{pubKey: pubKey, sharedSecret: sharedSecret}
	r := New(Config{
		Transport: mt,
		Crypto:    crypto.Suite{KeyAgreement: ka},
	})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256
	r.conn.AsymAlgo = algo.AsymECDSAP256
	r.conn.DHEGroup = algo.DHESECP256R1
	r.conn.AEADSuite = algo.AEADAES128GCM

	_, err := r.KeyExchange(context.Background(), 0, msgs.NoMeasurementSummaryHash)
	require.Error(t, err, "expected error for short response (opaque length)")
}

func TestKeyExchangeShortResponseForOpaqueData(t *testing.T) {
	pubKey := make([]byte, 32)
	sharedSecret := make([]byte, 32)

	// Header + session fields + random data + exchange data + opaque length (claims 10 bytes) but no data.
	hdr := []byte{0x12, uint8(codes.ResponseKeyExchangeRsp), 0x00, 0x00}
	sessionFields := []byte{0xBB, 0xBB, 0x00, 0x00}
	randomData := make([]byte, msgs.RandomDataSize)
	exchangeData := make([]byte, len(pubKey))
	opaqueLen := []byte{0x0A, 0x00} // claims 10 bytes of opaque data
	resp := append(hdr, sessionFields...)
	resp = append(resp, randomData...)
	resp = append(resp, exchangeData...)
	resp = append(resp, opaqueLen...)
	// No opaque data follows.

	mt := &mockTransport{responses: [][]byte{resp}}
	ka := &mockKeyAgreement{pubKey: pubKey, sharedSecret: sharedSecret}
	r := New(Config{
		Transport: mt,
		Crypto:    crypto.Suite{KeyAgreement: ka},
	})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256
	r.conn.AsymAlgo = algo.AsymECDSAP256
	r.conn.DHEGroup = algo.DHESECP256R1
	r.conn.AEADSuite = algo.AEADAES128GCM

	_, err := r.KeyExchange(context.Background(), 0, msgs.NoMeasurementSummaryHash)
	require.Error(t, err, "expected error for short response (opaque data)")
}

func TestKeyExchangeShortResponseForSignature(t *testing.T) {
	pubKey := make([]byte, 32)
	sharedSecret := make([]byte, 32)

	// Header + session fields + random data + exchange data + opaque (0 len), but no signature.
	hdr := []byte{0x12, uint8(codes.ResponseKeyExchangeRsp), 0x00, 0x00}
	sessionFields := []byte{0xBB, 0xBB, 0x00, 0x00}
	randomData := make([]byte, msgs.RandomDataSize)
	exchangeData := make([]byte, len(pubKey))
	opaqueLen := []byte{0x00, 0x00}
	resp := append(hdr, sessionFields...)
	resp = append(resp, randomData...)
	resp = append(resp, exchangeData...)
	resp = append(resp, opaqueLen...)
	// No signature follows (needs sigSize = 64 for ECDSA-P256).

	mt := &mockTransport{responses: [][]byte{resp}}
	ka := &mockKeyAgreement{pubKey: pubKey, sharedSecret: sharedSecret}
	r := New(Config{
		Transport: mt,
		Crypto:    crypto.Suite{KeyAgreement: ka},
	})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256
	r.conn.AsymAlgo = algo.AsymECDSAP256
	r.conn.DHEGroup = algo.DHESECP256R1
	r.conn.AEADSuite = algo.AEADAES128GCM

	_, err := r.KeyExchange(context.Background(), 0, msgs.NoMeasurementSummaryHash)
	require.Error(t, err, "expected error for short response (signature)")
}

func TestKeyExchangeFinishUnmarshalError(t *testing.T) {
	dheSize := 32
	pubKey := make([]byte, dheSize)
	sharedSecret := make([]byte, 32)
	digestSize := algo.HashSHA256.Size()
	sigSize := algo.AsymECDSAP256.SignatureSize()

	// Short finish response (too short for header unmarshal).
	finishResp := []byte{0x12, uint8(codes.ResponseFinishRsp)}

	mt := &mockTransport{
		responses: [][]byte{
			buildKeyExchangeResponse(0x12, 0xEEEE, pubKey, nil, sigSize, digestSize),
			finishResp,
		},
	}

	ka := &mockKeyAgreement{pubKey: pubKey, sharedSecret: sharedSecret}
	r := New(Config{
		Transport: mt,
		Crypto:    crypto.Suite{KeyAgreement: ka},
	})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256
	r.conn.AsymAlgo = algo.AsymECDSAP256
	r.conn.DHEGroup = algo.DHESECP256R1
	r.conn.AEADSuite = algo.AEADAES128GCM

	_, err := r.KeyExchange(context.Background(), 0, msgs.NoMeasurementSummaryHash)
	require.Error(t, err, "expected error from short finish response")
}

func TestKeyExchangeNoVerifyData(t *testing.T) {
	// Build a KEY_EXCHANGE_RSP without verify data to cover the
	// keResp.VerifyData == nil branch in session.go.
	dheSize := 32
	pubKey := make([]byte, dheSize)
	sharedSecret := make([]byte, 32)
	sigSize := algo.AsymECDSAP256.SignatureSize()

	// Manually build response without verify data.
	hdr := []byte{0x12, uint8(codes.ResponseKeyExchangeRsp), 0x00, 0x00}
	sessionFields := []byte{0xBB, 0xBB, 0x00, 0x00}
	randomData := make([]byte, msgs.RandomDataSize)
	exchangeData := make([]byte, dheSize)
	opaqueLen := []byte{0x00, 0x00}
	signature := make([]byte, sigSize)
	resp := append(hdr, sessionFields...)
	resp = append(resp, randomData...)
	resp = append(resp, exchangeData...)
	resp = append(resp, opaqueLen...)
	resp = append(resp, signature...)
	// No verify data after signature.

	mt := &mockTransport{
		responses: [][]byte{
			resp,
			buildFinishResponse(0x12),
		},
	}
	ka := &mockKeyAgreement{pubKey: pubKey, sharedSecret: sharedSecret}
	r := New(Config{
		Transport: mt,
		Crypto:    crypto.Suite{KeyAgreement: ka},
	})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256
	r.conn.AsymAlgo = algo.AsymECDSAP256
	r.conn.DHEGroup = algo.DHESECP256R1
	r.conn.AEADSuite = algo.AEADAES128GCM

	sess, err := r.KeyExchange(context.Background(), 0, msgs.NoMeasurementSummaryHash)
	require.NoError(t, err)
	require.NotNil(t, sess, "session is nil")
}

func TestNegotiateAlgorithmsUnmarshalError(t *testing.T) {
	// Response with ALGORITHMS code but too short for algorithm fields.
	resp := []byte{
		0x12, uint8(codes.ResponseAlgorithms), 0x00, 0x00,
		// Too short for AlgorithmsResponse.Unmarshal.
	}
	mt := &mockTransport{
		responses: [][]byte{
			buildVersionResponse(0x1200),
			buildCapabilitiesResponse(0x12, uint32(caps.RspCertCap)),
			resp,
		},
	}
	r := New(Config{
		Versions:     []algo.Version{algo.Version12},
		Transport:    mt,
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	_, err := r.InitConnection(context.Background())
	require.Error(t, err, "expected unmarshal error from algorithms response")
}

func TestGetVersionUnmarshalShortVersionEntries(t *testing.T) {
	// VERSION response header claims 1 entry but data is too short.
	resp := []byte{
		0x10, uint8(codes.ResponseVersion), 0x00, 0x00,
		0x00, 0x01, // reserved=0, count=1, but no version entry data follows
	}
	mt := &mockTransport{responses: [][]byte{resp}}
	r := New(Config{
		Versions:  []algo.Version{algo.Version12},
		Transport: mt,
	})

	_, err := r.InitConnection(context.Background())
	require.Error(t, err, "expected unmarshal error for short version entries")
}

func TestKeyExchangeShortResponseForSessionFields(t *testing.T) {
	pubKey := make([]byte, 32)
	sharedSecret := make([]byte, 32)

	// Return a response that has a valid header but is too short for session fields.
	shortResp := &msgs.KeyExchangeResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseKeyExchangeRsp),
		}},
	}
	data, _ := shortResp.Header.Marshal()

	mt := &mockTransport{
		responses: [][]byte{data},
	}

	ka := &mockKeyAgreement{pubKey: pubKey, sharedSecret: sharedSecret}

	r := New(Config{
		Transport: mt,
		Crypto:    crypto.Suite{KeyAgreement: ka},
	})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256
	r.conn.AsymAlgo = algo.AsymECDSAP256
	r.conn.DHEGroup = algo.DHESECP256R1
	r.conn.AEADSuite = algo.AEADAES128GCM

	_, err := r.KeyExchange(context.Background(), 0, msgs.NoMeasurementSummaryHash)
	require.Error(t, err, "expected error for short response")
}
