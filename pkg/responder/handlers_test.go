package responder

import (
	"context"
	gocrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	spdmcrypto "github.com/xaionaro-go/spdm/pkg/crypto"
	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/caps"
	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
	"github.com/xaionaro-go/spdm/pkg/session"
)

// errorSigner implements crypto.Signer that always returns an error.
type errorSigner struct{}

func (s *errorSigner) Public() gocrypto.PublicKey { return nil }
func (s *errorSigner) Sign(_ io.Reader, _ []byte, _ gocrypto.SignerOpts) ([]byte, error) {
	return nil, fmt.Errorf("sign error")
}

// --- Stub handler tests (encapsulation, respond_if_ready, set_key_pair_info, events) ---

func TestHandleGetEncapsulatedRequest(t *testing.T) {
	r := newTestResponder()
	r.version = algo.Version12

	req := []byte{0x12, uint8(codes.RequestGetEncapsulatedRequest), 0, 0}
	resp, err := r.ProcessMessage(context.Background(), req)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnsupportedRequest, errResp.ErrorCode())
}

func TestHandleDeliverEncapsulatedResponse(t *testing.T) {
	r := newTestResponder()
	r.version = algo.Version12

	req := []byte{0x12, uint8(codes.RequestDeliverEncapsulatedResponse), 0, 0}
	resp, err := r.ProcessMessage(context.Background(), req)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnsupportedRequest, errResp.ErrorCode())
}

func TestHandleRespondIfReady(t *testing.T) {
	r := newTestResponder()
	r.version = algo.Version12

	req := []byte{0x12, uint8(codes.RequestRespondIfReady), 0, 0}
	resp, err := r.ProcessMessage(context.Background(), req)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnsupportedRequest, errResp.ErrorCode())
}

func TestHandleSetKeyPairInfoNilProvider(t *testing.T) {
	r := newTestResponder()
	negotiateResponder(t, r)

	req := &msgs.SetKeyPairInfo{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestSetKeyPairInfo),
		}},
		KeyPairID:       1,
		Operation:       0x01,
		DesiredKeyUsage: 0x0003,
		DesiredAsymAlgo: 0x00000001,
	}
	reqData, _ := req.Marshal()
	resp, _ := r.ProcessMessage(context.Background(), reqData)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnsupportedRequest, errResp.ErrorCode())
}

func TestHandleSetKeyPairInfoNotNegotiated(t *testing.T) {
	r := newTestResponder()
	r.cfg.ProvisioningProvider = &mockProvisioningProvider{}
	r.version = 0x12

	req := &msgs.SetKeyPairInfo{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestSetKeyPairInfo),
		}},
		KeyPairID: 1,
	}
	reqData, _ := req.Marshal()
	resp, _ := r.ProcessMessage(context.Background(), reqData)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnexpectedRequest, errResp.ErrorCode())
}

func TestHandleSetKeyPairInfoSuccess(t *testing.T) {
	r := newTestResponder()
	r.cfg.ProvisioningProvider = &mockProvisioningProvider{}
	negotiateResponder(t, r)

	req := &msgs.SetKeyPairInfo{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestSetKeyPairInfo),
		}},
		KeyPairID:       1,
		Operation:       0x01,
		DesiredKeyUsage: 0x0003,
		DesiredAsymAlgo: 0x00000001,
		PublicKeyInfo:   []byte{0xAA, 0xBB},
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var ack msgs.SetKeyPairInfoAck
	require.NoError(t, ack.Unmarshal(resp))
	assert.Equal(t, uint8(codes.ResponseSetKeyPairInfoAck), ack.Header.RequestResponseCode)
}

func TestHandleSetKeyPairInfoProviderError(t *testing.T) {
	r := newTestResponder()
	r.cfg.ProvisioningProvider = &mockProvisioningProvider{
		setKeyPairErr: fmt.Errorf("key pair update failed"),
	}
	negotiateResponder(t, r)

	req := &msgs.SetKeyPairInfo{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestSetKeyPairInfo),
		}},
		KeyPairID: 1,
		Operation: 0x01,
	}
	reqData, _ := req.Marshal()
	resp, _ := r.ProcessMessage(context.Background(), reqData)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnspecified, errResp.ErrorCode())
}

func TestHandleSetKeyPairInfoUnmarshalError(t *testing.T) {
	r := newTestResponder()
	r.cfg.ProvisioningProvider = &mockProvisioningProvider{}
	negotiateResponder(t, r)

	// Too-short data for SET_KEY_PAIR_INFO (needs HeaderSize+11 bytes).
	resp, _ := r.ProcessMessage(context.Background(), []byte{0x12, uint8(codes.RequestSetKeyPairInfo), 0, 0})

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorInvalidRequest, errResp.ErrorCode())
}

func TestHandleGetSupportedEventTypes(t *testing.T) {
	r := newTestResponder()
	r.version = algo.Version12

	req := []byte{0x12, uint8(codes.RequestGetSupportedEventTypes), 0, 0}
	resp, err := r.ProcessMessage(context.Background(), req)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnsupportedRequest, errResp.ErrorCode())
}

func TestHandleSubscribeEventTypes(t *testing.T) {
	r := newTestResponder()
	r.version = algo.Version12

	req := []byte{0x12, uint8(codes.RequestSubscribeEventTypes), 0, 0}
	resp, err := r.ProcessMessage(context.Background(), req)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnsupportedRequest, errResp.ErrorCode())
}

func TestHandleSendEvent(t *testing.T) {
	r := newTestResponder()
	r.version = algo.Version12

	req := []byte{0x12, uint8(codes.RequestSendEvent), 0, 0}
	resp, err := r.ProcessMessage(context.Background(), req)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnsupportedRequest, errResp.ErrorCode())
}

// --- Session accessor tests ---

func TestGetSessionAndSetActiveSession(t *testing.T) {
	r := newTestResponder()

	// No session exists initially.
	assert.Nil(t, r.GetSession(0x12340001))

	// Add a session.
	sess := session.NewSession(0x12340001, algo.Version12, algo.HashSHA256, algo.AEADAES128GCM, true)
	r.sessions[0x12340001] = sess

	// GetSession should return it.
	assert.Equal(t, sess, r.GetSession(0x12340001))
	assert.Nil(t, r.GetSession(0x99999999))

	// SetActiveSession + ActiveSession.
	r.SetActiveSession(0x12340001)
	assert.Equal(t, sess, r.ActiveSession())
}

// --- baseHashToMeasHash coverage ---

func TestBaseHashToMeasHash(t *testing.T) {
	tests := []struct {
		input algo.BaseHashAlgo
		want  uint32
	}{
		{algo.HashSHA256, uint32(algo.MeasHashSHA256)},
		{algo.HashSHA384, uint32(algo.MeasHashSHA384)},
		{algo.HashSHA512, uint32(algo.MeasHashSHA512)},
		{algo.HashSHA3_256, uint32(algo.MeasHashSHA3_256)},
		{algo.HashSHA3_384, uint32(algo.MeasHashSHA3_384)},
		{algo.HashSHA3_512, uint32(algo.MeasHashSHA3_512)},
		{algo.HashSM3_256, uint32(algo.MeasHashSM3_256)},
		{algo.BaseHashAlgo(0xFF), uint32(algo.MeasHashRawBitStream)}, // unknown -> raw
	}
	for _, tt := range tests {
		got := baseHashToMeasHash(tt.input)
		assert.Equal(t, tt.want, got, "baseHashToMeasHash(%v)", tt.input)
	}
}

// --- KeyUpdate with active session ---

func TestKeyUpdateWithActiveSession(t *testing.T) {
	r := newTestResponder()
	r.version = algo.Version12

	// Create an established session with data keys.
	newHash := func() hash.Hash { return sha256.New() }
	hsSecret, err := session.DeriveHandshakeSecret(context.Background(), newHash, algo.Version12, make([]byte, 32))
	require.NoError(t, err)
	hsKeys, err := session.DeriveHandshakeKeys(context.Background(), newHash, algo.Version12, algo.AEADAES128GCM, hsSecret, make([]byte, 32))
	require.NoError(t, err)
	masterSecret, err := session.DeriveMasterSecret(context.Background(), newHash, algo.Version12, hsSecret)
	require.NoError(t, err)
	dataKeys, err := session.DeriveDataKeys(context.Background(), newHash, algo.Version12, algo.AEADAES128GCM, masterSecret, make([]byte, 32))
	require.NoError(t, err)

	sessID := session.SessionID(0x00010002)
	sess := session.NewSession(sessID, algo.Version12, algo.HashSHA256, algo.AEADAES128GCM, true)
	sess.HandshakeKeys = hsKeys
	sess.HandshakeSecret = hsSecret
	sess.MasterSecret = masterSecret
	sess.DataKeys = dataKeys
	sess.State = session.StateEstablished
	r.sessions[sessID] = sess
	r.SetActiveSession(sessID)
	r.hashAlgo = algo.HashSHA256

	// Test UpdateKey operation.
	req := &msgs.KeyUpdate{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestKeyUpdate),
			Param1:              msgs.KeyUpdateOpUpdateKey,
			Param2:              0x42,
		}},
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var kr msgs.KeyUpdateResponse
	require.NoError(t, kr.Unmarshal(resp))
	assert.Equal(t, uint8(codes.ResponseKeyUpdateAck), kr.Header.RequestResponseCode)
	assert.Equal(t, uint8(msgs.KeyUpdateOpUpdateKey), kr.Header.Param1)
	assert.Equal(t, uint8(0x42), kr.Header.Param2)

	// Test UpdateAllKeys operation.
	req.Header.Param1 = msgs.KeyUpdateOpUpdateAllKeys
	req.Header.Param2 = 0x43
	reqData, _ = req.Marshal()
	resp, err = r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)
	require.NoError(t, kr.Unmarshal(resp))
	assert.Equal(t, uint8(codes.ResponseKeyUpdateAck), kr.Header.RequestResponseCode)
	assert.Equal(t, uint8(msgs.KeyUpdateOpUpdateAllKeys), kr.Header.Param1)
	assert.True(t, sess.PendingResponseKeyUpdate)

	// Test VerifyNewKey operation.
	req.Header.Param1 = msgs.KeyUpdateOpVerifyNewKey
	req.Header.Param2 = 0x44
	reqData, _ = req.Marshal()
	resp, err = r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)
	require.NoError(t, kr.Unmarshal(resp))
	assert.Equal(t, uint8(codes.ResponseKeyUpdateAck), kr.Header.RequestResponseCode)
	assert.Equal(t, uint8(msgs.KeyUpdateOpVerifyNewKey), kr.Header.Param1)
}

// --- Measurements: single index, total count, signed ---

func TestGetMeasurementsTotalCount(t *testing.T) {
	r := newTestResponder()
	r.cfg.MeasProvider = &mockMeasProvider{
		blocks: []msgs.MeasurementBlock{
			{Index: 1, Spec: 0x01, ValueType: 0x01, Value: []byte("fw")},
			{Index: 2, Spec: 0x01, ValueType: 0x02, Value: []byte("cfg")},
		},
	}
	negotiateResponder(t, r)

	req := &msgs.GetMeasurements{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetMeasurements),
			Param2:              msgs.MeasOpTotalCount,
		}},
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var mr msgs.MeasurementsResponse
	require.NoError(t, mr.Unmarshal(resp))
	assert.Equal(t, uint8(2), mr.Header.Param1)  // total count
	assert.Equal(t, uint8(0), mr.NumberOfBlocks) // no blocks in record for TotalCount
}

func TestGetMeasurementsSingleIndex(t *testing.T) {
	blocks := []msgs.MeasurementBlock{
		{Index: 1, Spec: 0x01, ValueType: 0x01, Value: []byte("firmware")},
	}
	r := newTestResponder()
	r.cfg.MeasProvider = &indexMeasProvider{blocks: blocks}
	negotiateResponder(t, r)

	req := &msgs.GetMeasurements{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetMeasurements),
			Param2:              1, // index 1
		}},
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var mr msgs.MeasurementsResponse
	require.NoError(t, mr.Unmarshal(resp))
	assert.Equal(t, uint8(1), mr.NumberOfBlocks)
}

// indexMeasProvider returns all blocks for MeasOpAllMeasurements
// and filters by index for specific indices.
type indexMeasProvider struct {
	blocks []msgs.MeasurementBlock
}

func (m *indexMeasProvider) Collect(_ context.Context, index uint8) ([]msgs.MeasurementBlock, error) {
	if index == msgs.MeasOpAllMeasurements {
		return m.blocks, nil
	}
	for _, b := range m.blocks {
		if b.Index == index {
			return []msgs.MeasurementBlock{b}, nil
		}
	}
	return nil, nil // empty = not found
}

func (m *indexMeasProvider) SummaryHash(_ context.Context, _ uint8) ([]byte, error) {
	return make([]byte, 32), nil
}

func TestGetMeasurementsUnavailableIndex(t *testing.T) {
	r := newTestResponder()
	r.cfg.MeasProvider = &indexMeasProvider{
		blocks: []msgs.MeasurementBlock{
			{Index: 1, Spec: 0x01, ValueType: 0x01, Value: []byte("fw")},
		},
	}
	negotiateResponder(t, r)

	req := &msgs.GetMeasurements{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetMeasurements),
			Param2:              99, // unavailable index
		}},
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorInvalidRequest, errResp.ErrorCode())
}

func TestGetMeasurementsSigned(t *testing.T) {
	r := newTestResponder()
	r.cfg.MeasProvider = &mockMeasProvider{
		blocks: []msgs.MeasurementBlock{
			{Index: 1, Spec: 0x01, ValueType: 0x01, Value: []byte("fw")},
		},
	}
	r.cfg.DeviceSigner = &fakeSigner{}
	negotiateResponder(t, r)

	req := &msgs.GetMeasurements{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetMeasurements),
			Param1:              msgs.MeasAttrGenerateSignature,
			Param2:              msgs.MeasOpAllMeasurements,
		}},
		Nonce:       [32]byte{},
		SlotIDParam: 0,
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var mr msgs.MeasurementsResponse
	require.NoError(t, mr.Unmarshal(resp))
	assert.Equal(t, uint8(codes.ResponseMeasurements), mr.Header.RequestResponseCode)
	assert.Equal(t, uint8(1), mr.NumberOfBlocks)
	// After signed measurement, measTranscript should be reset.
	assert.Nil(t, r.measTranscript)
}

func TestGetMeasurementsCollectErrorForSpecificIndex(t *testing.T) {
	r := newTestResponder()
	r.cfg.MeasProvider = &errorOnIndexMeasProvider{}
	negotiateResponder(t, r)

	req := &msgs.GetMeasurements{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetMeasurements),
			Param2:              3, // specific index
		}},
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnspecified, errResp.ErrorCode())
}

// errorOnIndexMeasProvider returns an error for specific index collection.
type errorOnIndexMeasProvider struct{}

func (m *errorOnIndexMeasProvider) Collect(_ context.Context, index uint8) ([]msgs.MeasurementBlock, error) {
	if index == msgs.MeasOpAllMeasurements {
		return []msgs.MeasurementBlock{
			{Index: 1, Spec: 0x01, ValueType: 0x01, Value: []byte("fw")},
		}, nil
	}
	return nil, fmt.Errorf("collect error")
}

func (m *errorOnIndexMeasProvider) SummaryHash(_ context.Context, _ uint8) ([]byte, error) {
	return make([]byte, 32), nil
}

// --- ChunkGet tests ---

func TestChunkGetSequence(t *testing.T) {
	r := newTestResponder()
	r.version = algo.Version12
	r.cfg.DataTransferSize = 50 // small to force multi-chunk

	// Manually set up a chunkGet state with a large response.
	largeData := make([]byte, 200)
	for i := range largeData {
		largeData[i] = byte(i)
	}
	r.chunkGet = &chunkGetState{
		handle:       0x01,
		largeMessage: largeData,
	}

	// First CHUNK_GET (seq=0).
	req := &msgs.ChunkGet{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestChunkGet),
			Param2:              0x01,
		}},
		ChunkSeqNo: 0,
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var cr msgs.ChunkResponse
	require.NoError(t, cr.Unmarshal(resp))
	assert.Equal(t, uint8(codes.ResponseChunkResponse), cr.Header.RequestResponseCode)
	assert.Equal(t, uint32(len(largeData)), cr.LargeMessageSize)
	assert.True(t, len(cr.Chunk) > 0)
	// First chunk should NOT be the last (data is 200 bytes, transfer size 50).
	assert.Equal(t, uint8(0), cr.Header.Param1&msgs.ChunkResponseAttrLastChunk)

	// Continue reading chunks until done.
	totalRead := len(cr.Chunk)
	seqNo := uint16(1)
	for r.chunkGet != nil {
		req.ChunkSeqNo = seqNo
		reqData, _ = req.Marshal()
		resp, err = r.ProcessMessage(context.Background(), reqData)
		require.NoError(t, err)
		require.NoError(t, cr.Unmarshal(resp))
		totalRead += len(cr.Chunk)
		seqNo++
	}
	assert.Equal(t, len(largeData), totalRead)
}

func TestChunkGetSeqMismatch(t *testing.T) {
	r := newTestResponder()
	r.version = algo.Version12
	r.chunkGet = &chunkGetState{
		handle:        0x01,
		largeMessage:  make([]byte, 100),
		expectedSeqNo: 0,
	}

	// Send seq=5 when expecting seq=0.
	req := &msgs.ChunkGet{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestChunkGet),
			Param2:              0x01,
		}},
		ChunkSeqNo: 5,
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorInvalidRequest, errResp.ErrorCode())
	assert.Nil(t, r.chunkGet)
}

func TestChunkGetUnmarshalError(t *testing.T) {
	r := newTestResponder()
	r.version = algo.Version12
	r.chunkGet = &chunkGetState{
		handle:       0x01,
		largeMessage: make([]byte, 100),
	}

	// Too-short data for CHUNK_GET.
	resp, err := r.ProcessMessage(context.Background(), []byte{0x12, uint8(codes.RequestChunkGet), 0, 0})
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorInvalidRequest, errResp.ErrorCode())
}

// --- ChunkSend: sequence number mismatch ---

func TestChunkSendSeqMismatch(t *testing.T) {
	r := newTestResponder()
	r.version = algo.Version12

	// Start chunked transfer with seq=0.
	req0 := &msgs.ChunkSend{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestChunkSend),
			Param2:              1,
		}},
		ChunkSeqNo:       0,
		LargeMessageSize: 100,
		ChunkSize:        4,
		Chunk:            []byte{1, 2, 3, 4},
	}
	reqData, _ := req0.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var ack msgs.ChunkSendAck
	require.NoError(t, ack.Unmarshal(resp))
	assert.Equal(t, uint8(codes.ResponseChunkSendAck), ack.Header.RequestResponseCode)

	// Send seq=5 (expecting seq=1) -> error.
	req1 := &msgs.ChunkSend{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestChunkSend),
			Param2:              1,
		}},
		ChunkSeqNo: 5,
		ChunkSize:  4,
		Chunk:      []byte{5, 6, 7, 8},
	}
	reqData, _ = req1.Marshal()
	resp, err = r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorInvalidRequest, errResp.ErrorCode())
}

func TestChunkSendUnmarshalError(t *testing.T) {
	r := newTestResponder()
	r.version = algo.Version12

	// Too-short data for CHUNK_SEND.
	resp, err := r.ProcessMessage(context.Background(), []byte{0x12, uint8(codes.RequestChunkSend), 0, 0})
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorInvalidRequest, errResp.ErrorCode())
}

// --- SetCertificate: not negotiated, provider error ---

func TestSetCertificateNotNegotiated(t *testing.T) {
	r := newTestResponder()
	r.cfg.ProvisioningProvider = &mockProvisioningProvider{}
	r.version = algo.Version12

	req := &msgs.SetCertificate{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestSetCertificate),
		}},
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnexpectedRequest, errResp.ErrorCode())
}

func TestSetCertificateProviderError(t *testing.T) {
	r := newTestResponder()
	r.cfg.ProvisioningProvider = &mockProvisioningProvider{
		setCertErr: fmt.Errorf("storage full"),
	}
	negotiateResponder(t, r)

	req := &msgs.SetCertificate{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestSetCertificate),
		}},
		CertChain: []byte("chain"),
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnspecified, errResp.ErrorCode())
}

func TestSetCertificateMinimalHeader(t *testing.T) {
	r := newTestResponder()
	r.cfg.ProvisioningProvider = &mockProvisioningProvider{}
	negotiateResponder(t, r)

	// A 4-byte header is valid for SetCertificate (empty cert chain).
	resp, err := r.ProcessMessage(context.Background(), []byte{0x12, uint8(codes.RequestSetCertificate), 0, 0})
	require.NoError(t, err)

	var scr msgs.SetCertificateResponse
	require.NoError(t, scr.Unmarshal(resp))
	assert.Equal(t, uint8(codes.ResponseSetCertificateRsp), scr.Header.RequestResponseCode)
}

// --- GetKeyPairInfo: not negotiated, provider error ---

func TestGetKeyPairInfoNotNegotiated(t *testing.T) {
	r := newTestResponder()
	r.cfg.ProvisioningProvider = &mockProvisioningProvider{
		keyPairInfo: &msgs.KeyPairInfoResponse{TotalKeyPairs: 1},
	}
	r.version = algo.Version12

	req := &msgs.GetKeyPairInfo{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetKeyPairInfo),
		}},
		KeyPairID: 1,
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnexpectedRequest, errResp.ErrorCode())
}

func TestGetKeyPairInfoProviderError(t *testing.T) {
	r := newTestResponder()
	r.cfg.ProvisioningProvider = &mockProvisioningProvider{
		keyPairErr: fmt.Errorf("not found"),
	}
	negotiateResponder(t, r)

	req := &msgs.GetKeyPairInfo{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetKeyPairInfo),
		}},
		KeyPairID: 99,
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnspecified, errResp.ErrorCode())
}

// --- EndpointInfo: not negotiated, provider error ---

func TestGetEndpointInfoNotNegotiated(t *testing.T) {
	r := newTestResponder()
	r.cfg.EndpointInfoProvider = &mockEndpointInfoProvider{info: []byte("info")}
	r.version = algo.Version12

	req := &msgs.GetEndpointInfo{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetEndpointInfo),
		}},
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnexpectedRequest, errResp.ErrorCode())
}

func TestGetEndpointInfoProviderError(t *testing.T) {
	r := newTestResponder()
	r.cfg.EndpointInfoProvider = &mockEndpointInfoProvider{
		err: fmt.Errorf("endpoint unavailable"),
	}
	negotiateResponder(t, r)

	req := &msgs.GetEndpointInfo{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetEndpointInfo),
		}},
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnspecified, errResp.ErrorCode())
}

func TestGetEndpointInfoUnmarshalError(t *testing.T) {
	r := newTestResponder()
	r.cfg.EndpointInfoProvider = &mockEndpointInfoProvider{info: []byte("info")}
	negotiateResponder(t, r)

	// Too-short data for GET_ENDPOINT_INFO.
	resp, err := r.ProcessMessage(context.Background(), []byte{0x12, uint8(codes.RequestGetEndpointInfo), 0, 0})
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorInvalidRequest, errResp.ErrorCode())
}

// --- MEL: not negotiated, provider error ---

func TestGetMELNotNegotiated(t *testing.T) {
	r := newTestResponder()
	r.cfg.MELProvider = &mockMELProvider{portion: []byte("mel")}
	r.version = algo.Version12

	req := &msgs.GetMeasurementExtensionLog{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetMeasurementExtensionLog),
		}},
		Offset: 0,
		Length: 1024,
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnexpectedRequest, errResp.ErrorCode())
}

func TestGetMELProviderError(t *testing.T) {
	r := newTestResponder()
	r.cfg.MELProvider = &mockMELProvider{
		err: fmt.Errorf("mel error"),
	}
	negotiateResponder(t, r)

	req := &msgs.GetMeasurementExtensionLog{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetMeasurementExtensionLog),
		}},
		Offset: 0,
		Length: 1024,
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnspecified, errResp.ErrorCode())
}

// --- CSR: not negotiated (via version set but not negotiated flag) ---

func TestCSRUnmarshalErrorNewFile(t *testing.T) {
	r := newTestResponder()
	r.cfg.CSRProvider = &mockCSRProvider{csr: []byte("csr")}
	negotiateResponder(t, r)

	// Valid header but too short for GetCSR unmarshal.
	resp, err := r.ProcessMessage(context.Background(), []byte{0x12, uint8(codes.RequestGetCSR), 0, 0})
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorInvalidRequest, errResp.ErrorCode())
}

// --- mockKeyAgreement for key exchange tests ---

type mockDHEKeyPair struct {
	pubKey       []byte
	sharedSecret []byte
}

func (m *mockDHEKeyPair) PublicKey() []byte { return m.pubKey }

func (m *mockDHEKeyPair) ComputeSharedSecret(_ []byte) ([]byte, error) {
	return m.sharedSecret, nil
}

type mockKeyAgreement struct {
	publicKey    []byte
	sharedSecret []byte
}

func (m *mockKeyAgreement) GenerateDHE(_ algo.DHENamedGroup) (spdmcrypto.DHEKeyPair, error) {
	return &mockDHEKeyPair{pubKey: m.publicKey, sharedSecret: m.sharedSecret}, nil
}

// --- KEY_EXCHANGE handler test ---

func TestHandleKeyExchangeNotNegotiated(t *testing.T) {
	r := newTestResponder()
	r.version = algo.Version12

	req := &msgs.KeyExchange{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestKeyExchange),
		}},
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnexpectedRequest, errResp.ErrorCode())
}

func TestHandleKeyExchangeNoDHEGroup(t *testing.T) {
	r := newTestResponder()
	negotiateResponder(t, r)

	// Override dheGroup to 0 (no DHE negotiated).
	r.dheGroup = 0

	req := &msgs.KeyExchange{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestKeyExchange),
		}},
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnspecified, errResp.ErrorCode())
}

func TestHandleKeyExchangeSuccess(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	dhePublicKey := make([]byte, 64) // SECP256R1 public key size
	copy(dhePublicKey, privKey.PublicKey.X.Bytes())
	sharedSecret := make([]byte, 32)

	r := New(Config{
		Versions:         []algo.Version{algo.Version12},
		Caps:             caps.RspCertCap | caps.RspChalCap | caps.RspMeasCapSig,
		BaseAsymAlgo:     algo.AsymECDSAP256,
		BaseHashAlgo:     algo.HashSHA256,
		DHEGroups:        algo.DHESECP256R1,
		AEADSuites:       algo.AEADAES128GCM,
		DataTransferSize: 4096,
		MaxSPDMmsgSize:   65536,
	})

	r.cfg.DeviceSigner = privKey
	r.cfg.Crypto.KeyAgreement = &mockKeyAgreement{
		publicKey:    dhePublicKey,
		sharedSecret: sharedSecret,
	}
	r.cfg.CertProvider = &mockCertProvider{
		chains:  map[uint8][]byte{0: make([]byte, 50)},
		digests: map[uint8][]byte{0: make([]byte, 32)},
	}

	negotiateResponder(t, r)

	// Build KEY_EXCHANGE request.
	opaqueData := buildKeyExchangeOpaqueData()
	keReq := &msgs.KeyExchange{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestKeyExchange),
			Param1:              msgs.NoMeasurementSummaryHash,
			Param2:              0, // slotID
		}},
		ReqSessionID: 0x1234,
		ExchangeData: dhePublicKey,
		OpaqueData:   opaqueData,
	}
	reqData, _ := keReq.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), msgs.HeaderSize)
	assert.Equal(t, uint8(codes.ResponseKeyExchangeRsp), resp[1])

	// After KEY_EXCHANGE, there should be a pending session.
	require.NotNil(t, r.pending)
}

func TestHandleKeyExchangeUnmarshalError(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	r := newTestResponder()
	r.cfg.DeviceSigner = privKey
	r.cfg.Crypto.KeyAgreement = &mockKeyAgreement{
		publicKey:    make([]byte, 64),
		sharedSecret: make([]byte, 32),
	}
	negotiateResponder(t, r)

	// Too-short data for KEY_EXCHANGE (DHE size is 64, min = header+4+32+64+2 = 106).
	resp, err := r.ProcessMessage(context.Background(), []byte{0x12, uint8(codes.RequestKeyExchange), 0, 0})
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorInvalidRequest, errResp.ErrorCode())
}

// --- FINISH handler tests ---

func TestHandleFinishNoPending(t *testing.T) {
	r := newTestResponder()
	r.version = algo.Version12

	req := &msgs.Finish{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestFinish),
		}},
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnexpectedRequest, errResp.ErrorCode())
}

func TestHandleFinishUnmarshalError(t *testing.T) {
	r := newTestResponder()
	r.version = algo.Version12
	r.hashAlgo = algo.HashSHA256
	r.pending = &pendingSession{
		newHash: func() hash.Hash { return sha256.New() },
	}

	// Too-short data for Finish.
	resp, err := r.ProcessMessage(context.Background(), []byte{0x12, uint8(codes.RequestFinish), 0, 0})
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorInvalidRequest, errResp.ErrorCode())
}

func TestHandleKeyExchangeAndFinish(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	dhePublicKey := make([]byte, 64)
	sharedSecret := make([]byte, 32)

	r := New(Config{
		Versions:         []algo.Version{algo.Version12},
		Caps:             caps.RspCertCap | caps.RspChalCap | caps.RspMeasCapSig,
		BaseAsymAlgo:     algo.AsymECDSAP256,
		BaseHashAlgo:     algo.HashSHA256,
		DHEGroups:        algo.DHESECP256R1,
		AEADSuites:       algo.AEADAES128GCM,
		DataTransferSize: 4096,
		MaxSPDMmsgSize:   65536,
	})

	r.cfg.DeviceSigner = privKey
	r.cfg.Crypto.KeyAgreement = &mockKeyAgreement{
		publicKey:    dhePublicKey,
		sharedSecret: sharedSecret,
	}
	r.cfg.CertProvider = &mockCertProvider{
		chains:  map[uint8][]byte{0: make([]byte, 50)},
		digests: map[uint8][]byte{0: make([]byte, 32)},
	}

	ctx := context.Background()
	negotiateResponder(t, r)

	// KEY_EXCHANGE
	opaqueData := buildKeyExchangeOpaqueData()
	keReq := &msgs.KeyExchange{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestKeyExchange),
			Param1:              msgs.NoMeasurementSummaryHash,
			Param2:              0,
		}},
		ReqSessionID: 0x1234,
		ExchangeData: dhePublicKey,
		OpaqueData:   opaqueData,
	}
	reqData, _ := keReq.Marshal()
	resp, err := r.ProcessMessage(ctx, reqData)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), msgs.HeaderSize)
	assert.Equal(t, uint8(codes.ResponseKeyExchangeRsp), resp[1])
	require.NotNil(t, r.pending)

	// FINISH: build verify data using the pending session's keys.
	p := r.pending
	newHash := func() hash.Hash { return sha256.New() }
	hashSize := algo.HashSHA256.Size()

	finishHeader := msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
		SPDMVersion:         0x12,
		RequestResponseCode: uint8(codes.RequestFinish),
	}}
	finishHeaderBytes, _ := finishHeader.Marshal()

	thFinishHasher := newHash()
	thFinishHasher.Write(r.vcaTranscript)
	thFinishHasher.Write(p.certChainHash)
	thFinishHasher.Write(p.keReqBytes)
	thFinishHasher.Write(p.keRspBytes)
	thFinishHasher.Write(finishHeaderBytes)
	thFinishHash := thFinishHasher.Sum(nil)

	verifyData := session.GenerateFinishedKey(ctx, newHash, p.hsKeys.RequestFinished, thFinishHash)

	finishReq := &msgs.Finish{
		Header:     finishHeader,
		VerifyData: make([]byte, hashSize),
	}
	copy(finishReq.VerifyData, verifyData)

	finishData, _ := finishReq.Marshal()
	resp, err = r.ProcessMessage(ctx, finishData)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), msgs.HeaderSize)
	assert.Equal(t, uint8(codes.ResponseFinishRsp), resp[1])
	assert.Nil(t, r.pending, "pending should be nil after FINISH")

	// Session should be established.
	require.Len(t, r.sessions, 1)
}

// --- PSK_FINISH tests ---

func TestHandlePSKFinishUnmarshalError(t *testing.T) {
	r := newTestResponder()
	r.version = algo.Version12
	r.hashAlgo = algo.HashSHA256

	newHash := func() hash.Hash { return sha256.New() }
	hsSecret, _ := session.DeriveHandshakeSecret(context.Background(), newHash, algo.Version12, make([]byte, 32))
	hsKeys, _ := session.DeriveHandshakeKeys(context.Background(), newHash, algo.Version12, algo.AEADAES128GCM, hsSecret, make([]byte, 32))

	r.pendingPSK = &pendingPSKSession{
		sessionID:   0x00010002,
		newHash:     newHash,
		hsKeys:      hsKeys,
		hsSecret:    hsSecret,
		pskReqBytes: make([]byte, 10),
		pskRspBytes: make([]byte, 10),
		sess:        session.NewSession(0x00010002, algo.Version12, algo.HashSHA256, algo.AEADAES128GCM, true),
	}

	// Too-short data for PSK_FINISH (needs header+hashSize = 4+32 = 36 bytes).
	resp, err := r.ProcessMessage(context.Background(), []byte{0x12, uint8(codes.RequestPSKFinish), 0, 0})
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorInvalidRequest, errResp.ErrorCode())
}

func TestHandlePSKExchangeAndFinish(t *testing.T) {
	r := newTestResponder()
	r.cfg.PSKProvider = &mockPSKProvider{psk: make([]byte, 32)}
	ctx := context.Background()
	negotiateResponder(t, r)

	// PSK_EXCHANGE
	pskReq := &msgs.PSKExchange{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestPSKExchange),
			Param1:              msgs.NoMeasurementSummaryHash,
		}},
		ReqSessionID: 0x1234,
		PSKHint:      []byte("test"),
		Context:      make([]byte, 32),
		OpaqueData:   buildKeyExchangeOpaqueData(),
	}
	reqData, _ := pskReq.Marshal()
	resp, err := r.ProcessMessage(ctx, reqData)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), msgs.HeaderSize)
	assert.Equal(t, uint8(codes.ResponsePSKExchangeRsp), resp[1])
	require.NotNil(t, r.pendingPSK)

	// PSK_FINISH: build correct verify data.
	p := r.pendingPSK
	newHash := func() hash.Hash { return sha256.New() }
	hashSize := r.hashAlgo.Size()

	finishHeader := msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
		SPDMVersion:         0x12,
		RequestResponseCode: uint8(codes.RequestPSKFinish),
	}}
	finishHeaderBytes, _ := finishHeader.Marshal()

	thFinishHasher := newHash()
	thFinishHasher.Write(r.vcaTranscript)
	thFinishHasher.Write(p.pskReqBytes)
	thFinishHasher.Write(p.pskRspBytes)
	thFinishHasher.Write(finishHeaderBytes)
	thFinishHash := thFinishHasher.Sum(nil)

	verifyData := session.GenerateFinishedKey(ctx, newHash, p.hsKeys.RequestFinished, thFinishHash)

	// Build the full FINISH request: header + verify_data.
	var finishBuf []byte
	finishBuf = append(finishBuf, finishHeaderBytes...)
	finishBuf = append(finishBuf, verifyData...)
	_ = hashSize // used implicitly via verifyData length

	resp, err = r.ProcessMessage(ctx, finishBuf)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), msgs.HeaderSize)
	assert.Equal(t, uint8(codes.ResponsePSKFinishRsp), resp[1])
	assert.Nil(t, r.pendingPSK, "pendingPSK should be nil after PSK_FINISH")

	// Session should be established.
	require.Len(t, r.sessions, 1)
}

func TestHandlePSKFinishVerifyMismatch(t *testing.T) {
	r := newTestResponder()
	r.cfg.PSKProvider = &mockPSKProvider{psk: make([]byte, 32)}
	ctx := context.Background()
	negotiateResponder(t, r)

	// PSK_EXCHANGE
	pskReq := &msgs.PSKExchange{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestPSKExchange),
			Param1:              msgs.NoMeasurementSummaryHash,
		}},
		ReqSessionID: 0x5678,
		PSKHint:      []byte("test"),
		Context:      make([]byte, 32),
		OpaqueData:   buildKeyExchangeOpaqueData(),
	}
	reqData, _ := pskReq.Marshal()
	resp, err := r.ProcessMessage(ctx, reqData)
	require.NoError(t, err)
	assert.Equal(t, uint8(codes.ResponsePSKExchangeRsp), resp[1])
	require.NotNil(t, r.pendingPSK)

	// PSK_FINISH with wrong verify data.
	hashSize := r.hashAlgo.Size()
	finishHeader := msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
		SPDMVersion:         0x12,
		RequestResponseCode: uint8(codes.RequestPSKFinish),
	}}
	finishHeaderBytes, _ := finishHeader.Marshal()

	var finishBuf []byte
	finishBuf = append(finishBuf, finishHeaderBytes...)
	finishBuf = append(finishBuf, make([]byte, hashSize)...) // wrong verify data (all zeros)

	resp, err = r.ProcessMessage(ctx, finishBuf)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorDecryptError, errResp.ErrorCode())
}

// --- Algorithm negotiation: additional AlgStruct types ---

func TestNegotiateAlgorithmsReqBaseAsym(t *testing.T) {
	r := newTestResponder()
	ctx := context.Background()
	_, err := r.ProcessMessage(ctx, buildGetVersion())
	require.NoError(t, err)
	_, err = r.ProcessMessage(ctx, buildGetCapabilities())
	require.NoError(t, err)

	req := &msgs.NegotiateAlgorithms{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestNegotiateAlgorithms),
			Param1:              3,
		}},
		BaseAsymAlgo:             uint32(algo.AsymECDSAP256),
		BaseHashAlgo:             uint32(algo.HashSHA256),
		MeasurementSpecification: 0x01,
		AlgStructs: []msgs.AlgStructTable{
			{AlgType: msgs.AlgTypeDHE, AlgCount: 0x20, AlgSupported: uint16(algo.DHESECP256R1)},
			{AlgType: msgs.AlgTypeAEAD, AlgCount: 0x20, AlgSupported: uint16(algo.AEADAES128GCM)},
			{AlgType: msgs.AlgTypeReqBaseAsym, AlgCount: 0x20, AlgSupported: uint16(algo.AsymECDSAP256)},
		},
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(ctx, reqData)
	require.NoError(t, err)

	var ar msgs.AlgorithmsResponse
	require.NoError(t, ar.Unmarshal(resp))
	require.Equal(t, 3, len(ar.AlgStructs))

	// REQ_BASE_ASYM should have a selection.
	assert.Equal(t, uint8(msgs.AlgTypeReqBaseAsym), ar.AlgStructs[2].AlgType)
	assert.NotZero(t, ar.AlgStructs[2].AlgSupported)
}

func TestNegotiateAlgorithmsKeySchedule(t *testing.T) {
	r := newTestResponder()
	ctx := context.Background()
	_, err := r.ProcessMessage(ctx, buildGetVersion())
	require.NoError(t, err)
	_, err = r.ProcessMessage(ctx, buildGetCapabilities())
	require.NoError(t, err)

	req := &msgs.NegotiateAlgorithms{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestNegotiateAlgorithms),
			Param1:              3,
		}},
		BaseAsymAlgo:             uint32(algo.AsymECDSAP256),
		BaseHashAlgo:             uint32(algo.HashSHA256),
		MeasurementSpecification: 0x01,
		AlgStructs: []msgs.AlgStructTable{
			{AlgType: msgs.AlgTypeDHE, AlgCount: 0x20, AlgSupported: uint16(algo.DHESECP256R1)},
			{AlgType: msgs.AlgTypeAEAD, AlgCount: 0x20, AlgSupported: uint16(algo.AEADAES128GCM)},
			{AlgType: msgs.AlgTypeKeySchedule, AlgCount: 0x20, AlgSupported: uint16(algo.KeyScheduleSPDM)},
		},
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(ctx, reqData)
	require.NoError(t, err)

	var ar msgs.AlgorithmsResponse
	require.NoError(t, ar.Unmarshal(resp))
	require.Equal(t, 3, len(ar.AlgStructs))

	// KeySchedule should have SPDM key schedule selected.
	assert.Equal(t, uint8(msgs.AlgTypeKeySchedule), ar.AlgStructs[2].AlgType)
	assert.Equal(t, uint16(algo.KeyScheduleSPDM), ar.AlgStructs[2].AlgSupported)
}

// --- OtherParamsSupport / MeasurementSpecification in algorithms ---

func TestNegotiateAlgorithmsOpaqueDataFormat(t *testing.T) {
	r := newTestResponder()
	ctx := context.Background()
	_, err := r.ProcessMessage(ctx, buildGetVersion())
	require.NoError(t, err)
	_, err = r.ProcessMessage(ctx, buildGetCapabilities())
	require.NoError(t, err)

	req := &msgs.NegotiateAlgorithms{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestNegotiateAlgorithms),
			Param1:              2,
		}},
		BaseAsymAlgo:             uint32(algo.AsymECDSAP256),
		BaseHashAlgo:             uint32(algo.HashSHA256),
		MeasurementSpecification: 0x01,
		OtherParamsSupport:       0x02, // OpaqueDataFmt1
		AlgStructs: []msgs.AlgStructTable{
			{AlgType: msgs.AlgTypeDHE, AlgCount: 0x20, AlgSupported: uint16(algo.DHESECP256R1)},
			{AlgType: msgs.AlgTypeAEAD, AlgCount: 0x20, AlgSupported: uint16(algo.AEADAES128GCM)},
		},
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(ctx, reqData)
	require.NoError(t, err)

	var ar msgs.AlgorithmsResponse
	require.NoError(t, ar.Unmarshal(resp))
	assert.Equal(t, uint8(0x02), ar.OtherParamsSelection)
}

// --- Negotiate without MeasCap ---

func TestNegotiateAlgorithmsNoMeasCap(t *testing.T) {
	r := New(Config{
		Versions:         []algo.Version{algo.Version12},
		Caps:             caps.RspCertCap, // no MeasCap
		BaseAsymAlgo:     algo.AsymECDSAP256,
		BaseHashAlgo:     algo.HashSHA256,
		DHEGroups:        algo.DHESECP256R1,
		AEADSuites:       algo.AEADAES128GCM,
		DataTransferSize: 4096,
		MaxSPDMmsgSize:   65536,
	})
	ctx := context.Background()
	_, err := r.ProcessMessage(ctx, buildGetVersion())
	require.NoError(t, err)
	_, err = r.ProcessMessage(ctx, buildGetCapabilities())
	require.NoError(t, err)
	resp, err := r.ProcessMessage(ctx, buildNegotiateAlgorithms())
	require.NoError(t, err)

	var ar msgs.AlgorithmsResponse
	require.NoError(t, ar.Unmarshal(resp))
	assert.Equal(t, uint32(0), ar.MeasurementHashAlgo) // no meas cap -> 0
}

// --- ChunkSend: large response triggers CHUNK_GET state ---

func TestChunkSendLargeResponse(t *testing.T) {
	r := newTestResponder()
	r.version = algo.Version12
	// Set very small DataTransferSize to force large response.
	r.cfg.DataTransferSize = 20
	ctx := context.Background()

	// Build a valid GET_VERSION as the "large message" to reassemble.
	getVer := &msgs.GetVersion{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x10,
			RequestResponseCode: uint8(codes.RequestGetVersion),
		}},
	}
	getVerData, _ := getVer.Marshal()

	// Send as single chunk.
	req := &msgs.ChunkSend{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestChunkSend),
			Param1:              msgs.ChunkSendAttrLastChunk,
			Param2:              1,
		}},
		ChunkSeqNo:       0,
		LargeMessageSize: uint32(len(getVerData)),
		ChunkSize:        uint32(len(getVerData)),
		Chunk:            getVerData,
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(ctx, reqData)
	require.NoError(t, err)

	var ack msgs.ChunkSendAck
	require.NoError(t, ack.Unmarshal(resp))
	assert.Equal(t, uint8(codes.ResponseChunkSendAck), ack.Header.RequestResponseCode)

	// Either chunkGet was set (for large response) or response was embedded.
	// With DataTransferSize=20 and version response > 20 bytes, chunkGet should be set.
	if r.chunkGet != nil {
		assert.True(t, len(ack.Response) >= msgs.HeaderSize)
		// The embedded response should be ErrorLargeResponse.
		assert.Equal(t, uint8(codes.ResponseError), ack.Response[1])
	}
}

// --- Multi-chunk ChunkSend ---

func TestChunkSendMultiChunk(t *testing.T) {
	r := newTestResponder()
	r.version = algo.Version12
	ctx := context.Background()

	// Build a valid GET_VERSION as the "large message".
	getVer := &msgs.GetVersion{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x10,
			RequestResponseCode: uint8(codes.RequestGetVersion),
		}},
	}
	getVerData, _ := getVer.Marshal()

	// Split into two chunks.
	half := len(getVerData) / 2
	chunk1 := getVerData[:half]
	chunk2 := getVerData[half:]

	// First chunk (not last).
	req0 := &msgs.ChunkSend{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestChunkSend),
			Param1:              0, // not last
			Param2:              1,
		}},
		ChunkSeqNo:       0,
		LargeMessageSize: uint32(len(getVerData)),
		ChunkSize:        uint32(len(chunk1)),
		Chunk:            chunk1,
	}
	reqData, _ := req0.Marshal()
	resp, err := r.ProcessMessage(ctx, reqData)
	require.NoError(t, err)

	var ack msgs.ChunkSendAck
	require.NoError(t, ack.Unmarshal(resp))
	assert.Equal(t, uint16(0), ack.ChunkSeqNo)

	// Second chunk (last).
	req1 := &msgs.ChunkSend{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestChunkSend),
			Param1:              msgs.ChunkSendAttrLastChunk,
			Param2:              1,
		}},
		ChunkSeqNo: 1,
		ChunkSize:  uint32(len(chunk2)),
		Chunk:      chunk2,
	}
	reqData, _ = req1.Marshal()
	resp, err = r.ProcessMessage(ctx, reqData)
	require.NoError(t, err)

	require.NoError(t, ack.Unmarshal(resp))
	assert.Equal(t, uint8(codes.ResponseChunkSendAck), ack.Header.RequestResponseCode)
	// The response embedded in ACK should be valid.
	require.True(t, len(ack.Response) >= msgs.HeaderSize)
}

// --- ECDSA signature conversion ---

func TestToSPDMSignatureRSA(t *testing.T) {
	// RSA signatures pass through unchanged.
	sig := make([]byte, 256)
	for i := range sig {
		sig[i] = byte(i)
	}
	result, err := toSPDMSignature(algo.AsymRSASSA2048, sig)
	require.NoError(t, err)
	assert.Equal(t, sig, result)
}

func TestEcdsaDERToRawAlreadyRaw(t *testing.T) {
	// If the signature is already in raw format (not DER), it should be returned as-is.
	raw := make([]byte, 64)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	result, err := ecdsaDERToRaw(raw, 64)
	require.NoError(t, err)
	assert.Equal(t, raw, result)
}

func TestEcdsaRawSignature(t *testing.T) {
	r := new(big.Int).SetBytes([]byte{0x01, 0x02, 0x03})
	s := new(big.Int).SetBytes([]byte{0x04, 0x05, 0x06})
	result := ecdsaRawSignature(r, s, 64)
	assert.Equal(t, 64, len(result))
	// r should be right-aligned in first 32 bytes.
	assert.Equal(t, byte(0x01), result[29])
	assert.Equal(t, byte(0x02), result[30])
	assert.Equal(t, byte(0x03), result[31])
	// s should be right-aligned in last 32 bytes.
	assert.Equal(t, byte(0x04), result[61])
	assert.Equal(t, byte(0x05), result[62])
	assert.Equal(t, byte(0x06), result[63])
}

// --- Measurements with signature sign error ---

func TestGetMeasurementsSignError(t *testing.T) {
	r := newTestResponder()
	r.cfg.MeasProvider = &mockMeasProvider{
		blocks: []msgs.MeasurementBlock{
			{Index: 1, Spec: 0x01, ValueType: 0x01, Value: []byte("fw")},
		},
	}
	r.cfg.DeviceSigner = &errorSigner{}
	negotiateResponder(t, r)

	req := &msgs.GetMeasurements{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetMeasurements),
			Param1:              msgs.MeasAttrGenerateSignature,
			Param2:              msgs.MeasOpAllMeasurements,
		}},
		Nonce:       [32]byte{},
		SlotIDParam: 0,
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnspecified, errResp.ErrorCode())
}

// --- Challenge with measurement summary hash from provider ---

func TestChallengeWithMeasSummaryHash(t *testing.T) {
	measHash := make([]byte, 32)
	for i := range measHash {
		measHash[i] = 0xCC
	}
	r := newTestResponder()
	r.cfg.CertProvider = &mockCertProvider{
		digests: map[uint8][]byte{0: make([]byte, 32)},
	}
	r.cfg.MeasProvider = &mockMeasProvider{
		blocks: []msgs.MeasurementBlock{
			{Index: 1, Spec: 0x01, ValueType: 0x01, Value: []byte("fw")},
		},
	}
	negotiateResponder(t, r)

	req := &msgs.Challenge{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestChallenge),
			Param1:              0,
			Param2:              0xFF, // AllMeasurementsHash
		}},
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)
	assert.Equal(t, uint8(codes.ResponseChallengeAuth), resp[1])
}

func TestChallengeWithMeasSummaryHashError(t *testing.T) {
	r := newTestResponder()
	r.cfg.CertProvider = &mockCertProvider{
		digests: map[uint8][]byte{0: make([]byte, 32)},
	}
	r.cfg.MeasProvider = &errorMeasProvider{}
	negotiateResponder(t, r)

	req := &msgs.Challenge{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestChallenge),
			Param1:              0,
			Param2:              0xFF, // AllMeasurementsHash
		}},
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnspecified, errResp.ErrorCode())
}

// --- Challenge without MeasProvider but with hash type ---

func TestChallengeNoMeasProviderWithHashType(t *testing.T) {
	r := newTestResponder()
	r.cfg.CertProvider = &mockCertProvider{
		digests: map[uint8][]byte{0: make([]byte, 32)},
	}
	// No MeasProvider set.
	negotiateResponder(t, r)

	req := &msgs.Challenge{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestChallenge),
			Param1:              0,
			Param2:              0xFF, // AllMeasurementsHash
		}},
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)
	// Should still succeed with zero measurement hash.
	assert.Equal(t, uint8(codes.ResponseChallengeAuth), resp[1])
}

// --- Challenge sign error ---

func TestChallengeSignError(t *testing.T) {
	r := newTestResponder()
	r.cfg.CertProvider = &mockCertProvider{
		digests: map[uint8][]byte{0: make([]byte, 32)},
	}
	r.cfg.DeviceSigner = &errorSigner{}
	negotiateResponder(t, r)

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

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnspecified, errResp.ErrorCode())
}

// --- getBuffer on nil ---

func TestGetBufferNil(t *testing.T) {
	var s *chunkSendState
	assert.Nil(t, s.getBuffer())
}

func TestGetBufferNonNil(t *testing.T) {
	s := &chunkSendState{buffer: []byte{1, 2, 3}}
	assert.Equal(t, []byte{1, 2, 3}, s.getBuffer())
}
