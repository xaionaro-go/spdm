package unit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

func hdr(ver uint8, code uint8) msgs.MessageHeader {
	return msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: ver, RequestResponseCode: code}}
}

// --- Chunk messages ---

func TestWire_ChunkSend_SeqZero(t *testing.T) {
	orig := &msgs.ChunkSend{
		Header:           hdr(0x12, uint8(codes.RequestChunkSend)),
		ChunkSeqNo:       0,
		LargeMessageSize: 8192,
		Chunk:            []byte{0x01, 0x02, 0x03},
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.ChunkSend
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, uint16(0), got.ChunkSeqNo)
	assert.Equal(t, uint32(8192), got.LargeMessageSize)
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, got.Chunk)
	assert.Equal(t, codes.RequestChunkSend, orig.RequestCode())
	assert.False(t, orig.IsLastChunk())
}

func TestWire_ChunkSend_SeqNonZero(t *testing.T) {
	orig := &msgs.ChunkSend{
		Header:     hdr(0x12, uint8(codes.RequestChunkSend)|msgs.ChunkSendAttrLastChunk),
		ChunkSeqNo: 5,
		Chunk:      []byte{0xAA, 0xBB},
	}
	orig.Header.Param1 = msgs.ChunkSendAttrLastChunk
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.ChunkSend
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, uint16(5), got.ChunkSeqNo)
	assert.True(t, got.IsLastChunk())
	assert.Equal(t, []byte{0xAA, 0xBB}, got.Chunk)
}

func TestWire_ChunkSend_ShortBuffer(t *testing.T) {
	var m msgs.ChunkSend
	assert.ErrorIs(t, m.Unmarshal([]byte{0, 0, 0}), msgs.ErrShortBuffer)
}

func TestWire_ChunkSendAck(t *testing.T) {
	orig := &msgs.ChunkSendAck{
		Header:     hdr(0x12, uint8(codes.ResponseChunkSendAck)),
		ChunkSeqNo: 3,
		Response:   []byte{0x01, 0x02},
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.ChunkSendAck
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, uint16(3), got.ChunkSeqNo)
	assert.Equal(t, []byte{0x01, 0x02}, got.Response)
	assert.Equal(t, codes.ResponseChunkSendAck, orig.ResponseCode())
}

func TestWire_ChunkSendAck_NoResponse(t *testing.T) {
	orig := &msgs.ChunkSendAck{Header: hdr(0x12, 0x05), ChunkSeqNo: 1}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.ChunkSendAck
	require.NoError(t, got.Unmarshal(data))
	assert.Nil(t, got.Response)
}

func TestWire_ChunkGet(t *testing.T) {
	orig := &msgs.ChunkGet{Header: hdr(0x12, uint8(codes.RequestChunkGet)), ChunkSeqNo: 7}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.ChunkGet
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, uint16(7), got.ChunkSeqNo)
	assert.Equal(t, codes.RequestChunkGet, orig.RequestCode())
}

func TestWire_ChunkResponse_SeqZero(t *testing.T) {
	orig := &msgs.ChunkResponse{
		Header:           hdr(0x12, uint8(codes.ResponseChunkResponse)),
		ChunkSeqNo:       0,
		LargeMessageSize: 4096,
		Chunk:            []byte{0xDE, 0xAD},
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.ChunkResponse
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, uint32(4096), got.LargeMessageSize)
	assert.Equal(t, []byte{0xDE, 0xAD}, got.Chunk)
	assert.Equal(t, codes.ResponseChunkResponse, orig.ResponseCode())
}

func TestWire_ChunkResponse_LastChunk(t *testing.T) {
	orig := &msgs.ChunkResponse{
		Header:     msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x06, Param1: msgs.ChunkResponseAttrLastChunk}},
		ChunkSeqNo: 10,
		Chunk:      []byte{0xFF},
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.ChunkResponse
	require.NoError(t, got.Unmarshal(data))
	assert.True(t, got.IsLastChunk())
}

// --- CSR messages ---

func TestWire_GetCSR(t *testing.T) {
	orig := &msgs.GetCSR{
		Header:        hdr(0x12, uint8(codes.RequestGetCSR)),
		RequesterInfo: []byte("req-info"),
		OpaqueData:    []byte("opaque"),
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.GetCSR
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, []byte("req-info"), got.RequesterInfo)
	assert.Equal(t, []byte("opaque"), got.OpaqueData)
	assert.Equal(t, codes.RequestGetCSR, orig.RequestCode())
}

func TestWire_CSRResponse(t *testing.T) {
	orig := &msgs.CSRResponse{
		Header: hdr(0x12, uint8(codes.ResponseCSR)),
		CSR:    []byte{0x30, 0x82, 0x01, 0x22},
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.CSRResponse
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, []byte{0x30, 0x82, 0x01, 0x22}, got.CSR)
	assert.Equal(t, codes.ResponseCSR, orig.ResponseCode())
}

func TestWire_SetCertificate(t *testing.T) {
	orig := &msgs.SetCertificate{
		Header:    msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestSetCertificate), Param1: 0x03}},
		CertChain: []byte{0x01, 0x02, 0x03},
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.SetCertificate
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, uint8(0x03), got.SlotID())
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, got.CertChain)
	assert.Equal(t, codes.RequestSetCertificate, orig.RequestCode())
}

func TestWire_SetCertificateResponse(t *testing.T) {
	orig := &msgs.SetCertificateResponse{Header: hdr(0x12, uint8(codes.ResponseSetCertificateRsp))}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.SetCertificateResponse
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, codes.ResponseSetCertificateRsp, orig.ResponseCode())
}

// --- PSK messages ---

func TestWire_PSKExchange(t *testing.T) {
	orig := &msgs.PSKExchange{
		Header:       hdr(0x12, uint8(codes.RequestPSKExchange)),
		ReqSessionID: 0x1234,
		PSKHint:      []byte("hint"),
		Context:      []byte("ctx"),
		OpaqueData:   []byte("opq"),
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.PSKExchange
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, uint16(0x1234), got.ReqSessionID)
	assert.Equal(t, []byte("hint"), got.PSKHint)
	assert.Equal(t, []byte("ctx"), got.Context)
	assert.Equal(t, []byte("opq"), got.OpaqueData)
	assert.Equal(t, codes.RequestPSKExchange, orig.RequestCode())
}

func TestWire_PSKExchangeResponse(t *testing.T) {
	orig := &msgs.PSKExchangeResponse{
		Header:       hdr(0x12, uint8(codes.ResponsePSKExchangeRsp)),
		RspSessionID: 0x5678,
		Context:      []byte("rsp-ctx"),
		OpaqueData:   []byte("rsp-opq"),
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.PSKExchangeResponse
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, uint16(0x5678), got.RspSessionID)
	assert.Equal(t, codes.ResponsePSKExchangeRsp, orig.ResponseCode())
}

func TestWire_PSKFinish(t *testing.T) {
	orig := &msgs.PSKFinish{
		Header:     hdr(0x12, uint8(codes.RequestPSKFinish)),
		VerifyData: []byte{0xAA, 0xBB, 0xCC},
	}
	data, err := orig.Marshal()
	require.NoError(t, err)
	assert.Equal(t, codes.RequestPSKFinish, orig.RequestCode())
	assert.True(t, len(data) > msgs.HeaderSize)
}

func TestWire_PSKFinishResponse(t *testing.T) {
	orig := &msgs.PSKFinishResponse{Header: hdr(0x12, uint8(codes.ResponsePSKFinishRsp))}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.PSKFinishResponse
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, codes.ResponsePSKFinishRsp, orig.ResponseCode())
	assert.Equal(t, msgs.HeaderSize, len(data))
}

// --- Session messages ---

func TestWire_Heartbeat(t *testing.T) {
	orig := &msgs.Heartbeat{Header: hdr(0x12, uint8(codes.RequestHeartbeat))}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.Heartbeat
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, codes.RequestHeartbeat, orig.RequestCode())
}

func TestWire_HeartbeatResponse(t *testing.T) {
	orig := &msgs.HeartbeatResponse{Header: hdr(0x12, uint8(codes.ResponseHeartbeatAck))}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.HeartbeatResponse
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, codes.ResponseHeartbeatAck, orig.ResponseCode())
}

func TestWire_KeyUpdate(t *testing.T) {
	orig := &msgs.KeyUpdate{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestKeyUpdate),
			Param1: msgs.KeyUpdateOpUpdateKey, Param2: 0x42}},
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.KeyUpdate
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, uint8(msgs.KeyUpdateOpUpdateKey), got.Header.Param1)
	assert.Equal(t, uint8(0x42), got.Header.Param2)
	assert.Equal(t, codes.RequestKeyUpdate, orig.RequestCode())

	// Verify constants.
	assert.Equal(t, uint8(1), uint8(msgs.KeyUpdateOpUpdateKey))
	assert.Equal(t, uint8(2), uint8(msgs.KeyUpdateOpUpdateAllKeys))
	assert.Equal(t, uint8(3), uint8(msgs.KeyUpdateOpVerifyNewKey))
}

func TestWire_KeyUpdateResponse(t *testing.T) {
	orig := &msgs.KeyUpdateResponse{Header: hdr(0x12, uint8(codes.ResponseKeyUpdateAck))}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.KeyUpdateResponse
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, codes.ResponseKeyUpdateAck, orig.ResponseCode())
}

func TestWire_EndSession(t *testing.T) {
	orig := &msgs.EndSession{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestEndSession),
			Param1: msgs.EndSessionPreserveNegotiatedStateClear}},
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.EndSession
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, uint8(msgs.EndSessionPreserveNegotiatedStateClear), got.Header.Param1)
	assert.Equal(t, codes.RequestEndSession, orig.RequestCode())
}

func TestWire_EndSessionResponse(t *testing.T) {
	orig := &msgs.EndSessionResponse{Header: hdr(0x12, uint8(codes.ResponseEndSessionAck))}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.EndSessionResponse
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, codes.ResponseEndSessionAck, orig.ResponseCode())
}

// --- Vendor messages ---

func TestWire_VendorDefinedRequest(t *testing.T) {
	orig := &msgs.VendorDefinedRequest{
		Header:     hdr(0x12, uint8(codes.RequestVendorDefined)),
		StandardID: 0x0001,
		VendorID:   []byte{0x42, 0x43},
		Payload:    []byte("test-payload"),
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.VendorDefinedRequest
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, uint16(0x0001), got.StandardID)
	assert.Equal(t, []byte{0x42, 0x43}, got.VendorID)
	assert.Equal(t, []byte("test-payload"), got.Payload)
	assert.Equal(t, codes.RequestVendorDefined, orig.RequestCode())
}

func TestWire_VendorDefinedResponse(t *testing.T) {
	orig := &msgs.VendorDefinedResponse{
		Header:     hdr(0x12, uint8(codes.ResponseVendorDefined)),
		StandardID: 0x0002,
		VendorID:   []byte{0x01},
		Payload:    []byte("resp"),
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.VendorDefinedResponse
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, uint16(0x0002), got.StandardID)
	assert.Equal(t, []byte{0x01}, got.VendorID)
	assert.Equal(t, []byte("resp"), got.Payload)
	assert.Equal(t, codes.ResponseVendorDefined, orig.ResponseCode())
}

func TestWire_VendorDefined_ShortBuffer(t *testing.T) {
	var req msgs.VendorDefinedRequest
	assert.ErrorIs(t, req.Unmarshal([]byte{0, 0, 0, 0, 0}), msgs.ErrShortBuffer)
	var resp msgs.VendorDefinedResponse
	assert.ErrorIs(t, resp.Unmarshal([]byte{0, 0, 0, 0, 0}), msgs.ErrShortBuffer)
}

// --- Error messages ---

func TestWire_ErrorResponse(t *testing.T) {
	orig := &msgs.ErrorResponse{
		Header:       msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.ResponseError), Param1: uint8(codes.ErrorDecryptError), Param2: 0x42}},
		ExtErrorData: []byte{0x01, 0x02, 0x03, 0x04},
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.ErrorResponse
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, codes.ResponseError, orig.ResponseCode())
	assert.Equal(t, codes.ErrorDecryptError, got.ErrorCode())
	assert.Equal(t, uint8(0x42), got.ErrorData())
	assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, got.ExtErrorData)
}

func TestWire_ResponseNotReadyData(t *testing.T) {
	orig := &msgs.ResponseNotReadyData{RDExponent: 10, RequestCode: 0x81, Token: 0x01, RDTM: 100}
	data := orig.Marshal()
	assert.Equal(t, 4, len(data))

	var got msgs.ResponseNotReadyData
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, uint8(10), got.RDExponent)
	assert.Equal(t, uint8(0x81), got.RequestCode)
	assert.Equal(t, uint8(0x01), got.Token)
	assert.Equal(t, uint8(100), got.RDTM)

	assert.ErrorIs(t, got.Unmarshal([]byte{0, 0}), msgs.ErrShortBuffer)
}

func TestWire_RespondIfReady(t *testing.T) {
	orig := &msgs.RespondIfReady{Header: hdr(0x12, uint8(codes.RequestRespondIfReady))}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.RespondIfReady
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, codes.RequestRespondIfReady, orig.RequestCode())
}

// --- Finish messages ---

func TestWire_Finish_WithSignature(t *testing.T) {
	orig := &msgs.Finish{
		Header:     msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestFinish), Param1: 0x01}},
		Signature:  make([]byte, 64),
		VerifyData: make([]byte, 32),
	}
	data, err := orig.Marshal()
	require.NoError(t, err)
	assert.True(t, orig.SignatureIncluded())
	assert.Equal(t, codes.RequestFinish, orig.RequestCode())

	var got msgs.Finish
	require.NoError(t, got.UnmarshalWithSizes(data, 64, 32))
	assert.True(t, got.SignatureIncluded())
	assert.Equal(t, 64, len(got.Signature))
	assert.Equal(t, 32, len(got.VerifyData))
}

func TestWire_Finish_NoSignature(t *testing.T) {
	orig := &msgs.Finish{
		Header:     msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestFinish), Param1: 0x00}},
		VerifyData: make([]byte, 32),
	}
	data, err := orig.Marshal()
	require.NoError(t, err)
	assert.False(t, orig.SignatureIncluded())

	var got msgs.Finish
	require.NoError(t, got.UnmarshalWithSizes(data, 0, 32))
	assert.Nil(t, got.Signature)
	assert.Equal(t, 32, len(got.VerifyData))
}

func TestWire_Finish_ReqSlotID(t *testing.T) {
	m := &msgs.Finish{Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{Param2: 3}}}
	assert.Equal(t, uint8(3), m.ReqSlotID())
}

func TestWire_FinishResponse_WithVerifyData(t *testing.T) {
	orig := &msgs.FinishResponse{
		Header:     hdr(0x12, uint8(codes.ResponseFinishRsp)),
		VerifyData: make([]byte, 32),
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.FinishResponse
	require.NoError(t, got.UnmarshalWithHashSize(data, 32))
	assert.Equal(t, 32, len(got.VerifyData))
	assert.Equal(t, codes.ResponseFinishRsp, orig.ResponseCode())
}

func TestWire_FinishSignContext(t *testing.T) {
	assert.Equal(t, "requester-finish signing", msgs.FinishSignContext)
}

// --- KeyExchange messages ---

func TestWire_KeyExchange(t *testing.T) {
	orig := &msgs.KeyExchange{
		Header:        msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestKeyExchange), Param1: 0xFF, Param2: 0x00}},
		ReqSessionID:  0xABCD,
		SessionPolicy: msgs.SessionPolicyTerminationRuntimeUpdate,
		ExchangeData:  make([]byte, 64),
		OpaqueData:    []byte{0x01, 0x02},
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.KeyExchange
	require.NoError(t, got.UnmarshalWithDHESize(data, 64))
	assert.Equal(t, uint16(0xABCD), got.ReqSessionID)
	assert.Equal(t, uint8(msgs.SessionPolicyTerminationRuntimeUpdate), got.SessionPolicy)
	assert.Equal(t, 64, len(got.ExchangeData))
	assert.Equal(t, []byte{0x01, 0x02}, got.OpaqueData)
	assert.Equal(t, codes.RequestKeyExchange, orig.RequestCode())
	assert.Equal(t, uint8(0x00), orig.SlotID())
	assert.Equal(t, uint8(0xFF), orig.HashType())
}

func TestWire_KeyExchange_BasicUnmarshal(t *testing.T) {
	orig := &msgs.KeyExchange{
		Header:       hdr(0x12, uint8(codes.RequestKeyExchange)),
		ReqSessionID: 0x1234,
		ExchangeData: make([]byte, 64),
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.KeyExchange
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, uint16(0x1234), got.ReqSessionID)
}

func TestWire_KeyExchangeResponse(t *testing.T) {
	orig := &msgs.KeyExchangeResponse{
		Header:                 hdr(0x12, uint8(codes.ResponseKeyExchangeRsp)),
		RspSessionID:           0x5678,
		MutAuthRequested:       msgs.MutAuthRequested,
		ExchangeData:           make([]byte, 64),
		MeasurementSummaryHash: make([]byte, 32),
		OpaqueData:             []byte{0x03},
		Signature:              make([]byte, 64),
		VerifyData:             make([]byte, 32),
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.KeyExchangeResponse
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, uint16(0x5678), got.RspSessionID)
	assert.Equal(t, uint8(msgs.MutAuthRequested), got.MutAuthRequested)
	assert.Equal(t, codes.ResponseKeyExchangeRsp, orig.ResponseCode())
}

func TestWire_KeyExchange_Constants(t *testing.T) {
	assert.Equal(t, uint8(0x01), uint8(msgs.MutAuthRequested))
	assert.Equal(t, uint8(0x02), uint8(msgs.MutAuthRequestedWithEncapReq))
	assert.Equal(t, uint8(0x04), uint8(msgs.MutAuthRequestedWithGetDigests))
	assert.Equal(t, uint8(0x01), uint8(msgs.SessionPolicyTerminationRuntimeUpdate))
	assert.Equal(t, uint8(0x02), uint8(msgs.SessionPolicyEventAll))
	assert.Equal(t, "responder-key_exchange_rsp signing", msgs.KeyExchangeRspSignContext)
	assert.Equal(t, "Requester-KEP-dmtf-spdm-v1.2", msgs.KeyExchangeRequesterContext12)
	assert.Equal(t, "Responder-KEP-dmtf-spdm-v1.2", msgs.KeyExchangeResponderContext12)
}

// --- Advanced messages ---

func TestWire_GetMeasurementExtensionLog(t *testing.T) {
	orig := &msgs.GetMeasurementExtensionLog{
		Header: hdr(0x12, uint8(codes.RequestGetMeasurementExtensionLog)),
		Offset: 100,
		Length: 500,
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.GetMeasurementExtensionLog
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, uint32(100), got.Offset)
	assert.Equal(t, uint32(500), got.Length)
	assert.Equal(t, codes.RequestGetMeasurementExtensionLog, orig.RequestCode())
}

func TestWire_MeasurementExtensionLogResponse(t *testing.T) {
	orig := &msgs.MeasurementExtensionLogResponse{
		Header:          hdr(0x12, uint8(codes.ResponseMeasurementExtensionLog)),
		RemainderLength: 1000,
		MEL:             []byte{0x01, 0x02, 0x03, 0x04, 0x05},
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.MeasurementExtensionLogResponse
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, uint32(5), got.PortionLength)
	assert.Equal(t, uint32(1000), got.RemainderLength)
	assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04, 0x05}, got.MEL)
	assert.Equal(t, codes.ResponseMeasurementExtensionLog, orig.ResponseCode())
}

func TestWire_GetKeyPairInfo(t *testing.T) {
	orig := &msgs.GetKeyPairInfo{
		Header:    hdr(0x12, uint8(codes.RequestGetKeyPairInfo)),
		KeyPairID: 3,
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.GetKeyPairInfo
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, uint8(3), got.KeyPairID)
	assert.Equal(t, codes.RequestGetKeyPairInfo, orig.RequestCode())
}

func TestWire_KeyPairInfoResponse(t *testing.T) {
	orig := &msgs.KeyPairInfoResponse{
		Header:               hdr(0x12, uint8(codes.ResponseKeyPairInfo)),
		TotalKeyPairs:        5,
		KeyPairID:            2,
		Capabilities:         0x0003,
		KeyUsageCapabilities: 0x0001,
		CurrentKeyUsage:      0x0001,
		AsymAlgoCapabilities: 0x00000010,
		CurrentAsymAlgo:      0x00000010,
		PublicKeyInfoLen:     4,
		AssocCertSlotMask:    0x01,
		PublicKeyInfo:        []byte{0x30, 0x59, 0x30, 0x13},
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.KeyPairInfoResponse
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, uint8(5), got.TotalKeyPairs)
	assert.Equal(t, uint8(2), got.KeyPairID)
	assert.Equal(t, uint16(0x0003), got.Capabilities)
	assert.Equal(t, uint32(0x00000010), got.AsymAlgoCapabilities)
	assert.Equal(t, uint16(4), got.PublicKeyInfoLen)
	assert.Equal(t, uint8(0x01), got.AssocCertSlotMask)
	assert.Equal(t, []byte{0x30, 0x59, 0x30, 0x13}, got.PublicKeyInfo)
	assert.Equal(t, codes.ResponseKeyPairInfo, orig.ResponseCode())
}

func TestWire_GetEndpointInfo_NoSig(t *testing.T) {
	orig := &msgs.GetEndpointInfo{
		Header:            hdr(0x12, uint8(codes.RequestGetEndpointInfo)),
		RequestAttributes: 0x00,
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.GetEndpointInfo
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, uint8(0x00), got.RequestAttributes)
	assert.Equal(t, codes.RequestGetEndpointInfo, orig.RequestCode())
}

func TestWire_GetEndpointInfo_WithSig(t *testing.T) {
	orig := &msgs.GetEndpointInfo{
		Header:            hdr(0x12, uint8(codes.RequestGetEndpointInfo)),
		RequestAttributes: 0x01,
	}
	for i := range orig.Nonce {
		orig.Nonce[i] = byte(i)
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var got msgs.GetEndpointInfo
	require.NoError(t, got.Unmarshal(data))
	assert.Equal(t, uint8(0x01), got.RequestAttributes)
	assert.Equal(t, orig.Nonce, got.Nonce)
}

// --- Label/context constants ---

func TestWire_LabelConstants(t *testing.T) {
	assert.Equal(t, "spdm1.2 ", msgs.BinConcatLabel12)
	assert.Equal(t, "spdm1.3 ", msgs.BinConcatLabel13)
	assert.Equal(t, "derived", msgs.BinStr0Label)
	assert.Equal(t, "req hs data", msgs.BinStr1Label)
	assert.Equal(t, "rsp hs data", msgs.BinStr2Label)
	assert.Equal(t, "req app data", msgs.BinStr3Label)
	assert.Equal(t, "rsp app data", msgs.BinStr4Label)
	assert.Equal(t, "key", msgs.BinStr5Label)
	assert.Equal(t, "iv", msgs.BinStr6Label)
	assert.Equal(t, "finished", msgs.BinStr7Label)
	assert.Equal(t, "exp master", msgs.BinStr8Label)
	assert.Equal(t, "traffic upd", msgs.BinStr9Label)
}

func TestWire_SigningContexts(t *testing.T) {
	assert.Equal(t, "dmtf-spdm-v1.2.*", msgs.SigningPrefixContext12)
	assert.Equal(t, "dmtf-spdm-v1.3.*", msgs.SigningPrefixContext13)
	assert.Equal(t, 100, msgs.SigningContextSize)
	assert.Equal(t, "responder-endpoint_info signing", msgs.EndpointInfoSignContext)
	assert.Equal(t, "requester-endpoint_info signing", msgs.MutEndpointInfoSignContext)
}

// --- Short buffer errors ---

func TestWire_ShortBufferErrors(t *testing.T) {
	short := []byte{0, 0, 0}
	tests := []struct {
		name string
		fn   func() error
	}{
		{"ChunkSend", func() error { return (&msgs.ChunkSend{}).Unmarshal(short) }},
		{"ChunkSendAck", func() error { return (&msgs.ChunkSendAck{}).Unmarshal(short) }},
		{"ChunkGet", func() error { return (&msgs.ChunkGet{}).Unmarshal(short) }},
		{"ChunkResponse", func() error { return (&msgs.ChunkResponse{}).Unmarshal(short) }},
		{"GetCSR", func() error { return (&msgs.GetCSR{}).Unmarshal(short) }},
		{"CSRResponse", func() error { return (&msgs.CSRResponse{}).Unmarshal(short) }},
		{"PSKExchange", func() error { return (&msgs.PSKExchange{}).Unmarshal(short) }},
		{"PSKExchangeRsp", func() error { return (&msgs.PSKExchangeResponse{}).Unmarshal(short) }},
		{"KeyExchange", func() error { return (&msgs.KeyExchange{}).Unmarshal(short) }},
		{"KeyExchangeRsp", func() error { return (&msgs.KeyExchangeResponse{}).Unmarshal(short) }},
		{"GetMEL", func() error { return (&msgs.GetMeasurementExtensionLog{}).Unmarshal(short) }},
		{"MELResp", func() error { return (&msgs.MeasurementExtensionLogResponse{}).Unmarshal(short) }},
		{"GetKeyPairInfo", func() error { return (&msgs.GetKeyPairInfo{}).Unmarshal(short) }},
		{"KeyPairInfoResp", func() error { return (&msgs.KeyPairInfoResponse{}).Unmarshal(short) }},
		{"GetEndpointInfo", func() error { return (&msgs.GetEndpointInfo{}).Unmarshal(short) }},
		{"VendorReq", func() error { return (&msgs.VendorDefinedRequest{}).Unmarshal(short) }},
		{"VendorResp", func() error { return (&msgs.VendorDefinedResponse{}).Unmarshal(short) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Error(t, tt.fn())
		})
	}
}
