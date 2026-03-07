package msgs

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

// ---------------------------------------------------------------------------
// advanced.go: GetMeasurementExtensionLog
// ---------------------------------------------------------------------------

func TestGetMeasurementExtensionLog_RequestCode(t *testing.T) {
	m := &GetMeasurementExtensionLog{}
	assert.Equal(t, codes.RequestGetMeasurementExtensionLog, m.RequestCode())
}

func TestGetMeasurementExtensionLog_RoundTrip(t *testing.T) {
	m := &GetMeasurementExtensionLog{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x13, RequestResponseCode: 0xEF, Param1: 0x00, Param2: 0x00}},
		Offset: 128,
		Length: 4096,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	require.Len(t, data, HeaderSize+8)
	var m2 GetMeasurementExtensionLog
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, m.Header, m2.Header)
	assert.Equal(t, uint32(128), m2.Offset)
	assert.Equal(t, uint32(4096), m2.Length)
}

func TestGetMeasurementExtensionLog_ShortBuffer(t *testing.T) {
	var m GetMeasurementExtensionLog
	// Empty
	assert.True(t, errors.Is(m.Unmarshal(nil), ErrShortBuffer))
	// Too short for header
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize-1)), ErrShortBuffer))
	// Has header but missing fixed fields
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize)), ErrShortBuffer))
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize+7)), ErrShortBuffer))
	// Exact minimum should succeed
	require.NoError(t, m.Unmarshal(make([]byte, HeaderSize+8)))
}

// ---------------------------------------------------------------------------
// advanced.go: MeasurementExtensionLogResponse
// ---------------------------------------------------------------------------

func TestMeasurementExtensionLogResponse_ResponseCode(t *testing.T) {
	m := &MeasurementExtensionLogResponse{}
	assert.Equal(t, codes.ResponseMeasurementExtensionLog, m.ResponseCode())
}

func TestMeasurementExtensionLogResponse_RoundTrip(t *testing.T) {
	mel := bytes.Repeat([]byte{0xFE}, 64)
	m := &MeasurementExtensionLogResponse{
		Header:          MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x13, RequestResponseCode: 0x6F}},
		RemainderLength: 200,
		MEL:             mel,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 MeasurementExtensionLogResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint32(len(mel)), m2.PortionLength)
	assert.Equal(t, uint32(200), m2.RemainderLength)
	assert.Equal(t, mel, m2.MEL)
}

func TestMeasurementExtensionLogResponse_EmptyMEL(t *testing.T) {
	m := &MeasurementExtensionLogResponse{
		Header:          MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x13, RequestResponseCode: 0x6F}},
		RemainderLength: 0,
		MEL:             nil,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 MeasurementExtensionLogResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Empty(t, m2.MEL)
}

func TestMeasurementExtensionLogResponse_ShortBuffer(t *testing.T) {
	var m MeasurementExtensionLogResponse
	// Too short for header+fixed
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize+7)), ErrShortBuffer))
	// Header+fixed OK but PortionLength claims data that doesn't exist
	buf := make([]byte, HeaderSize+8)
	le.PutUint32(buf[HeaderSize:], 10) // PortionLength = 10
	le.PutUint32(buf[HeaderSize+4:], 0)
	assert.True(t, errors.Is(m.Unmarshal(buf), ErrShortBuffer))
}

// ---------------------------------------------------------------------------
// advanced.go: GetKeyPairInfo
// ---------------------------------------------------------------------------

func TestGetKeyPairInfo_RequestCode(t *testing.T) {
	m := &GetKeyPairInfo{}
	assert.Equal(t, codes.RequestGetKeyPairInfo, m.RequestCode())
}

func TestGetKeyPairInfo_RoundTrip(t *testing.T) {
	m := &GetKeyPairInfo{
		Header:    MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x13, RequestResponseCode: 0xFC}},
		KeyPairID: 7,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	require.Len(t, data, HeaderSize+1)
	var m2 GetKeyPairInfo
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint8(7), m2.KeyPairID)
}

func TestGetKeyPairInfo_ShortBuffer(t *testing.T) {
	var m GetKeyPairInfo
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize)), ErrShortBuffer))
}

// ---------------------------------------------------------------------------
// advanced.go: KeyPairInfoResponse
// ---------------------------------------------------------------------------

func TestKeyPairInfoResponse_ResponseCode(t *testing.T) {
	m := &KeyPairInfoResponse{}
	assert.Equal(t, codes.ResponseKeyPairInfo, m.ResponseCode())
}

func TestKeyPairInfoResponse_RoundTrip(t *testing.T) {
	pki := []byte{0x30, 0x59, 0x30, 0x13} // tiny ASN.1 stub
	m := &KeyPairInfoResponse{
		Header:               MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x13, RequestResponseCode: 0x7C}},
		TotalKeyPairs:        3,
		KeyPairID:            1,
		Capabilities:         0x000F,
		KeyUsageCapabilities: 0x0003,
		CurrentKeyUsage:      0x0001,
		AsymAlgoCapabilities: 0x00000060,
		CurrentAsymAlgo:      0x00000020,
		PublicKeyInfoLen:     uint16(len(pki)),
		AssocCertSlotMask:    0x05,
		PublicKeyInfo:        pki,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 KeyPairInfoResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint8(3), m2.TotalKeyPairs)
	assert.Equal(t, uint8(1), m2.KeyPairID)
	assert.Equal(t, uint16(0x000F), m2.Capabilities)
	assert.Equal(t, uint16(0x0003), m2.KeyUsageCapabilities)
	assert.Equal(t, uint16(0x0001), m2.CurrentKeyUsage)
	assert.Equal(t, uint32(0x00000060), m2.AsymAlgoCapabilities)
	assert.Equal(t, uint32(0x00000020), m2.CurrentAsymAlgo)
	assert.Equal(t, uint16(len(pki)), m2.PublicKeyInfoLen)
	assert.Equal(t, uint8(0x05), m2.AssocCertSlotMask)
	assert.Equal(t, pki, m2.PublicKeyInfo)
}

func TestKeyPairInfoResponse_ShortBuffer(t *testing.T) {
	var m KeyPairInfoResponse
	// Too short for fixed fields
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize+18)), ErrShortBuffer))
	// Fixed fields OK but PublicKeyInfoLen claims more data
	buf := make([]byte, HeaderSize+19)
	le.PutUint16(buf[HeaderSize+16:], 5) // PublicKeyInfoLen=5 but no data follows
	assert.True(t, errors.Is(m.Unmarshal(buf), ErrShortBuffer))
}

func TestKeyPairInfoResponse_EmptyPublicKeyInfo(t *testing.T) {
	m := &KeyPairInfoResponse{
		Header:           MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x13, RequestResponseCode: 0x7C}},
		TotalKeyPairs:    1,
		KeyPairID:        0,
		PublicKeyInfoLen: 0,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 KeyPairInfoResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Empty(t, m2.PublicKeyInfo)
}

// ---------------------------------------------------------------------------
// advanced.go: GetEndpointInfo
// ---------------------------------------------------------------------------

func TestGetEndpointInfo_RequestCode(t *testing.T) {
	m := &GetEndpointInfo{}
	assert.Equal(t, codes.RequestGetEndpointInfo, m.RequestCode())
}

func TestGetEndpointInfo_RoundTrip_NoSignature(t *testing.T) {
	m := &GetEndpointInfo{
		Header:            MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x13, RequestResponseCode: 0x87}},
		RequestAttributes: 0x00, // no signature requested
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	require.Len(t, data, HeaderSize+4)
	var m2 GetEndpointInfo
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint8(0x00), m2.RequestAttributes)
}

func TestGetEndpointInfo_RoundTrip_WithSignature(t *testing.T) {
	m := &GetEndpointInfo{
		Header:            MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x13, RequestResponseCode: 0x87}},
		RequestAttributes: 0x01, // signature requested
	}
	for i := range m.Nonce {
		m.Nonce[i] = byte(i + 1)
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	require.Len(t, data, HeaderSize+4+NonceSize)
	var m2 GetEndpointInfo
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, m.Nonce, m2.Nonce)
}

func TestGetEndpointInfo_ShortBuffer(t *testing.T) {
	var m GetEndpointInfo
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize+3)), ErrShortBuffer))
}

// ---------------------------------------------------------------------------
// csr.go: GetCSR
// ---------------------------------------------------------------------------

func TestGetCSR_RequestCode(t *testing.T) {
	m := &GetCSR{}
	assert.Equal(t, codes.RequestGetCSR, m.RequestCode())
}

func TestGetCSR_RoundTrip(t *testing.T) {
	reqInfo := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	opaque := []byte{0xAA, 0xBB, 0xCC}
	m := &GetCSR{
		Header:        MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xED}},
		RequesterInfo: reqInfo,
		OpaqueData:    opaque,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 GetCSR
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, reqInfo, m2.RequesterInfo)
	assert.Equal(t, opaque, m2.OpaqueData)
	assert.Equal(t, uint16(len(reqInfo)), m2.RequesterInfoLen)
	assert.Equal(t, uint16(len(opaque)), m2.OpaqueDataLen)
}

func TestGetCSR_EmptyFields(t *testing.T) {
	m := &GetCSR{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xED}},
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 GetCSR
	require.NoError(t, m2.Unmarshal(data))
	assert.Empty(t, m2.RequesterInfo)
	assert.Empty(t, m2.OpaqueData)
}

func TestGetCSR_ShortBuffer(t *testing.T) {
	var m GetCSR
	// Too short for fixed fields
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize+3)), ErrShortBuffer))
	// Fixed fields claim variable data that's missing
	buf := make([]byte, HeaderSize+4)
	le.PutUint16(buf[HeaderSize:], 10)  // RequesterInfoLen = 10
	le.PutUint16(buf[HeaderSize+2:], 0) // OpaqueDataLen = 0
	assert.True(t, errors.Is(m.Unmarshal(buf), ErrShortBuffer))
}

// ---------------------------------------------------------------------------
// csr.go: CSRResponse
// ---------------------------------------------------------------------------

func TestCSRResponse_ResponseCode(t *testing.T) {
	m := &CSRResponse{}
	assert.Equal(t, codes.ResponseCSR, m.ResponseCode())
}

func TestCSRResponse_RoundTrip(t *testing.T) {
	csr := bytes.Repeat([]byte{0x30}, 128)
	m := &CSRResponse{
		Header:   MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x6D}},
		Reserved: 0x1234,
		CSR:      csr,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 CSRResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint16(len(csr)), m2.CSRLength)
	assert.Equal(t, uint16(0x1234), m2.Reserved)
	assert.Equal(t, csr, m2.CSR)
}

func TestCSRResponse_ShortBuffer(t *testing.T) {
	var m CSRResponse
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize+3)), ErrShortBuffer))
	// CSRLength claims data that doesn't exist
	buf := make([]byte, HeaderSize+4)
	le.PutUint16(buf[HeaderSize:], 20) // CSRLength = 20
	assert.True(t, errors.Is(m.Unmarshal(buf), ErrShortBuffer))
}

// ---------------------------------------------------------------------------
// csr.go: SetCertificate
// ---------------------------------------------------------------------------

func TestSetCertificate_RequestCode(t *testing.T) {
	m := &SetCertificate{}
	assert.Equal(t, codes.RequestSetCertificate, m.RequestCode())
}

func TestSetCertificate_SlotID(t *testing.T) {
	tests := []struct {
		param1 uint8
		want   uint8
	}{
		{0x00, 0},
		{0x03, 3},
		{0x0F, 15},
		{0xF5, 5}, // upper nibble ignored
	}
	for _, tt := range tests {
		m := &SetCertificate{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{Param1: tt.param1}}}
		assert.Equal(t, tt.want, m.SlotID(), "Param1=0x%02X", tt.param1)
	}
}

func TestSetCertificate_RoundTrip(t *testing.T) {
	chain := bytes.Repeat([]byte{0xDE}, 200)
	m := &SetCertificate{
		Header:    MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xEE, Param1: 0x02}},
		CertChain: chain,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 SetCertificate
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, chain, m2.CertChain)
	assert.Equal(t, uint8(2), m2.SlotID())
}

func TestSetCertificate_EmptyCertChain(t *testing.T) {
	m := &SetCertificate{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xEE}},
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 SetCertificate
	require.NoError(t, m2.Unmarshal(data))
	assert.Empty(t, m2.CertChain)
}

func TestSetCertificate_ShortBuffer(t *testing.T) {
	var m SetCertificate
	// Less than header size
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize-1)), ErrShortBuffer))
}

// ---------------------------------------------------------------------------
// csr.go: SetCertificateResponse
// ---------------------------------------------------------------------------

func TestSetCertificateResponse_ResponseCode(t *testing.T) {
	m := &SetCertificateResponse{}
	assert.Equal(t, codes.ResponseSetCertificateRsp, m.ResponseCode())
}

func TestSetCertificateResponse_RoundTrip(t *testing.T) {
	m := &SetCertificateResponse{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x6E, Param1: 0x02}},
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	require.Len(t, data, HeaderSize)
	var m2 SetCertificateResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, m.Header, m2.Header)
}

func TestSetCertificateResponse_ShortBuffer(t *testing.T) {
	var m SetCertificateResponse
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize-1)), ErrShortBuffer))
}

// ---------------------------------------------------------------------------
// chunk.go: ChunkSend
// ---------------------------------------------------------------------------

func TestChunkSend_RequestCode(t *testing.T) {
	m := &ChunkSend{}
	assert.Equal(t, codes.RequestChunkSend, m.RequestCode())
}

func TestChunkSend_IsLastChunk(t *testing.T) {
	m := &ChunkSend{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{Param1: 0x00}}}
	assert.False(t, m.IsLastChunk())
	m.Header.Param1 = ChunkSendAttrLastChunk
	assert.True(t, m.IsLastChunk())
	m.Header.Param1 = 0xFF
	assert.True(t, m.IsLastChunk(), "expected true when other bits also set")
}

func TestChunkSend_RoundTrip_SeqZero(t *testing.T) {
	chunk := bytes.Repeat([]byte{0xAA}, 64)
	m := &ChunkSend{
		Header:           MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x85, Param2: 0x01}},
		ChunkSeqNo:       0,
		LargeMessageSize: 1024,
		Chunk:            chunk,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	// SeqNo==0: header(4) + seqno(2) + reserved(2) + chunksize(4) + largemsgsize(4) + chunk(64)
	expectedSize := HeaderSize + 8 + 4 + len(chunk)
	require.Len(t, data, expectedSize)
	var m2 ChunkSend
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint16(0), m2.ChunkSeqNo)
	assert.Equal(t, uint32(1024), m2.LargeMessageSize)
	assert.Equal(t, chunk, m2.Chunk)
}

func TestChunkSend_RoundTrip_SeqNonZero(t *testing.T) {
	chunk := bytes.Repeat([]byte{0xBB}, 32)
	m := &ChunkSend{
		Header:     MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x85, Param1: ChunkSendAttrLastChunk, Param2: 0x01}},
		ChunkSeqNo: 5,
		Chunk:      chunk,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	// SeqNo>0: no LargeMessageSize field
	expectedSize := HeaderSize + 8 + len(chunk)
	require.Len(t, data, expectedSize)
	var m2 ChunkSend
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint16(5), m2.ChunkSeqNo)
	assert.Equal(t, uint32(0), m2.LargeMessageSize, "LargeMessageSize should be 0 for SeqNo>0")
	assert.True(t, m2.IsLastChunk())
	assert.Equal(t, chunk, m2.Chunk)
}

func TestChunkSend_ShortBuffer(t *testing.T) {
	var m ChunkSend
	// Less than header + fixed 8 bytes
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize+7)), ErrShortBuffer))
	// SeqNo==0 but missing LargeMessageSize
	buf := make([]byte, HeaderSize+8)
	// ChunkSeqNo=0 (already zero), ChunkSize=0
	assert.True(t, errors.Is(m.Unmarshal(buf), ErrShortBuffer))
	// SeqNo==0, LargeMessageSize present but ChunkSize claims too much
	buf2 := make([]byte, HeaderSize+12)   // has LargeMessageSize
	le.PutUint32(buf2[HeaderSize+4:], 10) // ChunkSize = 10, but only 0 bytes of chunk follow
	assert.True(t, errors.Is(m.Unmarshal(buf2), ErrShortBuffer))
	// SeqNo>0, ChunkSize claims too much
	buf3 := make([]byte, HeaderSize+8)
	le.PutUint16(buf3[HeaderSize:], 1)   // ChunkSeqNo = 1
	le.PutUint32(buf3[HeaderSize+4:], 5) // ChunkSize = 5, but 0 bytes follow
	assert.True(t, errors.Is(m.Unmarshal(buf3), ErrShortBuffer))
}

// ---------------------------------------------------------------------------
// chunk.go: ChunkSendAck
// ---------------------------------------------------------------------------

func TestChunkSendAck_ResponseCode(t *testing.T) {
	m := &ChunkSendAck{}
	assert.Equal(t, codes.ResponseChunkSendAck, m.ResponseCode())
}

func TestChunkSendAck_RoundTrip(t *testing.T) {
	m := &ChunkSendAck{
		Header:     MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x05, Param2: 0x01}},
		ChunkSeqNo: 42,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 ChunkSendAck
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint16(42), m2.ChunkSeqNo)
	assert.Empty(t, m2.Response)
}

func TestChunkSendAck_WithEarlyErrorResponse(t *testing.T) {
	resp := []byte{0x12, 0x7F, 0x03, 0x00} // error response
	m := &ChunkSendAck{
		Header:     MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x05, Param1: ChunkSendAckAttrEarlyError}},
		ChunkSeqNo: 0,
		Response:   resp,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 ChunkSendAck
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, resp, m2.Response)
}

func TestChunkSendAck_ShortBuffer(t *testing.T) {
	var m ChunkSendAck
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize+1)), ErrShortBuffer))
}

// ---------------------------------------------------------------------------
// chunk.go: ChunkGet
// ---------------------------------------------------------------------------

func TestChunkGet_RequestCode(t *testing.T) {
	m := &ChunkGet{}
	assert.Equal(t, codes.RequestChunkGet, m.RequestCode())
}

func TestChunkGet_RoundTrip(t *testing.T) {
	m := &ChunkGet{
		Header:     MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x86, Param2: 0x03}},
		ChunkSeqNo: 0xFFFF,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	require.Len(t, data, HeaderSize+2)
	var m2 ChunkGet
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint16(0xFFFF), m2.ChunkSeqNo)
	assert.Equal(t, uint8(0x03), m2.Header.Param2)
}

func TestChunkGet_ShortBuffer(t *testing.T) {
	var m ChunkGet
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize+1)), ErrShortBuffer))
}

// ---------------------------------------------------------------------------
// chunk.go: ChunkResponse
// ---------------------------------------------------------------------------

func TestChunkResponse_ResponseCode(t *testing.T) {
	m := &ChunkResponse{}
	assert.Equal(t, codes.ResponseChunkResponse, m.ResponseCode())
}

func TestChunkResponse_IsLastChunk(t *testing.T) {
	m := &ChunkResponse{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{Param1: 0x00}}}
	assert.False(t, m.IsLastChunk())
	m.Header.Param1 = ChunkResponseAttrLastChunk
	assert.True(t, m.IsLastChunk())
}

func TestChunkResponse_RoundTrip_SeqZero(t *testing.T) {
	chunk := bytes.Repeat([]byte{0xCC}, 48)
	m := &ChunkResponse{
		Header:           MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x06, Param2: 0x02}},
		ChunkSeqNo:       0,
		LargeMessageSize: 2048,
		Chunk:            chunk,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	expectedSize := HeaderSize + 8 + 4 + len(chunk)
	require.Len(t, data, expectedSize)
	var m2 ChunkResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint32(2048), m2.LargeMessageSize)
	assert.Equal(t, chunk, m2.Chunk)
}

func TestChunkResponse_RoundTrip_SeqNonZero(t *testing.T) {
	chunk := bytes.Repeat([]byte{0xDD}, 16)
	m := &ChunkResponse{
		Header:     MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x06, Param1: ChunkResponseAttrLastChunk}},
		ChunkSeqNo: 3,
		Chunk:      chunk,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	expectedSize := HeaderSize + 8 + len(chunk)
	require.Len(t, data, expectedSize)
	var m2 ChunkResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint16(3), m2.ChunkSeqNo)
	assert.Equal(t, uint32(0), m2.LargeMessageSize, "LargeMessageSize should be 0 for SeqNo>0")
	assert.True(t, m2.IsLastChunk())
}

func TestChunkResponse_ShortBuffer(t *testing.T) {
	var m ChunkResponse
	// Less than header + fixed 8
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize+7)), ErrShortBuffer))
	// SeqNo==0 but missing LargeMessageSize
	buf := make([]byte, HeaderSize+8) // ChunkSeqNo=0 implied
	assert.True(t, errors.Is(m.Unmarshal(buf), ErrShortBuffer))
	// SeqNo==0, LargeMessageSize OK, ChunkSize claims too much
	buf2 := make([]byte, HeaderSize+12)
	le.PutUint32(buf2[HeaderSize+4:], 8) // ChunkSize = 8
	assert.True(t, errors.Is(m.Unmarshal(buf2), ErrShortBuffer))
	// SeqNo>0, ChunkSize claims too much
	buf3 := make([]byte, HeaderSize+8)
	le.PutUint16(buf3[HeaderSize:], 1)   // ChunkSeqNo = 1
	le.PutUint32(buf3[HeaderSize+4:], 3) // ChunkSize = 3
	assert.True(t, errors.Is(m.Unmarshal(buf3), ErrShortBuffer))
}
