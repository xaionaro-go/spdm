package msgs

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

func TestMessageHeaderRoundTrip(t *testing.T) {
	h := MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x84, Param1: 0x01, Param2: 0x02}}
	data, err := h.Marshal()
	require.NoError(t, err)
	require.Len(t, data, HeaderSize)
	var h2 MessageHeader
	require.NoError(t, h2.Unmarshal(data))
	require.Equal(t, h, h2)
}

func TestHeaderUnmarshalShort(t *testing.T) {
	var h MessageHeader
	assert.Equal(t, ErrShortBuffer, h.Unmarshal([]byte{0x12, 0x84}))
}

func TestGetVersionRoundTrip(t *testing.T) {
	m := &GetVersion{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x10, RequestResponseCode: 0x84}}}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 GetVersion
	require.NoError(t, m2.Unmarshal(data))
	require.Equal(t, m.Header, m2.Header)
}

func TestVersionResponseRoundTrip(t *testing.T) {
	m := &VersionResponse{
		Header:         MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x10, RequestResponseCode: 0x04}},
		VersionEntries: []uint16{0x1000, 0x1100, 0x1200},
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 VersionResponse
	require.NoError(t, m2.Unmarshal(data))
	require.Len(t, m2.VersionEntries, 3)
	require.Equal(t, m.VersionEntries, m2.VersionEntries)
}

func TestGetCapabilitiesRoundTrip(t *testing.T) {
	m := &GetCapabilities{
		Header:           MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xE1}},
		CTExponent:       10,
		Flags:            0x00008206,
		DataTransferSize: 1024,
		MaxSPDMmsgSize:   65536,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 GetCapabilities
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint8(10), m2.CTExponent)
	assert.Equal(t, uint32(0x00008206), m2.Flags)
	assert.Equal(t, uint32(1024), m2.DataTransferSize)
	assert.Equal(t, uint32(65536), m2.MaxSPDMmsgSize)
}

func TestCapabilitiesResponseRoundTrip(t *testing.T) {
	m := &CapabilitiesResponse{
		Header:           MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x61}},
		CTExponent:       10,
		Flags:            0x00038217,
		DataTransferSize: 4096,
		MaxSPDMmsgSize:   65536,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 CapabilitiesResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, m.Flags, m2.Flags)
	assert.Equal(t, m.DataTransferSize, m2.DataTransferSize)
}

func TestNegotiateAlgorithmsRoundTrip(t *testing.T) {
	m := &NegotiateAlgorithms{
		Header:                   MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xE3, Param1: 2}},
		MeasurementSpecification: 0x01,
		BaseAsymAlgo:             0x00000010,
		BaseHashAlgo:             0x00000001,
		AlgStructs: []AlgStructTable{
			{AlgType: AlgTypeDHE, AlgCount: 0x20, AlgSupported: 0x0008},
			{AlgType: AlgTypeAEAD, AlgCount: 0x20, AlgSupported: 0x0002},
		},
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 NegotiateAlgorithms
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint32(0x00000010), m2.BaseAsymAlgo)
	assert.Equal(t, uint32(0x00000001), m2.BaseHashAlgo)
	require.Len(t, m2.AlgStructs, 2)
	assert.Equal(t, uint8(AlgTypeDHE), m2.AlgStructs[0].AlgType)
	assert.Equal(t, uint16(0x0008), m2.AlgStructs[0].AlgSupported)
}

func TestAlgorithmsResponseRoundTrip(t *testing.T) {
	m := &AlgorithmsResponse{
		Header:                      MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x63, Param1: 2}},
		MeasurementSpecificationSel: 0x01,
		MeasurementHashAlgo:         0x02,
		BaseAsymSel:                 0x10,
		BaseHashSel:                 0x01,
		AlgStructs: []AlgStructTable{
			{AlgType: AlgTypeDHE, AlgCount: 0x20, AlgSupported: 0x0008},
			{AlgType: AlgTypeAEAD, AlgCount: 0x20, AlgSupported: 0x0002},
		},
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 AlgorithmsResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint32(0x10), m2.BaseAsymSel)
	assert.Equal(t, uint32(0x01), m2.BaseHashSel)
}

func TestGetCertificateRoundTrip(t *testing.T) {
	m := &GetCertificate{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x82, Param1: 0x01}},
		Offset: 0,
		Length: 1024,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 GetCertificate
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint8(1), m2.SlotID())
	assert.Equal(t, uint16(0), m2.Offset)
	assert.Equal(t, uint16(1024), m2.Length)
}

func TestCertificateResponseRoundTrip(t *testing.T) {
	chain := bytes.Repeat([]byte{0xAB}, 256)
	m := &CertificateResponse{
		Header:          MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x02, Param1: 0x01}},
		PortionLength:   256,
		RemainderLength: 512,
		CertChain:       chain,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 CertificateResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint16(256), m2.PortionLength)
	assert.Equal(t, uint16(512), m2.RemainderLength)
	require.Equal(t, chain, m2.CertChain, "cert chain mismatch")
}

func TestChallengeRoundTrip(t *testing.T) {
	m := &Challenge{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x83, Param1: 0, Param2: 0xFF}},
	}
	for i := range m.Nonce {
		m.Nonce[i] = byte(i)
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 Challenge
	require.NoError(t, m2.Unmarshal(data))
	require.Equal(t, m.Nonce, m2.Nonce)
}

func TestDigestResponseRoundTrip(t *testing.T) {
	digest := bytes.Repeat([]byte{0x42}, 32)
	m := &DigestResponse{
		Header:  MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x01, Param2: 0x03}},
		Digests: [][]byte{digest, digest},
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 DigestResponse
	require.NoError(t, m2.UnmarshalWithDigestSize(data, 32))
	require.Len(t, m2.Digests, 2)
	require.Equal(t, digest, m2.Digests[0], "digest mismatch")
}

func TestErrorResponseRoundTrip(t *testing.T) {
	m := &ErrorResponse{
		Header:       MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x7F, Param1: 0x03, Param2: 0x00}},
		ExtErrorData: []byte{0x01, 0x02, 0x03, 0x04},
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 ErrorResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, codes.SPDMErrorCode(0x03), m2.ErrorCode())
	require.Equal(t, m.ExtErrorData, m2.ExtErrorData, "ext data mismatch")
}

func TestKeyExchangeRoundTrip(t *testing.T) {
	m := &KeyExchange{
		Header:        MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xE4, Param1: 0xFF, Param2: 0}},
		ReqSessionID:  0x1234,
		SessionPolicy: 0x01,
		ExchangeData:  bytes.Repeat([]byte{0xCC}, 32),
		OpaqueData:    []byte{0x01, 0x02},
	}
	for i := range m.RandomData {
		m.RandomData[i] = byte(i)
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 KeyExchange
	require.NoError(t, m2.UnmarshalWithDHESize(data, 32))
	assert.Equal(t, uint16(0x1234), m2.ReqSessionID)
	assert.Equal(t, uint8(0x01), m2.SessionPolicy)
	require.Equal(t, m.ExchangeData, m2.ExchangeData, "exchange data mismatch")
	require.Equal(t, m.OpaqueData, m2.OpaqueData, "opaque data mismatch")
}

func TestVendorDefinedRoundTrip(t *testing.T) {
	m := &VendorDefinedRequest{
		Header:     MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xFE}},
		StandardID: 0x0003,
		VendorID:   []byte{0x01, 0x00},
		Payload:    []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 VendorDefinedRequest
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint16(0x0003), m2.StandardID)
	require.Equal(t, m.VendorID, m2.VendorID, "vendor_id mismatch")
	require.Equal(t, m.Payload, m2.Payload, "payload mismatch")
}

func TestChunkSendRoundTrip(t *testing.T) {
	// First chunk (seq 0 has LargeMessageSize)
	m := &ChunkSend{
		Header:           MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x85, Param2: 0x01}},
		ChunkSeqNo:       0,
		ChunkSize:        100,
		LargeMessageSize: 500,
		Chunk:            bytes.Repeat([]byte{0xAA}, 100),
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 ChunkSend
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint32(500), m2.LargeMessageSize)
	assert.Len(t, m2.Chunk, 100)
}

func TestChunkGetRoundTrip(t *testing.T) {
	m := &ChunkGet{
		Header:     MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x86, Param2: 0x01}},
		ChunkSeqNo: 5,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 ChunkGet
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint16(5), m2.ChunkSeqNo)
}

func TestGetCSRRoundTrip(t *testing.T) {
	m := &GetCSR{
		Header:        MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xED}},
		RequesterInfo: []byte{0x01, 0x02, 0x03},
		OpaqueData:    []byte{0xAA, 0xBB},
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 GetCSR
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, m.RequesterInfo, m2.RequesterInfo)
	assert.Equal(t, m.OpaqueData, m2.OpaqueData)
}

func TestCSRResponseRoundTrip(t *testing.T) {
	csr := bytes.Repeat([]byte{0x30}, 256)
	m := &CSRResponse{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x6D}},
		CSR:    csr,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 CSRResponse
	require.NoError(t, m2.Unmarshal(data))
	require.Equal(t, csr, m2.CSR, "CSR mismatch")
}

func TestParseMeasurementBlocks(t *testing.T) {
	// Build a single measurement block
	valueType := byte(0x01) // mutable firmware
	value := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	valueSize := len(value)
	measSize := 3 + valueSize // DMTF header + value
	record := []byte{
		0x01, 0x01, // index=1, spec=DMTF
		byte(measSize), byte(measSize >> 8), // measurement_size
		valueType,
		byte(valueSize), byte(valueSize >> 8),
	}
	record = append(record, value...)

	blocks, err := ParseMeasurementBlocks(record)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	assert.Equal(t, uint8(1), blocks[0].Index)
	assert.Equal(t, uint8(0x01), blocks[0].ValueType)
	require.Equal(t, value, blocks[0].Value, "value mismatch")
}

func TestPopcount8(t *testing.T) {
	tests := []struct {
		in   uint8
		want int
	}{
		{0x00, 0}, {0x01, 1}, {0x03, 2}, {0xFF, 8}, {0xAA, 4},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, popcount8(tt.in), "popcount8(0x%02X)", tt.in)
	}
}

func TestSessionMessagesRoundTrip(t *testing.T) {
	// Test all header-only session messages
	tests := []struct {
		name string
		msg  Message
	}{
		{"Heartbeat", &Heartbeat{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xE8}}}},
		{"HeartbeatResponse", &HeartbeatResponse{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x68}}}},
		{"KeyUpdate", &KeyUpdate{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xE9, Param1: 1, Param2: 0x42}}}},
		{"KeyUpdateResponse", &KeyUpdateResponse{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x69, Param1: 1, Param2: 0x42}}}},
		{"EndSession", &EndSession{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xEC, Param1: 0x01}}}},
		{"EndSessionResponse", &EndSessionResponse{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x6C}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.msg.Marshal()
			require.NoError(t, err)
			require.Len(t, data, HeaderSize)
			var h MessageHeader
			require.NoError(t, h.Unmarshal(data))
		})
	}
}

// --- Finish tests ---

func TestFinishRequestCode(t *testing.T) {
	m := &Finish{}
	assert.Equal(t, codes.RequestFinish, m.RequestCode())
}

func TestFinishSignatureIncluded(t *testing.T) {
	m := &Finish{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{Param1: 0x00}}}
	assert.False(t, m.SignatureIncluded(), "expected false when bit 0 not set")
	m.Header.Param1 = 0x01
	assert.True(t, m.SignatureIncluded(), "expected true when bit 0 set")
	m.Header.Param1 = 0xFF
	assert.True(t, m.SignatureIncluded(), "expected true when all bits set")
}

func TestFinishReqSlotID(t *testing.T) {
	m := &Finish{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{Param2: 0x03}}}
	assert.Equal(t, uint8(0x03), m.ReqSlotID())
}

func TestFinishRoundTripWithSizes(t *testing.T) {
	sig := bytes.Repeat([]byte{0xAA}, 64)
	verify := bytes.Repeat([]byte{0xBB}, 32)
	m := &Finish{
		Header:     MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xE5, Param1: 0x01, Param2: 0x02}},
		Signature:  sig,
		VerifyData: verify,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 Finish
	require.NoError(t, m2.UnmarshalWithSizes(data, 64, 32))
	require.Equal(t, sig, m2.Signature, "signature mismatch")
	require.Equal(t, verify, m2.VerifyData, "verify data mismatch")
	assert.True(t, m2.SignatureIncluded(), "expected signature included")
}

func TestFinishRoundTripNoSignature(t *testing.T) {
	verify := bytes.Repeat([]byte{0xCC}, 32)
	m := &Finish{
		Header:     MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xE5, Param1: 0x00}},
		VerifyData: verify,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 Finish
	require.NoError(t, m2.UnmarshalWithSizes(data, 64, 32))
	assert.Empty(t, m2.Signature)
	require.Equal(t, verify, m2.VerifyData, "verify data mismatch")
}

func TestFinishUnmarshalShort(t *testing.T) {
	var m Finish
	assert.Equal(t, ErrShortBuffer, m.Unmarshal([]byte{0x12, 0xE5}))
}

func TestFinishUnmarshalWithSizesShortSig(t *testing.T) {
	// Param1 bit 0 set => signature expected but data too short
	hdr := MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xE5, Param1: 0x01}}
	data, _ := hdr.Marshal()
	var m Finish
	assert.Equal(t, ErrShortBuffer, m.UnmarshalWithSizes(data, 64, 32))
}

func TestFinishUnmarshalWithSizesShortHash(t *testing.T) {
	// No signature, but hash data too short
	hdr := MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xE5, Param1: 0x00}}
	data, _ := hdr.Marshal()
	var m Finish
	assert.Equal(t, ErrShortBuffer, m.UnmarshalWithSizes(data, 0, 32))
}

func TestFinishResponseCode(t *testing.T) {
	m := &FinishResponse{}
	assert.Equal(t, codes.ResponseFinishRsp, m.ResponseCode())
}

func TestFinishResponseRoundTrip(t *testing.T) {
	verify := bytes.Repeat([]byte{0xDD}, 48)
	m := &FinishResponse{
		Header:     MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x65}},
		VerifyData: verify,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 FinishResponse
	require.NoError(t, m2.UnmarshalWithHashSize(data, 48))
	require.Equal(t, verify, m2.VerifyData, "verify data mismatch")
}

func TestFinishResponseNoVerifyData(t *testing.T) {
	m := &FinishResponse{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x65}},
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 FinishResponse
	require.NoError(t, m2.UnmarshalWithHashSize(data, 0))
	assert.Empty(t, m2.VerifyData)
}

func TestFinishResponseUnmarshalShort(t *testing.T) {
	var m FinishResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal([]byte{0x12}))
}

// --- PSK tests ---

func TestPSKExchangeRequestCode(t *testing.T) {
	m := &PSKExchange{}
	assert.Equal(t, codes.RequestPSKExchange, m.RequestCode())
}

func TestPSKExchangeRoundTrip(t *testing.T) {
	m := &PSKExchange{
		Header:       MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xE6}},
		ReqSessionID: 0xABCD,
		PSKHint:      []byte{0x01, 0x02, 0x03},
		Context:      []byte{0x04, 0x05},
		OpaqueData:   []byte{0x06},
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 PSKExchange
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint16(0xABCD), m2.ReqSessionID)
	require.Equal(t, m.PSKHint, m2.PSKHint, "PSKHint mismatch")
	require.Equal(t, m.Context, m2.Context, "Context mismatch")
	require.Equal(t, m.OpaqueData, m2.OpaqueData, "OpaqueData mismatch")
}

func TestPSKExchangeUnmarshalShort(t *testing.T) {
	var m PSKExchange
	// Too short for header + fixed fields
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize+4)))
}

func TestPSKExchangeUnmarshalShortVarFields(t *testing.T) {
	// Header + fixed fields present but variable fields truncated
	m := &PSKExchange{
		Header:       MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xE6}},
		ReqSessionID: 0x1234,
		PSKHint:      bytes.Repeat([]byte{0xFF}, 100),
		Context:      nil,
		OpaqueData:   nil,
	}
	data, _ := m.Marshal()
	// Truncate to just the fixed header portion
	truncated := data[:HeaderSize+8]
	var m2 PSKExchange
	assert.Equal(t, ErrShortBuffer, m2.Unmarshal(truncated))
}

func TestPSKExchangeResponseCode(t *testing.T) {
	m := &PSKExchangeResponse{}
	assert.Equal(t, codes.ResponsePSKExchangeRsp, m.ResponseCode())
}

func TestPSKExchangeResponseRoundTrip(t *testing.T) {
	m := &PSKExchangeResponse{
		Header:                 MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x66}},
		RspSessionID:           0x5678,
		MeasurementSummaryHash: bytes.Repeat([]byte{0xAA}, 32),
		Context:                []byte{0x01, 0x02, 0x03, 0x04},
		OpaqueData:             []byte{0xDE, 0xAD},
		VerifyData:             bytes.Repeat([]byte{0xBB}, 32),
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	// Unmarshal only parses fixed fields
	var m2 PSKExchangeResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint16(0x5678), m2.RspSessionID)
	assert.Equal(t, uint16(4), m2.ContextLen)
	assert.Equal(t, uint16(2), m2.OpaqueLen)
}

func TestPSKExchangeResponseUnmarshalShort(t *testing.T) {
	var m PSKExchangeResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize+4)))
}

func TestPSKFinishRequestCode(t *testing.T) {
	m := &PSKFinish{}
	assert.Equal(t, codes.RequestPSKFinish, m.RequestCode())
}

func TestPSKFinishRoundTrip(t *testing.T) {
	verify := bytes.Repeat([]byte{0xEE}, 32)
	m := &PSKFinish{
		Header:     MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xE7}},
		VerifyData: verify,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	require.Len(t, data, HeaderSize+32)
	// Unmarshal only parses header
	var m2 PSKFinish
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint8(0xE7), m2.Header.RequestResponseCode)
}

func TestPSKFinishUnmarshalShort(t *testing.T) {
	var m PSKFinish
	assert.Equal(t, ErrShortBuffer, m.Unmarshal([]byte{0x12, 0xE7}))
}

func TestPSKFinishResponseCode(t *testing.T) {
	m := &PSKFinishResponse{}
	assert.Equal(t, codes.ResponsePSKFinishRsp, m.ResponseCode())
}

func TestPSKFinishResponseRoundTrip(t *testing.T) {
	m := &PSKFinishResponse{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x67}},
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	require.Len(t, data, HeaderSize)
	var m2 PSKFinishResponse
	require.NoError(t, m2.Unmarshal(data))
	require.Equal(t, m.Header, m2.Header)
}

func TestPSKFinishResponseUnmarshalShort(t *testing.T) {
	var m PSKFinishResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal([]byte{0x12}))
}

// --- Measurements tests ---

func TestGetMeasurementsRequestCode(t *testing.T) {
	m := &GetMeasurements{}
	assert.Equal(t, codes.RequestGetMeasurements, m.RequestCode())
}

func TestGetMeasurementsRoundTrip(t *testing.T) {
	m := &GetMeasurements{
		Header:      MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xE0, Param1: MeasAttrGenerateSignature, Param2: 0x01}},
		SlotIDParam: 0x03,
	}
	for i := range m.Nonce {
		m.Nonce[i] = byte(i)
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	require.Len(t, data, HeaderSize+NonceSize+1)
	var m2 GetMeasurements
	require.NoError(t, m2.Unmarshal(data))
	require.Equal(t, m.Nonce, m2.Nonce)
	assert.Equal(t, uint8(0x03), m2.SlotIDParam)
	assert.Equal(t, uint8(MeasAttrGenerateSignature), m2.Header.Param1)
}

func TestGetMeasurementsUnmarshalShort(t *testing.T) {
	var m GetMeasurements
	// With MeasAttrGenerateSignature set, needs HeaderSize+NonceSize+1 bytes.
	buf := make([]byte, HeaderSize+NonceSize)
	buf[2] = MeasAttrGenerateSignature // Param1 with signature flag
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(buf))
}

func TestMeasurementsResponseCode(t *testing.T) {
	m := &MeasurementsResponse{}
	assert.Equal(t, codes.ResponseMeasurements, m.ResponseCode())
}

func TestMeasurementsResponseRoundTrip(t *testing.T) {
	record := []byte{0x01, 0x01, 0x07, 0x00, 0x01, 0x04, 0x00, 0xDE, 0xAD, 0xBE, 0xEF}
	opaque := []byte{0xAA, 0xBB, 0xCC}
	m := &MeasurementsResponse{
		Header:            MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x60, Param1: 0x00}},
		NumberOfBlocks:    1,
		MeasurementRecord: record,
		OpaqueData:        opaque,
	}
	for i := range m.Nonce {
		m.Nonce[i] = byte(i)
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 MeasurementsResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint8(1), m2.NumberOfBlocks)
	require.Equal(t, record, m2.MeasurementRecord, "measurement record mismatch")
	require.Equal(t, m.Nonce, m2.Nonce)
	require.Equal(t, opaque, m2.OpaqueData, "opaque data mismatch")
}

func TestMeasurementsResponseUnmarshalShort(t *testing.T) {
	var m MeasurementsResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize+2)))
}

func TestMeasurementsResponseUnmarshalShortRecord(t *testing.T) {
	// Header + numberOfBlocks + recordLen that exceeds data
	data := make([]byte, HeaderSize+4)
	data[0] = 0x12
	data[1] = 0x60
	data[4] = 1    // numberOfBlocks
	data[5] = 0xFF // recordLen low byte = 255
	var m MeasurementsResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(data))
}

// --- Session message tests ---

func TestHeartbeatRequestCode(t *testing.T) {
	m := &Heartbeat{}
	assert.Equal(t, codes.RequestHeartbeat, m.RequestCode())
}

func TestHeartbeatRoundTrip(t *testing.T) {
	m := &Heartbeat{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xE8}}}
	data, err := m.Marshal()
	require.NoError(t, err)
	require.Len(t, data, HeaderSize)
	var m2 Heartbeat
	require.NoError(t, m2.Unmarshal(data))
	require.Equal(t, m.Header, m2.Header)
}

func TestHeartbeatUnmarshalShort(t *testing.T) {
	var m Heartbeat
	assert.Equal(t, ErrShortBuffer, m.Unmarshal([]byte{0x12, 0xE8}))
}

func TestHeartbeatResponseCode(t *testing.T) {
	m := &HeartbeatResponse{}
	assert.Equal(t, codes.ResponseHeartbeatAck, m.ResponseCode())
}

func TestHeartbeatResponseRoundTrip(t *testing.T) {
	m := &HeartbeatResponse{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x68}}}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 HeartbeatResponse
	require.NoError(t, m2.Unmarshal(data))
	require.Equal(t, m.Header, m2.Header)
}

func TestHeartbeatResponseUnmarshalShort(t *testing.T) {
	var m HeartbeatResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal([]byte{0x12}))
}

func TestKeyUpdateRequestCode(t *testing.T) {
	m := &KeyUpdate{}
	assert.Equal(t, codes.RequestKeyUpdate, m.RequestCode())
}

func TestKeyUpdateRoundTrip(t *testing.T) {
	m := &KeyUpdate{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xE9, Param1: KeyUpdateOpUpdateKey, Param2: 0x42}}}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 KeyUpdate
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint8(KeyUpdateOpUpdateKey), m2.Header.Param1)
	assert.Equal(t, uint8(0x42), m2.Header.Param2)
}

func TestKeyUpdateUnmarshalShort(t *testing.T) {
	var m KeyUpdate
	assert.Equal(t, ErrShortBuffer, m.Unmarshal([]byte{0x12, 0xE9, 0x01}))
}

func TestKeyUpdateResponseCode(t *testing.T) {
	m := &KeyUpdateResponse{}
	assert.Equal(t, codes.ResponseKeyUpdateAck, m.ResponseCode())
}

func TestKeyUpdateResponseRoundTrip(t *testing.T) {
	m := &KeyUpdateResponse{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x69, Param1: KeyUpdateOpVerifyNewKey, Param2: 0x42}}}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 KeyUpdateResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint8(KeyUpdateOpVerifyNewKey), m2.Header.Param1)
	assert.Equal(t, uint8(0x42), m2.Header.Param2)
}

func TestKeyUpdateResponseUnmarshalShort(t *testing.T) {
	var m KeyUpdateResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal([]byte{0x12}))
}

func TestEndSessionRequestCode(t *testing.T) {
	m := &EndSession{}
	assert.Equal(t, codes.RequestEndSession, m.RequestCode())
}

func TestEndSessionRoundTrip(t *testing.T) {
	m := &EndSession{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xEC, Param1: EndSessionPreserveNegotiatedStateClear}}}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 EndSession
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint8(EndSessionPreserveNegotiatedStateClear), m2.Header.Param1)
}

func TestEndSessionUnmarshalShort(t *testing.T) {
	var m EndSession
	assert.Equal(t, ErrShortBuffer, m.Unmarshal([]byte{0x12, 0xEC}))
}

func TestEndSessionResponseCode(t *testing.T) {
	m := &EndSessionResponse{}
	assert.Equal(t, codes.ResponseEndSessionAck, m.ResponseCode())
}

func TestEndSessionResponseRoundTrip(t *testing.T) {
	m := &EndSessionResponse{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x6C}}}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 EndSessionResponse
	require.NoError(t, m2.Unmarshal(data))
	require.Equal(t, m.Header, m2.Header)
}

func TestEndSessionResponseUnmarshalShort(t *testing.T) {
	var m EndSessionResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal([]byte{0x12}))
}

// --- Short buffer tests for remaining Unmarshal branches ---

func TestKeyExchangeUnmarshalRoundTrip(t *testing.T) {
	m := &KeyExchange{
		Header:        MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xE4, Param1: 0xFF, Param2: 0x02}},
		ReqSessionID:  0xABCD,
		SessionPolicy: 0x03,
	}
	for i := range m.RandomData {
		m.RandomData[i] = byte(i)
	}
	data, _ := m.Marshal()
	var m2 KeyExchange
	require.NoError(t, m2.Unmarshal(data[:HeaderSize+4+RandomDataSize]))
	assert.Equal(t, uint16(0xABCD), m2.ReqSessionID)
	require.Equal(t, m.RandomData, m2.RandomData)
}

func TestKeyExchangeUnmarshalShort(t *testing.T) {
	var m KeyExchange
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize+4)))
}

func TestKeyExchangeResponseRoundTrip(t *testing.T) {
	m := &KeyExchangeResponse{
		Header:                 MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x64}},
		RspSessionID:           0x5678,
		MutAuthRequested:       MutAuthRequested,
		ReqSlotIDParam:         0x02,
		ExchangeData:           bytes.Repeat([]byte{0xBB}, 32),
		MeasurementSummaryHash: bytes.Repeat([]byte{0xCC}, 32),
		OpaqueData:             []byte{0x01, 0x02},
		Signature:              bytes.Repeat([]byte{0xDD}, 64),
		VerifyData:             bytes.Repeat([]byte{0xEE}, 32),
	}
	for i := range m.RandomData {
		m.RandomData[i] = byte(i)
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	assert.Equal(t, codes.ResponseKeyExchangeRsp, m.ResponseCode())
	var m2 KeyExchangeResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint16(0x5678), m2.RspSessionID)
	assert.Equal(t, uint8(MutAuthRequested), m2.MutAuthRequested)
}

func TestKeyExchangeResponseUnmarshalShort(t *testing.T) {
	var m KeyExchangeResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize+4)))
}

func TestChallengeAuthResponseRoundTrip(t *testing.T) {
	certHash := bytes.Repeat([]byte{0x11}, 32)
	measHash := bytes.Repeat([]byte{0x22}, 32)
	opaque := []byte{0xAA, 0xBB}
	sig := bytes.Repeat([]byte{0x33}, 64)
	m := &ChallengeAuthResponse{
		Header:                 MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x03, Param1: 0x01}},
		CertChainHash:          certHash,
		MeasurementSummaryHash: measHash,
		OpaqueData:             opaque,
		Signature:              sig,
	}
	for i := range m.Nonce {
		m.Nonce[i] = byte(i)
	}
	for i := range m.RequesterContext {
		m.RequesterContext[i] = byte(i + 10)
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	assert.Equal(t, codes.ResponseChallengeAuth, m.ResponseCode())
	assert.Equal(t, uint8(1), m.SlotID())
	var m2 ChallengeAuthResponse
	require.NoError(t, m2.UnmarshalWithSizes(data, 32, 32, 64))
	require.Equal(t, certHash, m2.CertChainHash, "cert hash mismatch")
	require.Equal(t, sig, m2.Signature, "sig mismatch")
}

func TestChallengeAuthResponseUnmarshalShort(t *testing.T) {
	var m ChallengeAuthResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal([]byte{0x12}))
	// Valid header-only unmarshal
	h5 := &MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x03}}
	hdr, _ := h5.Marshal()
	require.NoError(t, m.Unmarshal(hdr))
}

func TestChallengeUnmarshalShort(t *testing.T) {
	var m Challenge
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize+NonceSize-1)))
}

func TestChallengeAccessors(t *testing.T) {
	m := &Challenge{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{Param1: 0x02, Param2: 0xFF}}}
	assert.Equal(t, codes.RequestChallenge, m.RequestCode())
	assert.Equal(t, uint8(2), m.SlotID())
	assert.Equal(t, uint8(0xFF), m.HashType())
}

func TestVersionResponseUnmarshalShort(t *testing.T) {
	// Header present but entry count says 5, not enough data
	data := []byte{0x10, 0x04, 0x00, 0x00, 0x00, 0x05}
	var m VersionResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(data))
}

func TestGetCapabilitiesShortUnmarshal(t *testing.T) {
	// Only 8 bytes - enough for short form but not 1.2 fields
	var m GetCapabilities
	data := make([]byte, HeaderSize+8)
	data[0] = 0x12
	data[1] = 0xE1
	data[5] = 10 // CTExponent
	require.NoError(t, m.Unmarshal(data))
	assert.Equal(t, uint8(10), m.CTExponent)
	assert.Equal(t, uint32(0), m.DataTransferSize)
}

func TestGetCapabilitiesUnmarshalTooShort(t *testing.T) {
	var m GetCapabilities
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize+2)))
}

func TestCapabilitiesResponseUnmarshalTooShort(t *testing.T) {
	var m CapabilitiesResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize+2)))
}

func TestCapabilitiesResponseShortUnmarshal(t *testing.T) {
	var m CapabilitiesResponse
	data := make([]byte, HeaderSize+12)
	data[0] = 0x12
	data[5] = 8
	require.NoError(t, m.Unmarshal(data))
	assert.Equal(t, uint8(8), m.CTExponent)
}

func TestNegotiateAlgorithmsUnmarshalShort(t *testing.T) {
	var m NegotiateAlgorithms
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize+20)))
}

func TestNegotiateAlgorithmsUnmarshalShortAlgStruct(t *testing.T) {
	// Param1 says 1 struct but data ends right after fixed
	data := make([]byte, HeaderSize+28)
	data[0] = 0x12
	data[2] = 1 // Param1 = 1 struct
	var m NegotiateAlgorithms
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(data))
}

func TestAlgorithmsResponseUnmarshalShort(t *testing.T) {
	var m AlgorithmsResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize+28)))
}

func TestAlgorithmsResponseUnmarshalShortAlgStruct(t *testing.T) {
	data := make([]byte, HeaderSize+32)
	data[0] = 0x12
	data[2] = 1
	var m AlgorithmsResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(data))
}

func TestGetCertificateUnmarshalShort(t *testing.T) {
	var m GetCertificate
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize+2)))
}

func TestCertificateResponseUnmarshalShortChain(t *testing.T) {
	// PortionLength says 100 but only header+4 bytes present
	data := make([]byte, HeaderSize+4)
	data[0] = 0x12
	data[4] = 100 // portionLength low byte
	var m CertificateResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(data))
}

func TestCertificateResponseAccessors(t *testing.T) {
	m := &CertificateResponse{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{Param1: 0x03}}}
	assert.Equal(t, codes.ResponseCertificate, m.ResponseCode())
	assert.Equal(t, uint8(3), m.SlotID())
}

func TestGetCertificateRequestCode(t *testing.T) {
	m := &GetCertificate{}
	assert.Equal(t, codes.RequestGetCertificate, m.RequestCode())
}

func TestChunkSendNonZeroSeq(t *testing.T) {
	m := &ChunkSend{
		Header:     MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x85, Param1: ChunkSendAttrLastChunk}},
		ChunkSeqNo: 5,
		Chunk:      []byte{0x01, 0x02},
	}
	assert.Equal(t, codes.RequestChunkSend, m.RequestCode())
	assert.True(t, m.IsLastChunk())
	data, _ := m.Marshal()
	var m2 ChunkSend
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint16(5), m2.ChunkSeqNo)
	assert.Equal(t, uint32(0), m2.LargeMessageSize)
}

func TestChunkSendUnmarshalShortLargeMsg(t *testing.T) {
	// SeqNo=0 but not enough data for LargeMessageSize
	data := make([]byte, HeaderSize+8)
	data[0] = 0x12
	// ChunkSeqNo=0 (default), ChunkSize=0
	var m ChunkSend
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(data))
}

func TestChunkSendUnmarshalShortChunk(t *testing.T) {
	data := make([]byte, HeaderSize+12)
	data[0] = 0x12
	data[4] = 1  // ChunkSeqNo=1 (non-zero, no LargeMessageSize)
	data[8] = 99 // ChunkSize=99 but only 0 bytes of chunk
	var m ChunkSend
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(data))
}

func TestChunkSendAckRoundTrip(t *testing.T) {
	m := &ChunkSendAck{
		Header:     MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x05}},
		ChunkSeqNo: 3,
		Response:   []byte{0xAA, 0xBB},
	}
	assert.Equal(t, codes.ResponseChunkSendAck, m.ResponseCode())
	data, _ := m.Marshal()
	var m2 ChunkSendAck
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint16(3), m2.ChunkSeqNo)
	require.Equal(t, []byte{0xAA, 0xBB}, m2.Response, "response mismatch")
}

func TestChunkSendAckNoResponse(t *testing.T) {
	m := &ChunkSendAck{
		Header:     MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x05}},
		ChunkSeqNo: 0,
	}
	data, _ := m.Marshal()
	var m2 ChunkSendAck
	require.NoError(t, m2.Unmarshal(data))
	assert.Nil(t, m2.Response)
}

func TestChunkSendAckUnmarshalShort(t *testing.T) {
	var m ChunkSendAck
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize)))
}

func TestChunkGetUnmarshalShort(t *testing.T) {
	var m ChunkGet
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize)))
}

func TestChunkGetRequestCode(t *testing.T) {
	m := &ChunkGet{}
	assert.Equal(t, codes.RequestChunkGet, m.RequestCode())
}

func TestChunkResponseRoundTrip(t *testing.T) {
	m := &ChunkResponse{
		Header:           MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x06, Param1: ChunkResponseAttrLastChunk}},
		ChunkSeqNo:       0,
		LargeMessageSize: 200,
		Chunk:            []byte{0x01, 0x02, 0x03},
	}
	assert.Equal(t, codes.ResponseChunkResponse, m.ResponseCode())
	assert.True(t, m.IsLastChunk())
	data, _ := m.Marshal()
	var m2 ChunkResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint32(200), m2.LargeMessageSize)
	require.Equal(t, []byte{0x01, 0x02, 0x03}, m2.Chunk, "chunk mismatch")
}

func TestChunkResponseNonZeroSeq(t *testing.T) {
	m := &ChunkResponse{
		Header:     MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x06}},
		ChunkSeqNo: 2,
		Chunk:      []byte{0xFF},
	}
	data, _ := m.Marshal()
	var m2 ChunkResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint32(0), m2.LargeMessageSize)
}

func TestChunkResponseUnmarshalShort(t *testing.T) {
	var m ChunkResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize+4)))
}

func TestChunkResponseUnmarshalShortLargeMsg(t *testing.T) {
	data := make([]byte, HeaderSize+8)
	data[0] = 0x12
	var m ChunkResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(data))
}

func TestChunkResponseUnmarshalShortChunk(t *testing.T) {
	data := make([]byte, HeaderSize+12)
	data[0] = 0x12
	data[4] = 1
	data[8] = 50
	var m ChunkResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(data))
}

func TestGetCSRRequestCode(t *testing.T) {
	m := &GetCSR{}
	assert.Equal(t, codes.RequestGetCSR, m.RequestCode())
}

func TestGetCSRUnmarshalShort(t *testing.T) {
	var m GetCSR
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize+2)))
}

func TestGetCSRUnmarshalShortVarFields(t *testing.T) {
	data := make([]byte, HeaderSize+4)
	data[0] = 0x12
	data[4] = 50 // requesterInfoLen=50
	var m GetCSR
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(data))
}

func TestCSRResponseCode(t *testing.T) {
	m := &CSRResponse{}
	assert.Equal(t, codes.ResponseCSR, m.ResponseCode())
}

func TestCSRResponseUnmarshalShort(t *testing.T) {
	var m CSRResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize+2)))
}

func TestCSRResponseUnmarshalShortCSR(t *testing.T) {
	data := make([]byte, HeaderSize+4)
	data[0] = 0x12
	data[4] = 100 // CSRLength=100
	var m CSRResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(data))
}

func TestSetCertificateRoundTrip(t *testing.T) {
	chain := []byte{0x30, 0x82, 0x01, 0x00}
	m := &SetCertificate{
		Header:    MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xEE, Param1: 0x02}},
		CertChain: chain,
	}
	assert.Equal(t, codes.RequestSetCertificate, m.RequestCode())
	assert.Equal(t, uint8(2), m.SlotID())
	data, _ := m.Marshal()
	var m2 SetCertificate
	require.NoError(t, m2.Unmarshal(data))
	require.Equal(t, chain, m2.CertChain, "chain mismatch")
}

func TestSetCertificateEmpty(t *testing.T) {
	m := &SetCertificate{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12}}}
	data, _ := m.Marshal()
	var m2 SetCertificate
	require.NoError(t, m2.Unmarshal(data))
	assert.Nil(t, m2.CertChain, "expected nil chain")
}

func TestSetCertificateResponseRoundTrip(t *testing.T) {
	m := &SetCertificateResponse{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x6E}}}
	assert.Equal(t, codes.ResponseSetCertificateRsp, m.ResponseCode())
	data, _ := m.Marshal()
	var m2 SetCertificateResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, m.Header, m2.Header)
}

func TestGetDigestsRoundTrip(t *testing.T) {
	m := &GetDigests{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x81}}}
	assert.Equal(t, codes.RequestGetDigests, m.RequestCode())
	data, _ := m.Marshal()
	var m2 GetDigests
	require.NoError(t, m2.Unmarshal(data))
}

func TestDigestResponseAccessors(t *testing.T) {
	m := &DigestResponse{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{Param2: 0x05}}}
	assert.Equal(t, codes.ResponseDigests, m.ResponseCode())
	assert.Equal(t, uint8(0x05), m.SlotMask())
}

func TestDigestResponseUnmarshalHeaderOnly(t *testing.T) {
	h := &MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x01, Param2: 0x03}}
	hdr, _ := h.Marshal()
	var m DigestResponse
	require.NoError(t, m.Unmarshal(hdr))
}

func TestDigestResponseUnmarshalShort(t *testing.T) {
	var m DigestResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal([]byte{0x12}))
}

func TestDigestResponseUnmarshalWithDigestSizeShort(t *testing.T) {
	h2 := &MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x01, Param2: 0x03}}
	hdr, _ := h2.Marshal()
	var m DigestResponse
	assert.Equal(t, ErrShortBuffer, m.UnmarshalWithDigestSize(hdr, 32))
	assert.Equal(t, ErrShortBuffer, m.UnmarshalWithDigestSize([]byte{0x12}, 32))
}

func TestErrorResponseAccessors(t *testing.T) {
	m := &ErrorResponse{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{Param1: 0x05, Param2: 0x07}}}
	assert.Equal(t, codes.ResponseError, m.ResponseCode())
	assert.Equal(t, uint8(0x07), m.ErrorData())
}

func TestErrorResponseNoExtData(t *testing.T) {
	h3 := &MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x7F, Param1: 0x01}}
	hdr, _ := h3.Marshal()
	var m ErrorResponse
	require.NoError(t, m.Unmarshal(hdr))
	assert.Nil(t, m.ExtErrorData)
}

func TestErrorResponseLargeExtData(t *testing.T) {
	h4 := &MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x7F}}
	hdr, _ := h4.Marshal()
	data := append(hdr, bytes.Repeat([]byte{0xFF}, 40)...)
	var m ErrorResponse
	require.NoError(t, m.Unmarshal(data))
	assert.Len(t, m.ExtErrorData, 32)
}

func TestResponseNotReadyDataRoundTrip(t *testing.T) {
	d := &ResponseNotReadyData{RDExponent: 10, RequestCode: 0x81, Token: 0x42, RDTM: 0x05}
	data := d.Marshal()
	var d2 ResponseNotReadyData
	require.NoError(t, d2.Unmarshal(data))
	assert.Equal(t, uint8(10), d2.RDExponent)
	assert.Equal(t, uint8(0x81), d2.RequestCode)
	assert.Equal(t, uint8(0x42), d2.Token)
	assert.Equal(t, uint8(0x05), d2.RDTM)
}

func TestResponseNotReadyDataUnmarshalShort(t *testing.T) {
	var d ResponseNotReadyData
	assert.Equal(t, ErrShortBuffer, d.Unmarshal([]byte{1, 2}))
}

func TestRespondIfReadyRoundTrip(t *testing.T) {
	m := &RespondIfReady{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xFF, Param1: 0x81, Param2: 0x42}}}
	assert.Equal(t, codes.RequestRespondIfReady, m.RequestCode())
	data, _ := m.Marshal()
	var m2 RespondIfReady
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, m.Header, m2.Header)
}

func TestVendorDefinedResponseRoundTrip(t *testing.T) {
	m := &VendorDefinedResponse{
		Header:     MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x7E}},
		StandardID: 0x0001,
		VendorID:   []byte{0xAB, 0xCD},
		Payload:    []byte{0x01, 0x02, 0x03},
	}
	assert.Equal(t, codes.ResponseVendorDefined, m.ResponseCode())
	data, _ := m.Marshal()
	var m2 VendorDefinedResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint16(0x0001), m2.StandardID)
	require.Equal(t, m.VendorID, m2.VendorID, "vendor ID")
	require.Equal(t, m.Payload, m2.Payload, "payload")
}

func TestVendorDefinedResponseUnmarshalShort(t *testing.T) {
	var m VendorDefinedResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize+2)))
}

func TestVendorDefinedResponseUnmarshalShortVendorID(t *testing.T) {
	data := make([]byte, HeaderSize+3)
	data[0] = 0x12
	data[6] = 10 // vendorLen=10
	var m VendorDefinedResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(data))
}

func TestVendorDefinedResponseUnmarshalShortPayload(t *testing.T) {
	data := make([]byte, HeaderSize+5)
	data[0] = 0x12
	data[6] = 0             // vendorLen=0
	data[HeaderSize+3] = 50 // payloadLen=50
	var m VendorDefinedResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(data))
}

func TestVendorDefinedRequestUnmarshalShort(t *testing.T) {
	var m VendorDefinedRequest
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize+2)))
}

func TestVendorDefinedRequestUnmarshalShortVendorID(t *testing.T) {
	data := make([]byte, HeaderSize+3)
	data[0] = 0x12
	data[6] = 10
	var m VendorDefinedRequest
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(data))
}

func TestVendorDefinedRequestUnmarshalShortPayload(t *testing.T) {
	data := make([]byte, HeaderSize+5)
	data[0] = 0x12
	data[6] = 0
	data[HeaderSize+3] = 50
	var m VendorDefinedRequest
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(data))
}

func TestVendorDefinedRequestRequestCode(t *testing.T) {
	m := &VendorDefinedRequest{}
	assert.Equal(t, codes.RequestVendorDefined, m.RequestCode())
}

func TestGetVersionRequestCode(t *testing.T) {
	m := &GetVersion{}
	assert.Equal(t, codes.RequestGetVersion, m.RequestCode())
}

func TestVersionResponseCode(t *testing.T) {
	m := &VersionResponse{}
	assert.Equal(t, codes.ResponseVersion, m.ResponseCode())
}

func TestGetCapabilitiesRequestCode(t *testing.T) {
	m := &GetCapabilities{}
	assert.Equal(t, codes.RequestGetCapabilities, m.RequestCode())
}

func TestCapabilitiesResponseCode(t *testing.T) {
	m := &CapabilitiesResponse{}
	assert.Equal(t, codes.ResponseCapabilities, m.ResponseCode())
}

func TestNegotiateAlgorithmsRequestCode(t *testing.T) {
	m := &NegotiateAlgorithms{}
	assert.Equal(t, codes.RequestNegotiateAlgorithms, m.RequestCode())
}

func TestAlgorithmsResponseCode(t *testing.T) {
	m := &AlgorithmsResponse{}
	assert.Equal(t, codes.ResponseAlgorithms, m.ResponseCode())
}

func TestKeyExchangeAccessors(t *testing.T) {
	m := &KeyExchange{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{Param1: 0xFF, Param2: 0x03}}}
	assert.Equal(t, codes.RequestKeyExchange, m.RequestCode())
	assert.Equal(t, uint8(3), m.SlotID())
	assert.Equal(t, uint8(0xFF), m.HashType())
}

func TestKeyExchangeUnmarshalWithDHESizeShort(t *testing.T) {
	var m KeyExchange
	assert.Equal(t, ErrShortBuffer, m.UnmarshalWithDHESize(make([]byte, HeaderSize+4), 32))
}

func TestFinishResponseUnmarshalWithLargeHash(t *testing.T) {
	verify := bytes.Repeat([]byte{0xAA}, 64)
	m := &FinishResponse{
		Header:     MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x65}},
		VerifyData: verify,
	}
	data, _ := m.Marshal()
	var m2 FinishResponse
	require.NoError(t, m2.UnmarshalWithHashSize(data, 64))
	require.Equal(t, verify, m2.VerifyData, "mismatch")
}

// --- Advanced message tests ---

func TestGetMeasurementExtensionLogRoundTrip(t *testing.T) {
	m := &GetMeasurementExtensionLog{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xEB}},
		Offset: 100,
		Length: 256,
	}
	assert.Equal(t, codes.RequestGetMeasurementExtensionLog, m.RequestCode())
	data, _ := m.Marshal()
	var m2 GetMeasurementExtensionLog
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint32(100), m2.Offset)
	assert.Equal(t, uint32(256), m2.Length)
}

func TestGetMeasurementExtensionLogUnmarshalShort(t *testing.T) {
	var m GetMeasurementExtensionLog
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize+4)))
}

func TestMeasurementExtensionLogResponseRoundTrip(t *testing.T) {
	mel := bytes.Repeat([]byte{0xAB}, 50)
	m := &MeasurementExtensionLogResponse{
		Header:          MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x6B}},
		RemainderLength: 200,
		MEL:             mel,
	}
	assert.Equal(t, codes.ResponseMeasurementExtensionLog, m.ResponseCode())
	data, _ := m.Marshal()
	var m2 MeasurementExtensionLogResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint32(50), m2.PortionLength)
	assert.Equal(t, uint32(200), m2.RemainderLength)
	require.Equal(t, mel, m2.MEL, "MEL mismatch")
}

func TestMeasurementExtensionLogResponseUnmarshalShort(t *testing.T) {
	var m MeasurementExtensionLogResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize+4)))
}

func TestMeasurementExtensionLogResponseUnmarshalShortMEL(t *testing.T) {
	data := make([]byte, HeaderSize+8)
	data[0] = 0x12
	data[HeaderSize] = 50 // portionLength=50
	var m MeasurementExtensionLogResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(data))
}

func TestGetKeyPairInfoRoundTrip(t *testing.T) {
	m := &GetKeyPairInfo{
		Header:    MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xF0}},
		KeyPairID: 3,
	}
	assert.Equal(t, codes.RequestGetKeyPairInfo, m.RequestCode())
	data, _ := m.Marshal()
	var m2 GetKeyPairInfo
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint8(3), m2.KeyPairID)
}

func TestGetKeyPairInfoUnmarshalShort(t *testing.T) {
	var m GetKeyPairInfo
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize)))
}

func TestKeyPairInfoResponseRoundTrip(t *testing.T) {
	pki := []byte{0x30, 0x82, 0x01, 0x22}
	m := &KeyPairInfoResponse{
		Header:               MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x70}},
		TotalKeyPairs:        5,
		KeyPairID:            2,
		Capabilities:         0x0003,
		KeyUsageCapabilities: 0x0001,
		CurrentKeyUsage:      0x0001,
		AsymAlgoCapabilities: 0x00000010,
		CurrentAsymAlgo:      0x00000010,
		PublicKeyInfoLen:     4,
		AssocCertSlotMask:    0x01,
		PublicKeyInfo:        pki,
	}
	assert.Equal(t, codes.ResponseKeyPairInfo, m.ResponseCode())
	data, _ := m.Marshal()
	var m2 KeyPairInfoResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint8(5), m2.TotalKeyPairs)
	assert.Equal(t, uint8(2), m2.KeyPairID)
	require.Equal(t, pki, m2.PublicKeyInfo, "PKI mismatch")
}

func TestKeyPairInfoResponseUnmarshalShort(t *testing.T) {
	var m KeyPairInfoResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize+10)))
}

func TestKeyPairInfoResponseUnmarshalShortPKI(t *testing.T) {
	data := make([]byte, HeaderSize+19)
	data[0] = 0x12
	data[HeaderSize+16] = 50 // PublicKeyInfoLen=50
	var m KeyPairInfoResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(data))
}

func TestGetEndpointInfoRoundTrip(t *testing.T) {
	m := &GetEndpointInfo{
		Header:            MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xEA}},
		RequestAttributes: 0x00,
	}
	assert.Equal(t, codes.RequestGetEndpointInfo, m.RequestCode())
	data, _ := m.Marshal()
	var m2 GetEndpointInfo
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint8(0), m2.RequestAttributes)
}

func TestGetEndpointInfoWithNonce(t *testing.T) {
	m := &GetEndpointInfo{
		Header:            MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xEA}},
		RequestAttributes: 0x01,
	}
	for i := range m.Nonce {
		m.Nonce[i] = byte(i)
	}
	data, _ := m.Marshal()
	require.Len(t, data, HeaderSize+4+NonceSize)
	var m2 GetEndpointInfo
	require.NoError(t, m2.Unmarshal(data))
	require.Equal(t, m.Nonce, m2.Nonce)
}

func TestGetEndpointInfoUnmarshalShort(t *testing.T) {
	var m GetEndpointInfo
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize+2)))
}

func TestParseMeasurementBlocksShortHeader(t *testing.T) {
	_, err := ParseMeasurementBlocks([]byte{0x01, 0x02})
	assert.Equal(t, ErrShortBuffer, err)
}

func TestParseMeasurementBlocksShortBody(t *testing.T) {
	record := []byte{0x01, 0x01, 0x50, 0x00}
	_, err := ParseMeasurementBlocks(record)
	assert.Equal(t, ErrShortBuffer, err)
}

func TestParseMeasurementBlocksInvalidValueSize(t *testing.T) {
	// measSize=3 but valueSize claims 10
	record := []byte{0x01, 0x01, 0x03, 0x00, 0x01, 0x0A, 0x00}
	_, err := ParseMeasurementBlocks(record)
	assert.Equal(t, ErrInvalidField, err)
}

func TestParseMeasurementBlocksSmallMeasSize(t *testing.T) {
	// measSize < 3
	record := []byte{0x01, 0x01, 0x02, 0x00, 0xAA, 0xBB}
	blocks, err := ParseMeasurementBlocks(record)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	assert.Equal(t, uint8(0), blocks[0].ValueType, "expected zero value type for small meas")
}
