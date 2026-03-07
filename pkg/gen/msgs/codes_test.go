package msgs

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

// ---------------------------------------------------------------------------
// version.go
// ---------------------------------------------------------------------------

func TestGetVersion_RequestCode(t *testing.T) {
	m := &GetVersion{}
	assert.Equal(t, codes.RequestGetVersion, m.RequestCode())
}

func TestVersionResponse_ResponseCode(t *testing.T) {
	m := &VersionResponse{}
	assert.Equal(t, codes.ResponseVersion, m.ResponseCode())
}

func TestVersionResponse_UnmarshalShortHeader(t *testing.T) {
	var m VersionResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal([]byte{0x10, 0x04}))
}

func TestVersionResponse_UnmarshalShortEntries(t *testing.T) {
	// Header(4) + reserved(1) + count(1) = 6 bytes, count says 2 entries but no entry data
	data := []byte{0x10, 0x04, 0x00, 0x00, 0x00, 0x02}
	var m VersionResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(data))
}

// ---------------------------------------------------------------------------
// capabilities.go
// ---------------------------------------------------------------------------

func TestGetCapabilities_RequestCode(t *testing.T) {
	m := &GetCapabilities{}
	assert.Equal(t, codes.RequestGetCapabilities, m.RequestCode())
}

func TestCapabilitiesResponse_ResponseCode(t *testing.T) {
	m := &CapabilitiesResponse{}
	assert.Equal(t, codes.ResponseCapabilities, m.ResponseCode())
}

func TestCapabilitiesResponse_UnmarshalHeaderOnly(t *testing.T) {
	// 12 bytes: header(4) + reserved(1) + ct_exp(1) + ext_flags(2) + flags(4)
	// No 1.2 fields (DataTransferSize, MaxSPDMmsgSize).
	data := make([]byte, HeaderSize+4+4) // 12 bytes
	data[0] = 0x11
	data[1] = 0x61
	data[5] = 7 // CTExponent
	binary.LittleEndian.PutUint32(data[8:], 0x1234)
	var m CapabilitiesResponse
	require.NoError(t, m.Unmarshal(data))
	assert.Equal(t, uint8(7), m.CTExponent)
	assert.Equal(t, uint32(0x1234), m.Flags)
	assert.Equal(t, uint32(0), m.DataTransferSize, "1.2 fields should be zero when not present")
	assert.Equal(t, uint32(0), m.MaxSPDMmsgSize, "1.2 fields should be zero when not present")
}

func TestGetCapabilities_UnmarshalHeaderOnly(t *testing.T) {
	data := make([]byte, HeaderSize+4+4)
	data[0] = 0x11
	data[1] = 0xE1
	data[5] = 5
	var m GetCapabilities
	require.NoError(t, m.Unmarshal(data))
	assert.Equal(t, uint32(0), m.DataTransferSize, "1.2 fields should be zero")
	assert.Equal(t, uint32(0), m.MaxSPDMmsgSize, "1.2 fields should be zero")
}

func TestCapabilitiesResponse_UnmarshalTooShort(t *testing.T) {
	var m CapabilitiesResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal([]byte{0x12, 0x61, 0x00}))
}

// ---------------------------------------------------------------------------
// algorithms.go
// ---------------------------------------------------------------------------

func TestNegotiateAlgorithms_RequestCode(t *testing.T) {
	m := &NegotiateAlgorithms{}
	assert.Equal(t, codes.RequestNegotiateAlgorithms, m.RequestCode())
}

func TestAlgorithmsResponse_ResponseCode(t *testing.T) {
	m := &AlgorithmsResponse{}
	assert.Equal(t, codes.ResponseAlgorithms, m.ResponseCode())
}

func TestNegotiateAlgorithms_UnmarshalShortAlgStructs(t *testing.T) {
	// Build valid fixed header (32 bytes) but claim 1 alg struct with insufficient data
	data := make([]byte, 32) // exactly fixedSize, no room for alg struct
	data[0] = 0x12
	data[1] = 0xE3
	data[2] = 1 // Param1 = 1 alg struct
	var m NegotiateAlgorithms
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(data))
}

func TestAlgorithmsResponse_UnmarshalShortAlgStructs(t *testing.T) {
	data := make([]byte, 36) // exactly fixedSize, no room for alg struct
	data[0] = 0x12
	data[1] = 0x63
	data[2] = 1 // Param1 = 1 alg struct
	var m AlgorithmsResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(data))
}

func TestAlgorithmsResponse_UnmarshalTooShort(t *testing.T) {
	var m AlgorithmsResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, 10)))
}

func TestNegotiateAlgorithms_UnmarshalTooShort(t *testing.T) {
	var m NegotiateAlgorithms
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, 10)))
}

// ---------------------------------------------------------------------------
// digests.go
// ---------------------------------------------------------------------------

func TestGetDigests_RequestCode(t *testing.T) {
	m := &GetDigests{}
	assert.Equal(t, codes.RequestGetDigests, m.RequestCode())
}

func TestGetDigests_MarshalUnmarshal(t *testing.T) {
	m := &GetDigests{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x81}}}
	data, err := m.Marshal()
	require.NoError(t, err)
	require.Len(t, data, HeaderSize)
	var m2 GetDigests
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, m.Header, m2.Header)
}

func TestGetDigests_UnmarshalShort(t *testing.T) {
	var m GetDigests
	assert.Equal(t, ErrShortBuffer, m.Unmarshal([]byte{0x12}))
}

func TestDigestResponse_ResponseCode(t *testing.T) {
	m := &DigestResponse{}
	assert.Equal(t, codes.ResponseDigests, m.ResponseCode())
}

func TestDigestResponse_SlotMask(t *testing.T) {
	m := &DigestResponse{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{Param2: 0x07}}}
	assert.Equal(t, uint8(0x07), m.SlotMask())
}

func TestDigestResponse_UnmarshalShort(t *testing.T) {
	var m DigestResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal([]byte{0x12}))
}

func TestDigestResponse_UnmarshalWithDigestSizeShortHeader(t *testing.T) {
	var m DigestResponse
	assert.Equal(t, ErrShortBuffer, m.UnmarshalWithDigestSize([]byte{0x12}, 32))
}

func TestDigestResponse_UnmarshalWithDigestSizeShortDigests(t *testing.T) {
	// Header says 2 slots (Param2=0x03) but only 1 digest worth of data
	data := make([]byte, HeaderSize+32) // only 1 digest, need 2
	data[0] = 0x12
	data[1] = 0x01
	data[3] = 0x03 // Param2 = 2 bits set
	var m DigestResponse
	assert.Equal(t, ErrShortBuffer, m.UnmarshalWithDigestSize(data, 32))
}

// ---------------------------------------------------------------------------
// certificate.go
// ---------------------------------------------------------------------------

func TestGetCertificate_RequestCode(t *testing.T) {
	m := &GetCertificate{}
	assert.Equal(t, codes.RequestGetCertificate, m.RequestCode())
}

func TestCertificateResponse_ResponseCode(t *testing.T) {
	m := &CertificateResponse{}
	assert.Equal(t, codes.ResponseCertificate, m.ResponseCode())
}

func TestGetCertificate_SlotID(t *testing.T) {
	m := &GetCertificate{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{Param1: 0xF3}}}
	assert.Equal(t, uint8(0x03), m.SlotID())
}

func TestCertificateResponse_SlotID(t *testing.T) {
	m := &CertificateResponse{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{Param1: 0xA5}}}
	assert.Equal(t, uint8(0x05), m.SlotID())
}

func TestGetCertificate_UnmarshalShort(t *testing.T) {
	var m GetCertificate
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize+2)))
}

func TestCertificateResponse_UnmarshalShortHeader(t *testing.T) {
	var m CertificateResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize+2)))
}

func TestCertificateResponse_UnmarshalShortCertChain(t *testing.T) {
	// Header + PortionLength(2) + RemainderLength(2) present, but PortionLength says 100 bytes
	data := make([]byte, HeaderSize+4)
	data[0] = 0x12
	data[1] = 0x02
	binary.LittleEndian.PutUint16(data[4:], 100) // PortionLength = 100
	binary.LittleEndian.PutUint16(data[6:], 0)
	var m CertificateResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(data))
}

// ---------------------------------------------------------------------------
// challenge.go
// ---------------------------------------------------------------------------

func TestChallenge_RequestCode(t *testing.T) {
	m := &Challenge{}
	assert.Equal(t, codes.RequestChallenge, m.RequestCode())
}

func TestChallenge_SlotID(t *testing.T) {
	m := &Challenge{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{Param1: 0x02}}}
	assert.Equal(t, uint8(0x02), m.SlotID())
}

func TestChallenge_HashType(t *testing.T) {
	m := &Challenge{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{Param2: 0xFF}}}
	assert.Equal(t, uint8(0xFF), m.HashType())
}

func TestChallenge_UnmarshalShort(t *testing.T) {
	var m Challenge
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize+10)))
}

func TestChallengeAuthResponse_ResponseCode(t *testing.T) {
	m := &ChallengeAuthResponse{}
	assert.Equal(t, codes.ResponseChallengeAuth, m.ResponseCode())
}

func TestChallengeAuthResponse_SlotID(t *testing.T) {
	m := &ChallengeAuthResponse{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{Param1: 0xF7}}}
	assert.Equal(t, uint8(0x07), m.SlotID())
}

func TestChallengeAuthResponse_MarshalUnmarshalWithSizes(t *testing.T) {
	digestSize := 32
	measHashSize := 32
	sigSize := 64
	m := &ChallengeAuthResponse{
		Header:                 MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x03, Param1: 0x01}},
		CertChainHash:          bytes.Repeat([]byte{0xAA}, digestSize),
		MeasurementSummaryHash: bytes.Repeat([]byte{0xBB}, measHashSize),
		OpaqueData:             []byte{0x01, 0x02, 0x03},
		Signature:              bytes.Repeat([]byte{0xCC}, sigSize),
	}
	for i := range m.Nonce {
		m.Nonce[i] = byte(i)
	}
	for i := range m.RequesterContext {
		m.RequesterContext[i] = byte(i + 100)
	}

	data, err := m.Marshal()
	require.NoError(t, err)

	var m2 ChallengeAuthResponse
	require.NoError(t, m2.UnmarshalWithSizes(data, digestSize, measHashSize, sigSize))
	assert.Equal(t, m.CertChainHash, m2.CertChainHash)
	assert.Equal(t, m.Nonce, m2.Nonce)
	assert.Equal(t, m.MeasurementSummaryHash, m2.MeasurementSummaryHash)
	assert.Equal(t, m.OpaqueData, m2.OpaqueData)
	assert.Equal(t, m.Signature, m2.Signature)
}

func TestChallengeAuthResponse_UnmarshalShort(t *testing.T) {
	var m ChallengeAuthResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal([]byte{0x12}))
}

func TestChallengeAuthResponse_UnmarshalWithSizes_ShortAtCertChainHash(t *testing.T) {
	data := make([]byte, HeaderSize+10) // too short for digestSize=32
	data[0] = 0x12
	data[1] = 0x03
	var m ChallengeAuthResponse
	assert.Equal(t, ErrShortBuffer, m.UnmarshalWithSizes(data, 32, 32, 64))
}

func TestChallengeAuthResponse_UnmarshalWithSizes_ShortAtNonce(t *testing.T) {
	data := make([]byte, HeaderSize+32+10) // has digest but not nonce
	data[0] = 0x12
	data[1] = 0x03
	var m ChallengeAuthResponse
	assert.Equal(t, ErrShortBuffer, m.UnmarshalWithSizes(data, 32, 32, 64))
}

func TestChallengeAuthResponse_UnmarshalWithSizes_ShortAtMeasHash(t *testing.T) {
	data := make([]byte, HeaderSize+32+NonceSize+10) // has digest+nonce but not meas hash
	data[0] = 0x12
	data[1] = 0x03
	var m ChallengeAuthResponse
	assert.Equal(t, ErrShortBuffer, m.UnmarshalWithSizes(data, 32, 32, 64))
}

func TestChallengeAuthResponse_UnmarshalWithSizes_ShortAtOpaqueLen(t *testing.T) {
	data := make([]byte, HeaderSize+32+NonceSize+32) // no room for opaque_length
	data[0] = 0x12
	data[1] = 0x03
	var m ChallengeAuthResponse
	assert.Equal(t, ErrShortBuffer, m.UnmarshalWithSizes(data, 32, 32, 64))
}

func TestChallengeAuthResponse_UnmarshalWithSizes_ShortAtOpaqueData(t *testing.T) {
	off := HeaderSize + 32 + NonceSize + 32
	data := make([]byte, off+2) // opaque_length present but says 10 bytes
	data[0] = 0x12
	data[1] = 0x03
	binary.LittleEndian.PutUint16(data[off:], 10) // opaqueLen=10 but no data
	var m ChallengeAuthResponse
	assert.Equal(t, ErrShortBuffer, m.UnmarshalWithSizes(data, 32, 32, 64))
}

func TestChallengeAuthResponse_UnmarshalWithSizes_ShortAtReqContext(t *testing.T) {
	off := HeaderSize + 32 + NonceSize + 32
	data := make([]byte, off+2+2) // opaque_length(2) + opaqueData(0 claimed but 2 actual) - no req context
	data[0] = 0x12
	data[1] = 0x03
	binary.LittleEndian.PutUint16(data[off:], 0) // opaqueLen=0
	var m ChallengeAuthResponse
	assert.Equal(t, ErrShortBuffer, m.UnmarshalWithSizes(data, 32, 32, 64))
}

func TestChallengeAuthResponse_UnmarshalWithSizes_ShortAtSignature(t *testing.T) {
	off := HeaderSize + 32 + NonceSize + 32
	data := make([]byte, off+2+ReqContextSize+10) // has req context but not enough for signature(64)
	data[0] = 0x12
	data[1] = 0x03
	binary.LittleEndian.PutUint16(data[off:], 0) // opaqueLen=0
	var m ChallengeAuthResponse
	assert.Equal(t, ErrShortBuffer, m.UnmarshalWithSizes(data, 32, 32, 64))
}

func TestChallengeAuthResponse_UnmarshalWithSizes_ShortHeader(t *testing.T) {
	var m ChallengeAuthResponse
	assert.Equal(t, ErrShortBuffer, m.UnmarshalWithSizes([]byte{0x12}, 32, 32, 64))
}

// ---------------------------------------------------------------------------
// keyexchange.go
// ---------------------------------------------------------------------------

func TestKeyExchange_RequestCode(t *testing.T) {
	m := &KeyExchange{}
	assert.Equal(t, codes.RequestKeyExchange, m.RequestCode())
}

func TestKeyExchange_SlotID(t *testing.T) {
	m := &KeyExchange{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{Param2: 0x03}}}
	assert.Equal(t, uint8(0x03), m.SlotID())
}

func TestKeyExchange_HashType(t *testing.T) {
	m := &KeyExchange{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{Param1: 0xFF}}}
	assert.Equal(t, uint8(0xFF), m.HashType())
}

func TestKeyExchange_UnmarshalShort(t *testing.T) {
	var m KeyExchange
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize+10)))
}

func TestKeyExchange_UnmarshalWithDHESize_ShortInitial(t *testing.T) {
	// Too short for header+4+random+dhe+2
	data := make([]byte, HeaderSize+4+RandomDataSize)
	data[0] = 0x12
	data[1] = 0xE4
	var m KeyExchange
	assert.Equal(t, ErrShortBuffer, m.UnmarshalWithDHESize(data, 32))
}

func TestKeyExchange_UnmarshalWithDHESize_ShortAtOpaqueData(t *testing.T) {
	dheSize := 32
	minSize := HeaderSize + 4 + RandomDataSize + dheSize + 2
	data := make([]byte, minSize)
	data[0] = 0x12
	data[1] = 0xE4
	// Set opaqueLen=10 but no data follows
	binary.LittleEndian.PutUint16(data[minSize-2:], 10)
	var m KeyExchange
	assert.Equal(t, ErrShortBuffer, m.UnmarshalWithDHESize(data, dheSize))
}

func TestKeyExchangeResponse_ResponseCode(t *testing.T) {
	m := &KeyExchangeResponse{}
	assert.Equal(t, codes.ResponseKeyExchangeRsp, m.ResponseCode())
}

func TestKeyExchangeResponse_MarshalUnmarshal(t *testing.T) {
	m := &KeyExchangeResponse{
		Header:                 MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x64}},
		RspSessionID:           0xABCD,
		MutAuthRequested:       0x01,
		ReqSlotIDParam:         0x02,
		ExchangeData:           bytes.Repeat([]byte{0xDD}, 32),
		MeasurementSummaryHash: bytes.Repeat([]byte{0xEE}, 32),
		OpaqueData:             []byte{0x01, 0x02},
		Signature:              bytes.Repeat([]byte{0xFF}, 64),
		VerifyData:             bytes.Repeat([]byte{0x11}, 32),
	}
	for i := range m.RandomData {
		m.RandomData[i] = byte(i)
	}

	data, err := m.Marshal()
	require.NoError(t, err)

	// Unmarshal parses only header + session fields + random data
	var m2 KeyExchangeResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint16(0xABCD), m2.RspSessionID)
	assert.Equal(t, uint8(0x01), m2.MutAuthRequested)
	assert.Equal(t, m.RandomData, m2.RandomData)
}

func TestKeyExchangeResponse_UnmarshalShort(t *testing.T) {
	var m KeyExchangeResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(make([]byte, HeaderSize+4)))
}

// ---------------------------------------------------------------------------
// error_msg.go
// ---------------------------------------------------------------------------

func TestErrorResponse_ResponseCode(t *testing.T) {
	m := &ErrorResponse{}
	assert.Equal(t, codes.ResponseError, m.ResponseCode())
}

func TestErrorResponse_ErrorCodeTyped(t *testing.T) {
	m := &ErrorResponse{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{Param1: uint8(codes.ErrorResponseNotReady)}}}
	assert.Equal(t, codes.ErrorResponseNotReady, m.ErrorCode())
}

func TestErrorResponse_ErrorData(t *testing.T) {
	m := &ErrorResponse{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{Param2: 0x42}}}
	assert.Equal(t, uint8(0x42), m.ErrorData())
}

func TestErrorResponse_UnmarshalNoExtData(t *testing.T) {
	data := []byte{0x12, 0x7F, 0x03, 0x00} // exactly header, no ext data
	var m ErrorResponse
	require.NoError(t, m.Unmarshal(data))
	assert.Equal(t, codes.ErrorBusy, m.ErrorCode())
	assert.Nil(t, m.ExtErrorData, "ExtErrorData should be nil for header-only")
}

func TestErrorResponse_UnmarshalShort(t *testing.T) {
	var m ErrorResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal([]byte{0x12}))
}

func TestResponseNotReadyData_MarshalUnmarshal(t *testing.T) {
	d := &ResponseNotReadyData{
		RDExponent:  5,
		RequestCode: 0x81,
		Token:       0x42,
		RDTM:        10,
	}
	data := d.Marshal()
	require.Len(t, data, 4)
	assert.Equal(t, []byte{5, 0x81, 0x42, 10}, data)

	var d2 ResponseNotReadyData
	require.NoError(t, d2.Unmarshal(data))
	assert.Equal(t, *d, d2)
}

func TestResponseNotReadyData_UnmarshalShort(t *testing.T) {
	var d ResponseNotReadyData
	assert.Equal(t, ErrShortBuffer, d.Unmarshal([]byte{0x01, 0x02}))
}

func TestRespondIfReady_RequestCode(t *testing.T) {
	m := &RespondIfReady{}
	assert.Equal(t, codes.RequestRespondIfReady, m.RequestCode())
}

func TestRespondIfReady_MarshalUnmarshal(t *testing.T) {
	m := &RespondIfReady{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
		SPDMVersion:         0x12,
		RequestResponseCode: 0xFF,
		Param1:              0x81, // original request code
		Param2:              0x42, // token
	}}}
	data, err := m.Marshal()
	require.NoError(t, err)
	require.Len(t, data, HeaderSize)
	var m2 RespondIfReady
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, m.Header, m2.Header)
}

func TestRespondIfReady_UnmarshalShort(t *testing.T) {
	var m RespondIfReady
	assert.Equal(t, ErrShortBuffer, m.Unmarshal([]byte{0x12}))
}

// ---------------------------------------------------------------------------
// vendor.go
// ---------------------------------------------------------------------------

func TestVendorDefinedRequest_RequestCode(t *testing.T) {
	m := &VendorDefinedRequest{}
	assert.Equal(t, codes.RequestVendorDefined, m.RequestCode())
}

func TestVendorDefinedResponse_ResponseCode(t *testing.T) {
	m := &VendorDefinedResponse{}
	assert.Equal(t, codes.ResponseVendorDefined, m.ResponseCode())
}

func TestVendorDefinedResponse_MarshalUnmarshal(t *testing.T) {
	m := &VendorDefinedResponse{
		Header:     MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x7E}},
		StandardID: 0x0005,
		VendorID:   []byte{0xAA, 0xBB},
		Payload:    []byte{0x01, 0x02, 0x03, 0x04},
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	var m2 VendorDefinedResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint16(0x0005), m2.StandardID)
	assert.Equal(t, m.VendorID, m2.VendorID)
	assert.Equal(t, m.Payload, m2.Payload)
}

func TestVendorDefinedResponse_UnmarshalShortHeader(t *testing.T) {
	var m VendorDefinedResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal([]byte{0x12, 0x7E}))
}

func TestVendorDefinedResponse_UnmarshalShortVendorID(t *testing.T) {
	// Header(4) + StandardID(2) + VendorIDLen(1)=5 but only 7 bytes, vendorLen=5 needs more
	data := make([]byte, HeaderSize+3)
	data[0] = 0x12
	data[1] = 0x7E
	data[HeaderSize+2] = 5 // vendorLen=5 but not enough data
	var m VendorDefinedResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(data))
}

func TestVendorDefinedResponse_UnmarshalShortPayload(t *testing.T) {
	// Header(4) + StandardID(2) + VendorIDLen(1)=0 + PayloadLen(2)=100, but no payload data
	data := make([]byte, HeaderSize+2+1+2) // 9 bytes
	data[0] = 0x12
	data[1] = 0x7E
	data[HeaderSize+2] = 0                                  // vendorLen=0
	binary.LittleEndian.PutUint16(data[HeaderSize+3:], 100) // payloadLen=100
	var m VendorDefinedResponse
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(data))
}

func TestVendorDefinedRequest_UnmarshalShortHeader(t *testing.T) {
	var m VendorDefinedRequest
	assert.Equal(t, ErrShortBuffer, m.Unmarshal([]byte{0x12, 0xFE}))
}

func TestVendorDefinedRequest_UnmarshalShortVendorID(t *testing.T) {
	data := make([]byte, HeaderSize+3)
	data[0] = 0x12
	data[1] = 0xFE
	data[HeaderSize+2] = 10 // vendorLen=10, not enough data
	var m VendorDefinedRequest
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(data))
}

func TestVendorDefinedRequest_UnmarshalShortPayload(t *testing.T) {
	data := make([]byte, HeaderSize+2+1+2)
	data[0] = 0x12
	data[1] = 0xFE
	data[HeaderSize+2] = 0
	binary.LittleEndian.PutUint16(data[HeaderSize+3:], 50)
	var m VendorDefinedRequest
	assert.Equal(t, ErrShortBuffer, m.Unmarshal(data))
}
