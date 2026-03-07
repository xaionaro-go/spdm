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
// encapsulation.go: GetEncapsulatedRequest
// ---------------------------------------------------------------------------

func TestGetEncapsulatedRequest_RequestCode(t *testing.T) {
	m := &GetEncapsulatedRequest{}
	assert.Equal(t, codes.RequestGetEncapsulatedRequest, m.RequestCode())
}

func TestGetEncapsulatedRequest_RoundTrip(t *testing.T) {
	m := &GetEncapsulatedRequest{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xEA, Param1: 0x01, Param2: 0x02}},
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	require.Len(t, data, HeaderSize)

	var m2 GetEncapsulatedRequest
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, m.Header, m2.Header)
}

func TestGetEncapsulatedRequest_ShortBuffer(t *testing.T) {
	var m GetEncapsulatedRequest
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize-1)), ErrShortBuffer))
}

// ---------------------------------------------------------------------------
// encapsulation.go: EncapsulatedRequestResponse
// ---------------------------------------------------------------------------

func TestEncapsulatedRequestResponse_ResponseCode(t *testing.T) {
	m := &EncapsulatedRequestResponse{}
	assert.Equal(t, codes.ResponseEncapsulatedRequest, m.ResponseCode())
}

func TestEncapsulatedRequestResponse_RoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte{0xAB}, 64)
	m := &EncapsulatedRequestResponse{
		Header:           MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x6A, Param1: 0x01}},
		EncapsulatedData: payload,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	require.Len(t, data, HeaderSize+len(payload))

	var m2 EncapsulatedRequestResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, m.Header, m2.Header)
	assert.Equal(t, payload, m2.EncapsulatedData)
}

func TestEncapsulatedRequestResponse_Empty(t *testing.T) {
	m := &EncapsulatedRequestResponse{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x6A}},
	}
	data, err := m.Marshal()
	require.NoError(t, err)

	var m2 EncapsulatedRequestResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Nil(t, m2.EncapsulatedData)
}

func TestEncapsulatedRequestResponse_ShortBuffer(t *testing.T) {
	var m EncapsulatedRequestResponse
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize-1)), ErrShortBuffer))
}

// ---------------------------------------------------------------------------
// encapsulation.go: DeliverEncapsulatedResponse
// ---------------------------------------------------------------------------

func TestDeliverEncapsulatedResponse_RequestCode(t *testing.T) {
	m := &DeliverEncapsulatedResponse{}
	assert.Equal(t, codes.RequestDeliverEncapsulatedResponse, m.RequestCode())
}

func TestDeliverEncapsulatedResponse_RoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte{0xCD}, 48)
	m := &DeliverEncapsulatedResponse{
		Header:           MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xEB, Param1: 0x03}},
		EncapsulatedData: payload,
	}
	data, err := m.Marshal()
	require.NoError(t, err)

	var m2 DeliverEncapsulatedResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, m.Header, m2.Header)
	assert.Equal(t, payload, m2.EncapsulatedData)
}

func TestDeliverEncapsulatedResponse_Empty(t *testing.T) {
	m := &DeliverEncapsulatedResponse{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xEB}},
	}
	data, err := m.Marshal()
	require.NoError(t, err)

	var m2 DeliverEncapsulatedResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Nil(t, m2.EncapsulatedData)
}

func TestDeliverEncapsulatedResponse_ShortBuffer(t *testing.T) {
	var m DeliverEncapsulatedResponse
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize-1)), ErrShortBuffer))
}

// ---------------------------------------------------------------------------
// encapsulation.go: EncapsulatedResponseAck
// ---------------------------------------------------------------------------

func TestEncapsulatedResponseAck_ResponseCode(t *testing.T) {
	m := &EncapsulatedResponseAck{}
	assert.Equal(t, codes.ResponseEncapsulatedResponseAck, m.ResponseCode())
}

func TestEncapsulatedResponseAck_RoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte{0xEF}, 32)
	m := &EncapsulatedResponseAck{
		Header:           MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x6B, Param2: 0x05}},
		EncapsulatedData: payload,
	}
	data, err := m.Marshal()
	require.NoError(t, err)

	var m2 EncapsulatedResponseAck
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, m.Header, m2.Header)
	assert.Equal(t, payload, m2.EncapsulatedData)
}

func TestEncapsulatedResponseAck_Empty(t *testing.T) {
	m := &EncapsulatedResponseAck{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x6B}},
	}
	data, err := m.Marshal()
	require.NoError(t, err)

	var m2 EncapsulatedResponseAck
	require.NoError(t, m2.Unmarshal(data))
	assert.Nil(t, m2.EncapsulatedData)
}

func TestEncapsulatedResponseAck_ShortBuffer(t *testing.T) {
	var m EncapsulatedResponseAck
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize-1)), ErrShortBuffer))
}

// ---------------------------------------------------------------------------
// event.go: GetSupportedEventTypes
// ---------------------------------------------------------------------------

func TestGetSupportedEventTypes_RequestCode(t *testing.T) {
	m := &GetSupportedEventTypes{}
	assert.Equal(t, codes.RequestGetSupportedEventTypes, m.RequestCode())
}

func TestGetSupportedEventTypes_RoundTrip(t *testing.T) {
	m := &GetSupportedEventTypes{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x13, RequestResponseCode: 0xE2}},
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	require.Len(t, data, HeaderSize)

	var m2 GetSupportedEventTypes
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, m.Header, m2.Header)
}

func TestGetSupportedEventTypes_ShortBuffer(t *testing.T) {
	var m GetSupportedEventTypes
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize-1)), ErrShortBuffer))
}

// ---------------------------------------------------------------------------
// event.go: SupportedEventTypesResponse
// ---------------------------------------------------------------------------

func TestSupportedEventTypesResponse_ResponseCode(t *testing.T) {
	m := &SupportedEventTypesResponse{}
	assert.Equal(t, codes.ResponseSupportedEventTypes, m.ResponseCode())
}

func TestSupportedEventTypesResponse_RoundTrip(t *testing.T) {
	eventData := bytes.Repeat([]byte{0xAA}, 16)
	m := &SupportedEventTypesResponse{
		Header:              MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x13, RequestResponseCode: 0x62}},
		SupportedEventCount: 4,
		EventGroupData:      eventData,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	require.Len(t, data, HeaderSize+1+len(eventData))

	var m2 SupportedEventTypesResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint8(4), m2.SupportedEventCount)
	assert.Equal(t, eventData, m2.EventGroupData)
}

func TestSupportedEventTypesResponse_NoEventData(t *testing.T) {
	m := &SupportedEventTypesResponse{
		Header:              MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x13, RequestResponseCode: 0x62}},
		SupportedEventCount: 0,
	}
	data, err := m.Marshal()
	require.NoError(t, err)

	var m2 SupportedEventTypesResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint8(0), m2.SupportedEventCount)
	assert.Nil(t, m2.EventGroupData)
}

func TestSupportedEventTypesResponse_ShortBuffer(t *testing.T) {
	var m SupportedEventTypesResponse
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize)), ErrShortBuffer))
}

// ---------------------------------------------------------------------------
// event.go: SubscribeEventTypes
// ---------------------------------------------------------------------------

func TestSubscribeEventTypes_RequestCode(t *testing.T) {
	m := &SubscribeEventTypes{}
	assert.Equal(t, codes.RequestSubscribeEventTypes, m.RequestCode())
}

func TestSubscribeEventTypes_RoundTrip(t *testing.T) {
	eventData := bytes.Repeat([]byte{0xBB}, 8)
	m := &SubscribeEventTypes{
		Header:         MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x13, RequestResponseCode: 0xF0}},
		SubscribeCount: 2,
		EventGroupData: eventData,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	require.Len(t, data, HeaderSize+1+len(eventData))

	var m2 SubscribeEventTypes
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint8(2), m2.SubscribeCount)
	assert.Equal(t, eventData, m2.EventGroupData)
}

func TestSubscribeEventTypes_NoEventData(t *testing.T) {
	m := &SubscribeEventTypes{
		Header:         MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x13, RequestResponseCode: 0xF0}},
		SubscribeCount: 0,
	}
	data, err := m.Marshal()
	require.NoError(t, err)

	var m2 SubscribeEventTypes
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint8(0), m2.SubscribeCount)
	assert.Nil(t, m2.EventGroupData)
}

func TestSubscribeEventTypes_ShortBuffer(t *testing.T) {
	var m SubscribeEventTypes
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize)), ErrShortBuffer))
}

// ---------------------------------------------------------------------------
// event.go: SubscribeEventTypesAckResponse
// ---------------------------------------------------------------------------

func TestSubscribeEventTypesAckResponse_ResponseCode(t *testing.T) {
	m := &SubscribeEventTypesAckResponse{}
	assert.Equal(t, codes.ResponseSubscribeEventTypesAck, m.ResponseCode())
}

func TestSubscribeEventTypesAckResponse_RoundTrip(t *testing.T) {
	m := &SubscribeEventTypesAckResponse{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x13, RequestResponseCode: 0x70}},
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	require.Len(t, data, HeaderSize)

	var m2 SubscribeEventTypesAckResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, m.Header, m2.Header)
}

func TestSubscribeEventTypesAckResponse_ShortBuffer(t *testing.T) {
	var m SubscribeEventTypesAckResponse
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize-1)), ErrShortBuffer))
}

// ---------------------------------------------------------------------------
// event.go: SendEvent
// ---------------------------------------------------------------------------

func TestSendEvent_RequestCode(t *testing.T) {
	m := &SendEvent{}
	assert.Equal(t, codes.RequestSendEvent, m.RequestCode())
}

func TestSendEvent_RoundTrip(t *testing.T) {
	eventData := bytes.Repeat([]byte{0xCC}, 100)
	m := &SendEvent{
		Header:    MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x13, RequestResponseCode: 0xF1, Param1: 0x01}},
		EventData: eventData,
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	require.Len(t, data, HeaderSize+len(eventData))

	var m2 SendEvent
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, m.Header, m2.Header)
	assert.Equal(t, eventData, m2.EventData)
}

func TestSendEvent_NoData(t *testing.T) {
	m := &SendEvent{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x13, RequestResponseCode: 0xF1}},
	}
	data, err := m.Marshal()
	require.NoError(t, err)

	var m2 SendEvent
	require.NoError(t, m2.Unmarshal(data))
	assert.Nil(t, m2.EventData)
}

func TestSendEvent_ShortBuffer(t *testing.T) {
	var m SendEvent
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize-1)), ErrShortBuffer))
}

// ---------------------------------------------------------------------------
// event.go: EventAckResponse
// ---------------------------------------------------------------------------

func TestEventAckResponse_ResponseCode(t *testing.T) {
	m := &EventAckResponse{}
	assert.Equal(t, codes.ResponseEventAck, m.ResponseCode())
}

func TestEventAckResponse_RoundTrip(t *testing.T) {
	m := &EventAckResponse{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x13, RequestResponseCode: 0x71}},
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	require.Len(t, data, HeaderSize)

	var m2 EventAckResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, m.Header, m2.Header)
}

func TestEventAckResponse_ShortBuffer(t *testing.T) {
	var m EventAckResponse
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize-1)), ErrShortBuffer))
}

// ---------------------------------------------------------------------------
// set_key_pair_info.go: SetKeyPairInfo
// ---------------------------------------------------------------------------

func TestSetKeyPairInfo_RequestCode(t *testing.T) {
	m := &SetKeyPairInfo{}
	assert.Equal(t, codes.RequestSetKeyPairInfo, m.RequestCode())
}

func TestSetKeyPairInfo_RoundTrip(t *testing.T) {
	pki := bytes.Repeat([]byte{0x30}, 64)
	m := &SetKeyPairInfo{
		Header:                   MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x13, RequestResponseCode: 0xFD}},
		KeyPairID:                3,
		Operation:                1,
		DesiredKeyUsage:          0x0003,
		DesiredAsymAlgo:          0x00000060,
		DesiredAssocCertSlotMask: 0x05,
		PublicKeyInfo:            pki,
	}
	data, err := m.Marshal()
	require.NoError(t, err)

	var m2 SetKeyPairInfo
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint8(3), m2.KeyPairID)
	assert.Equal(t, uint8(1), m2.Operation)
	assert.Equal(t, uint16(0x0003), m2.DesiredKeyUsage)
	assert.Equal(t, uint32(0x00000060), m2.DesiredAsymAlgo)
	assert.Equal(t, uint8(0x05), m2.DesiredAssocCertSlotMask)
	assert.Equal(t, pki, m2.PublicKeyInfo)
}

func TestSetKeyPairInfo_EmptyPublicKeyInfo(t *testing.T) {
	m := &SetKeyPairInfo{
		Header:    MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x13, RequestResponseCode: 0xFD}},
		KeyPairID: 0,
		Operation: 2,
	}
	data, err := m.Marshal()
	require.NoError(t, err)

	var m2 SetKeyPairInfo
	require.NoError(t, m2.Unmarshal(data))
	assert.Empty(t, m2.PublicKeyInfo)
}

func TestSetKeyPairInfo_ShortBuffer(t *testing.T) {
	var m SetKeyPairInfo
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize+10)), ErrShortBuffer))
}

func TestSetKeyPairInfo_ShortPublicKeyInfo(t *testing.T) {
	// Fixed fields OK but PublicKeyInfoLen claims more data than available
	buf := make([]byte, HeaderSize+11)
	le.PutUint16(buf[HeaderSize+9:], 100) // pkiLen = 100 but no data follows
	var m SetKeyPairInfo
	assert.True(t, errors.Is(m.Unmarshal(buf), ErrShortBuffer))
}

// ---------------------------------------------------------------------------
// set_key_pair_info.go: SetKeyPairInfoAck
// ---------------------------------------------------------------------------

func TestSetKeyPairInfoAck_ResponseCode(t *testing.T) {
	m := &SetKeyPairInfoAck{}
	assert.Equal(t, codes.ResponseSetKeyPairInfoAck, m.ResponseCode())
}

func TestSetKeyPairInfoAck_RoundTrip(t *testing.T) {
	m := &SetKeyPairInfoAck{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x13, RequestResponseCode: 0x7D}},
	}
	data, err := m.Marshal()
	require.NoError(t, err)
	require.Len(t, data, HeaderSize)

	var m2 SetKeyPairInfoAck
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, m.Header, m2.Header)
}

func TestSetKeyPairInfoAck_ShortBuffer(t *testing.T) {
	var m SetKeyPairInfoAck
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize-1)), ErrShortBuffer))
}

// ---------------------------------------------------------------------------
// advanced.go: EndpointInfoResponse
// ---------------------------------------------------------------------------

func TestEndpointInfoResponse_ResponseCode(t *testing.T) {
	m := &EndpointInfoResponse{}
	assert.Equal(t, codes.ResponseEndpointInfo, m.ResponseCode())
}

func TestEndpointInfoResponse_RoundTrip(t *testing.T) {
	info := bytes.Repeat([]byte{0xDD}, 32)
	m := &EndpointInfoResponse{
		Header:          MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x13, RequestResponseCode: 0x07}},
		RemainderLength: 100,
		EndpointInfo:    info,
	}
	data, err := m.Marshal()
	require.NoError(t, err)

	var m2 EndpointInfoResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, uint32(len(info)), m2.PortionLength)
	assert.Equal(t, uint32(100), m2.RemainderLength)
	assert.Equal(t, info, m2.EndpointInfo)
}

func TestEndpointInfoResponse_Empty(t *testing.T) {
	m := &EndpointInfoResponse{
		Header:          MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x13, RequestResponseCode: 0x07}},
		RemainderLength: 0,
	}
	data, err := m.Marshal()
	require.NoError(t, err)

	var m2 EndpointInfoResponse
	require.NoError(t, m2.Unmarshal(data))
	assert.Empty(t, m2.EndpointInfo)
}

func TestEndpointInfoResponse_ShortBuffer(t *testing.T) {
	var m EndpointInfoResponse
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize+7)), ErrShortBuffer))
}

func TestEndpointInfoResponse_ShortData(t *testing.T) {
	// Fixed fields OK but PortionLength claims more data than available
	buf := make([]byte, HeaderSize+8)
	le.PutUint32(buf[HeaderSize:], 50) // PortionLength = 50, no data
	var m EndpointInfoResponse
	assert.True(t, errors.Is(m.Unmarshal(buf), ErrShortBuffer))
}

// ---------------------------------------------------------------------------
// Short buffer error paths for partially covered Unmarshal methods
// ---------------------------------------------------------------------------

func TestVersionResponseUnmarshalShortEntries(t *testing.T) {
	// Entry count claims 5 entries but buffer only has header+2
	buf := make([]byte, HeaderSize+2)
	buf[5] = 5 // VersionNumberEntryCount = 5
	var m VersionResponse
	assert.True(t, errors.Is(m.Unmarshal(buf), ErrShortBuffer))
}

func TestGetCapabilitiesUnmarshalMinimal(t *testing.T) {
	// Header+12 bytes for SPDM 1.1 (without DataTransferSize/MaxSPDMmsgSize)
	buf := make([]byte, HeaderSize+12)
	buf[0] = 0x11 // SPDM 1.1
	buf[1] = 0xE1
	buf[5] = 10 // CTExponent
	le.PutUint32(buf[8:], 0x00008206)
	var m GetCapabilities
	require.NoError(t, m.Unmarshal(buf))
	assert.Equal(t, uint32(0), m.DataTransferSize)
	assert.Equal(t, uint32(0), m.MaxSPDMmsgSize)
	assert.Equal(t, uint8(10), m.CTExponent)
}

func TestCapabilitiesResponseUnmarshalMinimal(t *testing.T) {
	buf := make([]byte, HeaderSize+12)
	buf[0] = 0x11
	buf[1] = 0x61
	var m CapabilitiesResponse
	require.NoError(t, m.Unmarshal(buf))
	assert.Equal(t, uint32(0), m.DataTransferSize)
}

func TestGetCertificateUnmarshalShortHeader(t *testing.T) {
	var m GetCertificate
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize-1)), ErrShortBuffer))
}

func TestCertificateResponseUnmarshalShortPortionLen(t *testing.T) {
	// Header + 4 bytes OK, but PortionLength claims more
	buf := make([]byte, HeaderSize+4)
	le.PutUint16(buf[HeaderSize:], 50) // PortionLength=50, no data
	var m CertificateResponse
	assert.True(t, errors.Is(m.Unmarshal(buf), ErrShortBuffer))
}

func TestChallengeUnmarshalShortNonce(t *testing.T) {
	var m Challenge
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize+NonceSize-1)), ErrShortBuffer))
}

func TestChallengeAuthResponseUnmarshalWithSizes_ShortDigest(t *testing.T) {
	var m ChallengeAuthResponse
	// Header OK but not enough data for digest
	buf := make([]byte, HeaderSize)
	assert.True(t, errors.Is(m.UnmarshalWithSizes(buf, 32, 0, 0), ErrShortBuffer))
}

func TestChallengeAuthResponseUnmarshalWithSizes_ShortNonce(t *testing.T) {
	var m ChallengeAuthResponse
	buf := make([]byte, HeaderSize+32) // enough for digest but not nonce
	assert.True(t, errors.Is(m.UnmarshalWithSizes(buf, 32, 0, 0), ErrShortBuffer))
}

func TestChallengeAuthResponseUnmarshalWithSizes_ShortMeasHash(t *testing.T) {
	var m ChallengeAuthResponse
	buf := make([]byte, HeaderSize+32+NonceSize) // enough for digest+nonce but not measHash
	assert.True(t, errors.Is(m.UnmarshalWithSizes(buf, 32, 32, 0), ErrShortBuffer))
}

func TestChallengeAuthResponseUnmarshalWithSizes_ShortOpaqueLen(t *testing.T) {
	var m ChallengeAuthResponse
	// digest(32) + nonce(32) + measHash(32) but no opaque_length
	buf := make([]byte, HeaderSize+32+NonceSize+32)
	assert.True(t, errors.Is(m.UnmarshalWithSizes(buf, 32, 32, 0), ErrShortBuffer))
}

func TestChallengeAuthResponseUnmarshalWithSizes_ShortOpaqueData(t *testing.T) {
	var m ChallengeAuthResponse
	buf := make([]byte, HeaderSize+32+NonceSize+32+2)
	le.PutUint16(buf[HeaderSize+32+NonceSize+32:], 100) // opaqueLen=100
	assert.True(t, errors.Is(m.UnmarshalWithSizes(buf, 32, 32, 0), ErrShortBuffer))
}

func TestChallengeAuthResponseUnmarshalWithSizes_ShortSig(t *testing.T) {
	var m ChallengeAuthResponse
	// digest(32) + nonce(32) + measHash(0) + opaqueLen(2) + opaque(0) but not enough for sig
	buf := make([]byte, HeaderSize+32+NonceSize+2)
	le.PutUint16(buf[HeaderSize+32+NonceSize:], 0) // opaqueLen=0
	assert.True(t, errors.Is(m.UnmarshalWithSizes(buf, 32, 0, 64), ErrShortBuffer))
}

func TestChallengeAuthResponseUnmarshalWithSizes_ShortReqContext13(t *testing.T) {
	var m ChallengeAuthResponse
	// SPDM 1.3 needs RequesterContext
	buf := make([]byte, HeaderSize+32+NonceSize+2)
	buf[0] = 0x13                                  // SPDM 1.3
	le.PutUint16(buf[HeaderSize+32+NonceSize:], 0) // opaqueLen=0
	assert.True(t, errors.Is(m.UnmarshalWithSizes(buf, 32, 0, 0), ErrShortBuffer))
}

func TestChallengeAuthResponseMarshal_Version13(t *testing.T) {
	m := &ChallengeAuthResponse{
		Header:                 MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x13, RequestResponseCode: 0x63}},
		CertChainHash:          bytes.Repeat([]byte{0x01}, 32),
		MeasurementSummaryHash: bytes.Repeat([]byte{0x02}, 32),
		OpaqueData:             []byte{0x03, 0x04},
		Signature:              bytes.Repeat([]byte{0x05}, 64),
	}
	for i := range m.Nonce {
		m.Nonce[i] = byte(i)
	}
	for i := range m.RequesterContext {
		m.RequesterContext[i] = byte(i + 0x10)
	}

	data, err := m.Marshal()
	require.NoError(t, err)

	var m2 ChallengeAuthResponse
	require.NoError(t, m2.UnmarshalWithSizes(data, 32, 32, 64))
	assert.Equal(t, m.CertChainHash, m2.CertChainHash)
	assert.Equal(t, m.Nonce, m2.Nonce)
	assert.Equal(t, m.RequesterContext, m2.RequesterContext)
	assert.Equal(t, m.Signature, m2.Signature)
}

func TestChallengeAuthResponseMarshal_Version12(t *testing.T) {
	m := &ChallengeAuthResponse{
		Header:                 MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x63}},
		CertChainHash:          bytes.Repeat([]byte{0x01}, 32),
		MeasurementSummaryHash: nil,
		OpaqueData:             nil,
		Signature:              bytes.Repeat([]byte{0x05}, 64),
	}

	data, err := m.Marshal()
	require.NoError(t, err)

	var m2 ChallengeAuthResponse
	require.NoError(t, m2.UnmarshalWithSizes(data, 32, 0, 64))
	assert.Equal(t, m.CertChainHash, m2.CertChainHash)
	assert.Equal(t, m.Signature, m2.Signature)
}

func TestFinishUnmarshalWithSizes_ShortHash(t *testing.T) {
	// No signature, but hash too short
	buf := make([]byte, HeaderSize)
	buf[2] = 0x00 // Param1: no signature
	var m Finish
	assert.True(t, errors.Is(m.UnmarshalWithSizes(buf, 0, 32), ErrShortBuffer))
}

func TestFinishUnmarshalWithSizes_ShortSig(t *testing.T) {
	// Signature requested but too short
	buf := make([]byte, HeaderSize)
	buf[2] = 0x01 // Param1 bit 0: signature included
	var m Finish
	assert.True(t, errors.Is(m.UnmarshalWithSizes(buf, 64, 32), ErrShortBuffer))
}

func TestFinishResponseUnmarshalWithHashSize_NoVerifyData(t *testing.T) {
	// When the data is too short for verify data, it should still succeed
	// (VerifyData is optional)
	buf := make([]byte, HeaderSize)
	var m FinishResponse
	require.NoError(t, m.UnmarshalWithHashSize(buf, 32))
	assert.Nil(t, m.VerifyData)
}

func TestFinishResponseUnmarshalWithHashSize_WithVerifyData(t *testing.T) {
	verify := bytes.Repeat([]byte{0x42}, 32)
	buf := make([]byte, HeaderSize+32)
	copy(buf[HeaderSize:], verify)
	var m FinishResponse
	require.NoError(t, m.UnmarshalWithHashSize(buf, 32))
	assert.Equal(t, verify, m.VerifyData)
}

func TestKeyExchangeUnmarshalWithDHESize_ShortOpaqueLen(t *testing.T) {
	// Enough for header+4+random+dhe but no opaque_length
	dheSize := 32
	buf := make([]byte, HeaderSize+4+RandomDataSize+dheSize)
	var m KeyExchange
	assert.True(t, errors.Is(m.UnmarshalWithDHESize(buf, dheSize), ErrShortBuffer))
}

func TestKeyExchangeUnmarshalWithDHESize_ShortOpaqueData(t *testing.T) {
	dheSize := 32
	buf := make([]byte, HeaderSize+4+RandomDataSize+dheSize+2)
	le.PutUint16(buf[HeaderSize+4+RandomDataSize+dheSize:], 50) // opaqueLen=50
	var m KeyExchange
	assert.True(t, errors.Is(m.UnmarshalWithDHESize(buf, dheSize), ErrShortBuffer))
}

func TestKeyExchangeResponseUnmarshalShortHeader(t *testing.T) {
	var m KeyExchangeResponse
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize-1)), ErrShortBuffer))
}

func TestGetMeasurementsUnmarshalWithSignature(t *testing.T) {
	m := &GetMeasurements{
		Header:      MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xE0, Param1: MeasAttrGenerateSignature}},
		SlotIDParam: 0x02,
	}
	for i := range m.Nonce {
		m.Nonce[i] = byte(i)
	}

	data, err := m.Marshal()
	require.NoError(t, err)

	var m2 GetMeasurements
	require.NoError(t, m2.Unmarshal(data))
	assert.Equal(t, m.Nonce, m2.Nonce)
	assert.Equal(t, uint8(0x02), m2.SlotIDParam)
}

func TestGetMeasurementsUnmarshalWithoutSignature(t *testing.T) {
	m := &GetMeasurements{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0xE0, Param1: 0x00}},
	}
	data, err := m.Marshal()
	require.NoError(t, err)

	// Unmarshal with no signature flag: nonce/slotID should not be parsed
	buf := data[:HeaderSize] // only header
	var m2 GetMeasurements
	require.NoError(t, m2.Unmarshal(buf))
	assert.Equal(t, uint8(0x00), m2.Header.Param1)
}

func TestGetMeasurementsUnmarshalShortSigFields(t *testing.T) {
	// Param1 has signature flag, but buffer too short for nonce+slotID
	buf := make([]byte, HeaderSize+NonceSize)
	buf[2] = MeasAttrGenerateSignature
	var m GetMeasurements
	assert.True(t, errors.Is(m.Unmarshal(buf), ErrShortBuffer))
}

func TestMeasurementsResponseUnmarshalShortRecordLen(t *testing.T) {
	// Header+4 OK, but MeasurementRecordLen claims more data
	buf := make([]byte, HeaderSize+4)
	buf[5] = 0xFF // recordLen byte 0
	buf[6] = 0x00
	buf[7] = 0x00
	var m MeasurementsResponse
	assert.True(t, errors.Is(m.Unmarshal(buf), ErrShortBuffer))
}

func TestPSKExchangeUnmarshalShortVarData(t *testing.T) {
	// Header+8 OK, but variable field lengths claim more data
	buf := make([]byte, HeaderSize+8)
	le.PutUint16(buf[HeaderSize+2:], 10) // PSKHintLen = 10
	le.PutUint16(buf[HeaderSize+4:], 0)  // ContextLen = 0
	le.PutUint16(buf[HeaderSize+6:], 0)  // OpaqueLen = 0
	var m PSKExchange
	assert.True(t, errors.Is(m.Unmarshal(buf), ErrShortBuffer))
}

func TestDigestResponseUnmarshalWithDigestSize_ShortDigests(t *testing.T) {
	// Header OK, Param2 says 3 slots, but not enough data
	buf := make([]byte, HeaderSize)
	buf[3] = 0x07 // 3 slots set
	var m DigestResponse
	assert.True(t, errors.Is(m.UnmarshalWithDigestSize(buf, 32), ErrShortBuffer))
}

func TestGetCSRUnmarshalShortOpaqueData(t *testing.T) {
	// Fixed fields OK, RequesterInfoLen=0, OpaqueDataLen claims more
	buf := make([]byte, HeaderSize+4)
	le.PutUint16(buf[HeaderSize:], 0)    // RequesterInfoLen = 0
	le.PutUint16(buf[HeaderSize+2:], 20) // OpaqueDataLen = 20
	var m GetCSR
	assert.True(t, errors.Is(m.Unmarshal(buf), ErrShortBuffer))
}

func TestCSRResponseUnmarshalShortCSRBody(t *testing.T) {
	buf := make([]byte, HeaderSize+4)
	le.PutUint16(buf[HeaderSize:], 50) // CSRLength = 50
	var m CSRResponse
	assert.True(t, errors.Is(m.Unmarshal(buf), ErrShortBuffer))
}

func TestChunkSendAck_ShortBuffer_EarlyError(t *testing.T) {
	var m ChunkSendAck
	// Buffer with EarlyError flag but only header+2 (missing Response field)
	buf := make([]byte, HeaderSize+2)
	buf[2] = ChunkSendAckAttrEarlyError // Param1 = EarlyError
	require.NoError(t, m.Unmarshal(buf))
	assert.Empty(t, m.Response)
}

func TestGetEndpointInfo_ShortBufferWithSignature(t *testing.T) {
	var m GetEndpointInfo
	// Minimum size for non-signature request
	buf := make([]byte, HeaderSize+4)
	buf[4] = 0x01 // RequestAttributes = signature requested
	// Buffer is too short for nonce -- but UnmarshalWithSizes doesn't check
	require.NoError(t, m.Unmarshal(buf))
	// Nonce should be zero (not enough data to read)
}

func TestGetMeasurementExtensionLog_ShortHeader(t *testing.T) {
	var m GetMeasurementExtensionLog
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize-1)), ErrShortBuffer))
}

func TestKeyPairInfoResponse_EmptyPKI(t *testing.T) {
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
	assert.Len(t, m2.PublicKeyInfo, 0)
}

func TestGetKeyPairInfo_ShortHeader(t *testing.T) {
	var m GetKeyPairInfo
	assert.True(t, errors.Is(m.Unmarshal(make([]byte, HeaderSize-1)), ErrShortBuffer))
}

// ---------------------------------------------------------------------------
// psk.go: PSKExchangeResponse.UnmarshalWithSizes
// ---------------------------------------------------------------------------

func TestPSKExchangeResponseUnmarshalWithSizes_RoundTrip(t *testing.T) {
	hashSize := 32
	hmacSize := 32
	measHash := bytes.Repeat([]byte{0xAA}, hashSize)
	ctx := bytes.Repeat([]byte{0xBB}, 16)
	opaque := bytes.Repeat([]byte{0xCC}, 8)
	verify := bytes.Repeat([]byte{0xDD}, hmacSize)

	m := &PSKExchangeResponse{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponsePSKExchangeRsp),
		}},
		RspSessionID:           0x1234,
		Reserved:               0,
		MeasurementSummaryHash: measHash,
		Context:                ctx,
		OpaqueData:             opaque,
		VerifyData:             verify,
	}

	data, err := m.Marshal()
	require.NoError(t, err)

	var m2 PSKExchangeResponse
	require.NoError(t, m2.UnmarshalWithSizes(data, hashSize, hmacSize))
	assert.Equal(t, m.Header, m2.Header)
	assert.Equal(t, m.RspSessionID, m2.RspSessionID)
	assert.Equal(t, measHash, m2.MeasurementSummaryHash)
	assert.Equal(t, ctx, m2.Context)
	assert.Equal(t, opaque, m2.OpaqueData)
	assert.Equal(t, verify, m2.VerifyData)
}

func TestPSKExchangeResponseUnmarshalWithSizes_NoMeasHash(t *testing.T) {
	hmacSize := 32
	ctx := bytes.Repeat([]byte{0xBB}, 16)
	verify := bytes.Repeat([]byte{0xDD}, hmacSize)

	m := &PSKExchangeResponse{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponsePSKExchangeRsp),
		}},
		RspSessionID: 0x5678,
		Context:      ctx,
		VerifyData:   verify,
	}

	data, err := m.Marshal()
	require.NoError(t, err)

	var m2 PSKExchangeResponse
	require.NoError(t, m2.UnmarshalWithSizes(data, 0, hmacSize))
	assert.Equal(t, m.RspSessionID, m2.RspSessionID)
	assert.Nil(t, m2.MeasurementSummaryHash)
	assert.Equal(t, ctx, m2.Context)
	assert.Equal(t, verify, m2.VerifyData)
}

func TestPSKExchangeResponseUnmarshalWithSizes_ShortHeader(t *testing.T) {
	var m PSKExchangeResponse
	assert.True(t, errors.Is(m.UnmarshalWithSizes(make([]byte, HeaderSize+7), 0, 0), ErrShortBuffer))
}

func TestPSKExchangeResponseUnmarshalWithSizes_ShortMeasHash(t *testing.T) {
	var m PSKExchangeResponse
	buf := make([]byte, HeaderSize+8)
	le.PutUint16(buf[HeaderSize+4:], 0) // ContextLen = 0
	le.PutUint16(buf[HeaderSize+6:], 0) // OpaqueLen = 0
	assert.True(t, errors.Is(m.UnmarshalWithSizes(buf, 32, 0), ErrShortBuffer))
}

func TestPSKExchangeResponseUnmarshalWithSizes_ShortContext(t *testing.T) {
	var m PSKExchangeResponse
	buf := make([]byte, HeaderSize+8)
	le.PutUint16(buf[HeaderSize+4:], 16) // ContextLen = 16
	le.PutUint16(buf[HeaderSize+6:], 0)  // OpaqueLen = 0
	assert.True(t, errors.Is(m.UnmarshalWithSizes(buf, 0, 0), ErrShortBuffer))
}

func TestPSKExchangeResponseUnmarshalWithSizes_ShortOpaque(t *testing.T) {
	var m PSKExchangeResponse
	buf := make([]byte, HeaderSize+8)
	le.PutUint16(buf[HeaderSize+4:], 0) // ContextLen = 0
	le.PutUint16(buf[HeaderSize+6:], 8) // OpaqueLen = 8
	assert.True(t, errors.Is(m.UnmarshalWithSizes(buf, 0, 0), ErrShortBuffer))
}

func TestPSKExchangeResponseUnmarshalWithSizes_ShortVerifyData(t *testing.T) {
	var m PSKExchangeResponse
	buf := make([]byte, HeaderSize+8)
	le.PutUint16(buf[HeaderSize+4:], 0) // ContextLen = 0
	le.PutUint16(buf[HeaderSize+6:], 0) // OpaqueLen = 0
	assert.True(t, errors.Is(m.UnmarshalWithSizes(buf, 0, 32), ErrShortBuffer))
}
