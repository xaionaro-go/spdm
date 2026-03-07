package msgs

import (
	"testing"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

func FuzzMessageHeaderUnmarshal(f *testing.F) {
	valid := &MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: 0x84, Param1: 0x01, Param2: 0x02}}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg MessageHeader
		_ = msg.Unmarshal(data)
	})
}

func FuzzGetVersionUnmarshal(f *testing.F) {
	valid := &GetVersion{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x10, RequestResponseCode: uint8(codes.RequestGetVersion)}}}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg GetVersion
		_ = msg.Unmarshal(data)
	})
}

func FuzzVersionResponseUnmarshal(f *testing.F) {
	valid := &VersionResponse{
		Header:         MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x10, RequestResponseCode: uint8(codes.ResponseVersion)}},
		VersionEntries: []uint16{0x1200, 0x1100},
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg VersionResponse
		_ = msg.Unmarshal(data)
	})
}

func FuzzGetCapabilitiesUnmarshal(f *testing.F) {
	valid := &GetCapabilities{
		Header:           MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestGetCapabilities)}},
		CTExponent:       12,
		Flags:            0x0001,
		DataTransferSize: 4096,
		MaxSPDMmsgSize:   4096,
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg GetCapabilities
		_ = msg.Unmarshal(data)
	})
}

func FuzzCapabilitiesResponseUnmarshal(f *testing.F) {
	valid := &CapabilitiesResponse{
		Header:           MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.ResponseCapabilities)}},
		CTExponent:       12,
		Flags:            0x0001,
		DataTransferSize: 4096,
		MaxSPDMmsgSize:   4096,
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg CapabilitiesResponse
		_ = msg.Unmarshal(data)
	})
}

func FuzzNegotiateAlgorithmsUnmarshal(f *testing.F) {
	valid := &NegotiateAlgorithms{
		Header:                   MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestNegotiateAlgorithms), Param1: 4}},
		MeasurementSpecification: 0x01,
		OtherParamsSupport:       0x02,
		BaseAsymAlgo:             0x00000040,
		BaseHashAlgo:             0x00000002,
		AlgStructs: []AlgStructTable{
			{AlgType: AlgTypeDHE, AlgCount: 0x20, AlgSupported: 0x0008},
			{AlgType: AlgTypeAEAD, AlgCount: 0x20, AlgSupported: 0x0002},
			{AlgType: AlgTypeReqBaseAsym, AlgCount: 0x20, AlgSupported: 0x0040},
			{AlgType: AlgTypeKeySchedule, AlgCount: 0x20, AlgSupported: 0x0001},
		},
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg NegotiateAlgorithms
		_ = msg.Unmarshal(data)
	})
}

func FuzzAlgorithmsResponseUnmarshal(f *testing.F) {
	valid := &AlgorithmsResponse{
		Header:                      MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.ResponseAlgorithms), Param1: 4}},
		MeasurementSpecificationSel: 0x01,
		OtherParamsSelection:        0x02,
		MeasurementHashAlgo:         0x00000002,
		BaseAsymSel:                 0x00000040,
		BaseHashSel:                 0x00000002,
		AlgStructs: []AlgStructTable{
			{AlgType: AlgTypeDHE, AlgCount: 0x20, AlgSupported: 0x0008},
			{AlgType: AlgTypeAEAD, AlgCount: 0x20, AlgSupported: 0x0002},
			{AlgType: AlgTypeReqBaseAsym, AlgCount: 0x20, AlgSupported: 0x0040},
			{AlgType: AlgTypeKeySchedule, AlgCount: 0x20, AlgSupported: 0x0001},
		},
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg AlgorithmsResponse
		_ = msg.Unmarshal(data)
	})
}

func FuzzGetDigestsUnmarshal(f *testing.F) {
	valid := &GetDigests{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestGetDigests)}}}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg GetDigests
		_ = msg.Unmarshal(data)
	})
}

func FuzzDigestResponseUnmarshal(f *testing.F) {
	valid := &DigestResponse{
		Header:  MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.ResponseDigests), Param2: 0x01}},
		Digests: [][]byte{make([]byte, 32)},
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg DigestResponse
		_ = msg.Unmarshal(data)
	})
}

func FuzzGetCertificateUnmarshal(f *testing.F) {
	valid := &GetCertificate{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestGetCertificate)}},
		Offset: 0,
		Length: 1024,
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg GetCertificate
		_ = msg.Unmarshal(data)
	})
}

func FuzzCertificateResponseUnmarshal(f *testing.F) {
	valid := &CertificateResponse{
		Header:          MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.ResponseCertificate)}},
		PortionLength:   4,
		RemainderLength: 100,
		CertChain:       []byte{0x01, 0x02, 0x03, 0x04},
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg CertificateResponse
		_ = msg.Unmarshal(data)
	})
}

func FuzzChallengeUnmarshal(f *testing.F) {
	valid := &Challenge{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestChallenge), Param1: 0, Param2: 0x01}},
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg Challenge
		_ = msg.Unmarshal(data)
	})
}

func FuzzChallengeAuthResponseUnmarshal(f *testing.F) {
	valid := &ChallengeAuthResponse{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.ResponseChallengeAuth)}},
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg ChallengeAuthResponse
		_ = msg.Unmarshal(data)
	})
}

func FuzzGetMeasurementsUnmarshal(f *testing.F) {
	valid := &GetMeasurements{
		Header:      MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestGetMeasurements), Param1: MeasAttrGenerateSignature}},
		SlotIDParam: 0,
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg GetMeasurements
		_ = msg.Unmarshal(data)
	})
}

func FuzzMeasurementsResponseUnmarshal(f *testing.F) {
	valid := &MeasurementsResponse{
		Header:            MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.ResponseMeasurements)}},
		NumberOfBlocks:    1,
		MeasurementRecord: []byte{0x01, 0x00, 0x03, 0x00, 0x01, 0x01, 0x00},
		OpaqueData:        []byte{0xAA},
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg MeasurementsResponse
		_ = msg.Unmarshal(data)
	})
}

func FuzzKeyExchangeUnmarshal(f *testing.F) {
	valid := &KeyExchange{
		Header:       MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestKeyExchange), Param1: 0x01}},
		ReqSessionID: 0x1234,
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg KeyExchange
		_ = msg.Unmarshal(data)
	})
}

func FuzzKeyExchangeResponseUnmarshal(f *testing.F) {
	valid := &KeyExchangeResponse{
		Header:       MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.ResponseKeyExchangeRsp)}},
		RspSessionID: 0x5678,
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg KeyExchangeResponse
		_ = msg.Unmarshal(data)
	})
}

func FuzzFinishUnmarshal(f *testing.F) {
	valid := &Finish{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestFinish)}},
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg Finish
		_ = msg.Unmarshal(data)
	})
}

func FuzzFinishResponseUnmarshal(f *testing.F) {
	valid := &FinishResponse{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.ResponseFinishRsp)}},
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg FinishResponse
		_ = msg.Unmarshal(data)
	})
}

func FuzzPSKExchangeUnmarshal(f *testing.F) {
	valid := &PSKExchange{
		Header:       MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestPSKExchange)}},
		ReqSessionID: 0x1234,
		PSKHint:      []byte("hint"),
		Context:      []byte("ctx"),
		OpaqueData:   []byte{0x01},
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg PSKExchange
		_ = msg.Unmarshal(data)
	})
}

func FuzzPSKExchangeResponseUnmarshal(f *testing.F) {
	valid := &PSKExchangeResponse{
		Header:       MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.ResponsePSKExchangeRsp)}},
		RspSessionID: 0x5678,
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg PSKExchangeResponse
		_ = msg.Unmarshal(data)
	})
}

func FuzzPSKFinishUnmarshal(f *testing.F) {
	valid := &PSKFinish{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestPSKFinish)}},
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg PSKFinish
		_ = msg.Unmarshal(data)
	})
}

func FuzzPSKFinishResponseUnmarshal(f *testing.F) {
	valid := &PSKFinishResponse{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.ResponsePSKFinishRsp)}},
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg PSKFinishResponse
		_ = msg.Unmarshal(data)
	})
}

func FuzzHeartbeatUnmarshal(f *testing.F) {
	valid := &Heartbeat{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestHeartbeat)}}}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg Heartbeat
		_ = msg.Unmarshal(data)
	})
}

func FuzzHeartbeatResponseUnmarshal(f *testing.F) {
	valid := &HeartbeatResponse{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.ResponseHeartbeatAck)}}}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg HeartbeatResponse
		_ = msg.Unmarshal(data)
	})
}

func FuzzKeyUpdateUnmarshal(f *testing.F) {
	valid := &KeyUpdate{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestKeyUpdate), Param1: KeyUpdateOpUpdateKey}}}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg KeyUpdate
		_ = msg.Unmarshal(data)
	})
}

func FuzzKeyUpdateResponseUnmarshal(f *testing.F) {
	valid := &KeyUpdateResponse{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.ResponseKeyUpdateAck)}}}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg KeyUpdateResponse
		_ = msg.Unmarshal(data)
	})
}

func FuzzEndSessionUnmarshal(f *testing.F) {
	valid := &EndSession{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestEndSession)}}}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg EndSession
		_ = msg.Unmarshal(data)
	})
}

func FuzzEndSessionResponseUnmarshal(f *testing.F) {
	valid := &EndSessionResponse{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.ResponseEndSessionAck)}}}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg EndSessionResponse
		_ = msg.Unmarshal(data)
	})
}

func FuzzErrorResponseUnmarshal(f *testing.F) {
	valid := &ErrorResponse{
		Header:       MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.ResponseError), Param1: 0x01}},
		ExtErrorData: []byte{0x0A, 0x84, 0x01, 0x05},
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg ErrorResponse
		_ = msg.Unmarshal(data)
	})
}

func FuzzResponseNotReadyDataUnmarshal(f *testing.F) {
	valid := &ResponseNotReadyData{RDExponent: 10, RequestCode: 0x84, Token: 1, RDTM: 5}
	f.Add(valid.Marshal())
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg ResponseNotReadyData
		_ = msg.Unmarshal(data)
	})
}

func FuzzRespondIfReadyUnmarshal(f *testing.F) {
	valid := &RespondIfReady{Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestRespondIfReady), Param1: 0x84, Param2: 1}}}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg RespondIfReady
		_ = msg.Unmarshal(data)
	})
}

func FuzzVendorDefinedRequestUnmarshal(f *testing.F) {
	valid := &VendorDefinedRequest{
		Header:     MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestVendorDefined)}},
		StandardID: 0x0001,
		VendorID:   []byte{0x01, 0x02},
		Payload:    []byte{0xAA, 0xBB},
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg VendorDefinedRequest
		_ = msg.Unmarshal(data)
	})
}

func FuzzVendorDefinedResponseUnmarshal(f *testing.F) {
	valid := &VendorDefinedResponse{
		Header:     MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.ResponseVendorDefined)}},
		StandardID: 0x0001,
		VendorID:   []byte{0x01, 0x02},
		Payload:    []byte{0xCC, 0xDD},
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg VendorDefinedResponse
		_ = msg.Unmarshal(data)
	})
}

func FuzzChunkSendUnmarshal(f *testing.F) {
	valid := &ChunkSend{
		Header:           MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestChunkSend), Param2: 1}},
		ChunkSeqNo:       0,
		LargeMessageSize: 100,
		Chunk:            []byte{0x01, 0x02, 0x03},
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg ChunkSend
		_ = msg.Unmarshal(data)
	})
}

func FuzzChunkSendAckUnmarshal(f *testing.F) {
	valid := &ChunkSendAck{
		Header:     MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.ResponseChunkSendAck), Param2: 1}},
		ChunkSeqNo: 0,
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg ChunkSendAck
		_ = msg.Unmarshal(data)
	})
}

func FuzzChunkGetUnmarshal(f *testing.F) {
	valid := &ChunkGet{
		Header:     MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestChunkGet), Param2: 1}},
		ChunkSeqNo: 0,
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg ChunkGet
		_ = msg.Unmarshal(data)
	})
}

func FuzzChunkResponseUnmarshal(f *testing.F) {
	valid := &ChunkResponse{
		Header:           MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.ResponseChunkResponse), Param2: 1}},
		ChunkSeqNo:       0,
		LargeMessageSize: 100,
		Chunk:            []byte{0x01, 0x02, 0x03},
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg ChunkResponse
		_ = msg.Unmarshal(data)
	})
}

func FuzzGetCSRUnmarshal(f *testing.F) {
	valid := &GetCSR{
		Header:        MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestGetCSR)}},
		RequesterInfo: []byte{0x01, 0x02},
		OpaqueData:    []byte{0x03},
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg GetCSR
		_ = msg.Unmarshal(data)
	})
}

func FuzzCSRResponseUnmarshal(f *testing.F) {
	valid := &CSRResponse{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.ResponseCSR)}},
		CSR:    []byte{0x30, 0x82, 0x01, 0x00},
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg CSRResponse
		_ = msg.Unmarshal(data)
	})
}

func FuzzSetCertificateUnmarshal(f *testing.F) {
	valid := &SetCertificate{
		Header:    MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestSetCertificate)}},
		CertChain: []byte{0x30, 0x82, 0x01, 0x00},
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg SetCertificate
		_ = msg.Unmarshal(data)
	})
}

func FuzzSetCertificateResponseUnmarshal(f *testing.F) {
	valid := &SetCertificateResponse{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.ResponseSetCertificateRsp)}},
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg SetCertificateResponse
		_ = msg.Unmarshal(data)
	})
}

func FuzzGetMeasurementExtensionLogUnmarshal(f *testing.F) {
	valid := &GetMeasurementExtensionLog{
		Header: MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestGetMeasurementExtensionLog)}},
		Offset: 0,
		Length: 256,
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg GetMeasurementExtensionLog
		_ = msg.Unmarshal(data)
	})
}

func FuzzMeasurementExtensionLogResponseUnmarshal(f *testing.F) {
	valid := &MeasurementExtensionLogResponse{
		Header:          MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.ResponseMeasurementExtensionLog)}},
		RemainderLength: 0,
		MEL:             []byte{0x01, 0x02, 0x03, 0x04},
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg MeasurementExtensionLogResponse
		_ = msg.Unmarshal(data)
	})
}

func FuzzGetKeyPairInfoUnmarshal(f *testing.F) {
	valid := &GetKeyPairInfo{
		Header:    MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestGetKeyPairInfo)}},
		KeyPairID: 1,
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg GetKeyPairInfo
		_ = msg.Unmarshal(data)
	})
}

func FuzzKeyPairInfoResponseUnmarshal(f *testing.F) {
	valid := &KeyPairInfoResponse{
		Header:               MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.ResponseKeyPairInfo)}},
		TotalKeyPairs:        2,
		KeyPairID:            1,
		Capabilities:         0x0001,
		KeyUsageCapabilities: 0x0001,
		CurrentKeyUsage:      0x0001,
		AsymAlgoCapabilities: 0x00000040,
		CurrentAsymAlgo:      0x00000040,
		AssocCertSlotMask:    0x01,
		PublicKeyInfo:        []byte{0x30, 0x59},
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg KeyPairInfoResponse
		_ = msg.Unmarshal(data)
	})
}

func FuzzGetEndpointInfoUnmarshal(f *testing.F) {
	valid := &GetEndpointInfo{
		Header:            MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestGetEndpointInfo)}},
		RequestAttributes: 0x00,
	}
	if data, err := valid.Marshal(); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var msg GetEndpointInfo
		_ = msg.Unmarshal(data)
	})
}
