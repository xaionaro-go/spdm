package unit

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

// ---------------------------------------------------------------------------
// Challenge (challenge.go)
// ---------------------------------------------------------------------------

func TestMsgs_Challenge_RequestCode(t *testing.T) {
	var m msgs.Challenge
	assert.Equal(t, codes.RequestChallenge, m.RequestCode())
}

func TestMsgs_Challenge_SlotID(t *testing.T) {
	m := msgs.Challenge{Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{Param1: 3}}}
	assert.Equal(t, uint8(3), m.SlotID())
}

func TestMsgs_Challenge_HashType(t *testing.T) {
	m := msgs.Challenge{Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{Param2: 0x01}}}
	assert.Equal(t, uint8(0x01), m.HashType())
}

func TestMsgs_Challenge_MarshalUnmarshalRoundTrip(t *testing.T) {
	orig := &msgs.Challenge{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestChallenge),
			Param1:              2,
			Param2:              0x01,
		}},
	}
	for i := range orig.Nonce {
		orig.Nonce[i] = byte(i)
	}

	data, err := orig.Marshal()
	require.NoError(t, err)
	assert.Len(t, data, msgs.HeaderSize+msgs.NonceSize)

	var parsed msgs.Challenge
	require.NoError(t, parsed.Unmarshal(data))
	assert.Equal(t, orig.Header.SPDMVersion, parsed.Header.SPDMVersion)
	assert.Equal(t, orig.Header.Param1, parsed.Header.Param1)
	assert.Equal(t, orig.Header.Param2, parsed.Header.Param2)
	assert.Equal(t, orig.Nonce, parsed.Nonce)
}

func TestMsgs_Challenge_UnmarshalShortBuffer(t *testing.T) {
	var m msgs.Challenge
	assert.ErrorIs(t, m.Unmarshal(make([]byte, msgs.HeaderSize+msgs.NonceSize-1)), msgs.ErrShortBuffer)
	assert.ErrorIs(t, m.Unmarshal(nil), msgs.ErrShortBuffer)
}

// ---------------------------------------------------------------------------
// ChallengeAuthResponse (challenge.go)
// ---------------------------------------------------------------------------

func TestMsgs_ChallengeAuthResponse_ResponseCode(t *testing.T) {
	var m msgs.ChallengeAuthResponse
	assert.Equal(t, codes.ResponseChallengeAuth, m.ResponseCode())
}

func TestMsgs_ChallengeAuthResponse_SlotID(t *testing.T) {
	m := msgs.ChallengeAuthResponse{Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{Param1: 0xF3}}}
	assert.Equal(t, uint8(0x03), m.SlotID())
}

func TestMsgs_ChallengeAuthResponse_MarshalUnmarshalV12(t *testing.T) {
	digestSize := 32
	sigSize := 64
	measHashSize := 0 // NoMeasurementSummaryHash

	orig := &msgs.ChallengeAuthResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseChallengeAuth),
			Param1:              0x01,
			Param2:              0x00,
		}},
		CertChainHash:          bytes.Repeat([]byte{0xAA}, digestSize),
		MeasurementSummaryHash: make([]byte, measHashSize),
		OpaqueData:             []byte{0x01, 0x02, 0x03},
		Signature:              bytes.Repeat([]byte{0xBB}, sigSize),
	}
	for i := range orig.Nonce {
		orig.Nonce[i] = byte(i + 0x10)
	}

	data, err := orig.Marshal()
	require.NoError(t, err)

	// SPDM 1.2: no RequesterContext
	expectedSize := msgs.HeaderSize + digestSize + msgs.NonceSize + measHashSize + 2 + len(orig.OpaqueData) + sigSize
	assert.Len(t, data, expectedSize)

	var parsed msgs.ChallengeAuthResponse
	require.NoError(t, parsed.UnmarshalWithSizes(data, digestSize, measHashSize, sigSize))
	assert.Equal(t, orig.CertChainHash, parsed.CertChainHash)
	assert.Equal(t, orig.Nonce, parsed.Nonce)
	assert.Equal(t, orig.OpaqueData, parsed.OpaqueData)
	assert.Equal(t, orig.Signature, parsed.Signature)
}

func TestMsgs_ChallengeAuthResponse_MarshalUnmarshalV13(t *testing.T) {
	digestSize := 48
	sigSize := 96
	measHashSize := 48

	orig := &msgs.ChallengeAuthResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x13,
			RequestResponseCode: uint8(codes.ResponseChallengeAuth),
			Param1:              0x02,
		}},
		CertChainHash:          bytes.Repeat([]byte{0xCC}, digestSize),
		MeasurementSummaryHash: bytes.Repeat([]byte{0xDD}, measHashSize),
		OpaqueData:             []byte{0x10, 0x20},
		Signature:              bytes.Repeat([]byte{0xEE}, sigSize),
	}
	for i := range orig.Nonce {
		orig.Nonce[i] = byte(i)
	}
	for i := range orig.RequesterContext {
		orig.RequesterContext[i] = byte(i + 0x80)
	}

	data, err := orig.Marshal()
	require.NoError(t, err)

	// SPDM 1.3: includes RequesterContext
	expectedSize := msgs.HeaderSize + digestSize + msgs.NonceSize + measHashSize + 2 + len(orig.OpaqueData) + msgs.ReqContextSize + sigSize
	assert.Len(t, data, expectedSize)

	var parsed msgs.ChallengeAuthResponse
	require.NoError(t, parsed.UnmarshalWithSizes(data, digestSize, measHashSize, sigSize))
	assert.Equal(t, orig.CertChainHash, parsed.CertChainHash)
	assert.Equal(t, orig.Nonce, parsed.Nonce)
	assert.Equal(t, orig.MeasurementSummaryHash, parsed.MeasurementSummaryHash)
	assert.Equal(t, orig.OpaqueData, parsed.OpaqueData)
	assert.Equal(t, orig.RequesterContext, parsed.RequesterContext)
	assert.Equal(t, orig.Signature, parsed.Signature)
}

func TestMsgs_ChallengeAuthResponse_UnmarshalHeaderOnly(t *testing.T) {
	orig := &msgs.ChallengeAuthResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseChallengeAuth),
			Param1:              0x05,
		}},
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var parsed msgs.ChallengeAuthResponse
	require.NoError(t, parsed.Unmarshal(data))
	assert.Equal(t, uint8(0x12), parsed.Header.SPDMVersion)
	assert.Equal(t, uint8(0x05), parsed.Header.Param1)
}

func TestMsgs_ChallengeAuthResponse_UnmarshalShortBuffer(t *testing.T) {
	var m msgs.ChallengeAuthResponse
	assert.ErrorIs(t, m.Unmarshal(make([]byte, msgs.HeaderSize-1)), msgs.ErrShortBuffer)
	assert.ErrorIs(t, m.UnmarshalWithSizes(make([]byte, msgs.HeaderSize-1), 32, 0, 64), msgs.ErrShortBuffer)
	// Short in cert_chain_hash region
	assert.ErrorIs(t, m.UnmarshalWithSizes(make([]byte, msgs.HeaderSize+10), 32, 0, 64), msgs.ErrShortBuffer)
}

// ---------------------------------------------------------------------------
// Digests (digests.go)
// ---------------------------------------------------------------------------

func TestMsgs_GetDigests_RequestCode(t *testing.T) {
	var m msgs.GetDigests
	assert.Equal(t, codes.RequestGetDigests, m.RequestCode())
}

func TestMsgs_GetDigests_Unmarshal(t *testing.T) {
	orig := &msgs.GetDigests{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetDigests),
		}},
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var parsed msgs.GetDigests
	require.NoError(t, parsed.Unmarshal(data))
	assert.Equal(t, uint8(0x12), parsed.Header.SPDMVersion)
}

func TestMsgs_DigestResponse_ResponseCode(t *testing.T) {
	var m msgs.DigestResponse
	assert.Equal(t, codes.ResponseDigests, m.ResponseCode())
}

func TestMsgs_DigestResponse_UnmarshalHeaderOnly(t *testing.T) {
	orig := &msgs.DigestResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseDigests),
			Param2:              0x03, // slots 0 and 1
		}},
		Digests: [][]byte{
			bytes.Repeat([]byte{0xAA}, 32),
			bytes.Repeat([]byte{0xBB}, 32),
		},
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var parsed msgs.DigestResponse
	require.NoError(t, parsed.Unmarshal(data))
	assert.Equal(t, uint8(0x03), parsed.Header.Param2)
	assert.Nil(t, parsed.Digests) // header-only unmarshal does not parse digests
}

func TestMsgs_DigestResponse_UnmarshalWithDigestSize(t *testing.T) {
	digestSize := 32
	// Param2 = 0x05 means slots 0 and 2 set (2 bits)
	orig := &msgs.DigestResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseDigests),
			Param2:              0x05,
		}},
		Digests: [][]byte{
			bytes.Repeat([]byte{0xAA}, digestSize),
			bytes.Repeat([]byte{0xBB}, digestSize),
		},
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var parsed msgs.DigestResponse
	require.NoError(t, parsed.UnmarshalWithDigestSize(data, digestSize))
	require.Len(t, parsed.Digests, 2)
	assert.Equal(t, orig.Digests[0], parsed.Digests[0])
	assert.Equal(t, orig.Digests[1], parsed.Digests[1])
}

func TestMsgs_DigestResponse_UnmarshalWithDigestSizeShortBuffer(t *testing.T) {
	var m msgs.DigestResponse
	assert.ErrorIs(t, m.UnmarshalWithDigestSize(make([]byte, msgs.HeaderSize-1), 32), msgs.ErrShortBuffer)

	// Valid header but not enough room for the digests
	buf := []byte{0x12, uint8(codes.ResponseDigests), 0x00, 0x03} // 2 slots, but no digest data
	assert.ErrorIs(t, m.UnmarshalWithDigestSize(buf, 32), msgs.ErrShortBuffer)
}

// ---------------------------------------------------------------------------
// Measurements (measurements.go)
// ---------------------------------------------------------------------------

func TestMsgs_GetMeasurements_RequestCode(t *testing.T) {
	var m msgs.GetMeasurements
	assert.Equal(t, codes.RequestGetMeasurements, m.RequestCode())
}

func TestMsgs_MeasurementsResponse_ResponseCode(t *testing.T) {
	var m msgs.MeasurementsResponse
	assert.Equal(t, codes.ResponseMeasurements, m.ResponseCode())
}

func TestMsgs_ParseMeasurementBlocks_Normal(t *testing.T) {
	// Single block: Index=1, Spec=1, ValueType=0x01, Value="test"
	record := []byte{
		1,    // Index
		0x01, // MeasurementSpecification
		7, 0, // MeasurementSize = 3 (DMTF header) + 4 (value) = 7
		0x01, // ValueType
		4, 0, // ValueSize = 4
		't', 'e', 's', 't',
	}

	blocks, err := msgs.ParseMeasurementBlocks(record)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	assert.Equal(t, uint8(1), blocks[0].Index)
	assert.Equal(t, uint8(0x01), blocks[0].Spec)
	assert.Equal(t, uint8(0x01), blocks[0].ValueType)
	assert.Equal(t, []byte("test"), blocks[0].Value)
}

func TestMsgs_ParseMeasurementBlocks_MultipleBlocks(t *testing.T) {
	block1 := []byte{
		1, 0x01, 7, 0,
		0x01, 4, 0,
		'a', 'b', 'c', 'd',
	}
	block2 := []byte{
		2, 0x01, 5, 0,
		0x02, 2, 0,
		'x', 'y',
	}
	record := append(block1, block2...)

	blocks, err := msgs.ParseMeasurementBlocks(record)
	require.NoError(t, err)
	require.Len(t, blocks, 2)
	assert.Equal(t, uint8(1), blocks[0].Index)
	assert.Equal(t, []byte("abcd"), blocks[0].Value)
	assert.Equal(t, uint8(2), blocks[1].Index)
	assert.Equal(t, []byte("xy"), blocks[1].Value)
}

func TestMsgs_ParseMeasurementBlocks_ShortBuffer(t *testing.T) {
	// Too short to even have the block header
	_, err := msgs.ParseMeasurementBlocks([]byte{0x01, 0x01, 0x07})
	assert.ErrorIs(t, err, msgs.ErrShortBuffer)

	// Block header says 7 bytes of measurement data, but only 3 available
	_, err = msgs.ParseMeasurementBlocks([]byte{1, 0x01, 7, 0, 0x01, 4, 0})
	assert.ErrorIs(t, err, msgs.ErrShortBuffer)
}

func TestMsgs_ParseMeasurementBlocks_InvalidField(t *testing.T) {
	// DMTF header claims ValueSize=100, but MeasurementSize is only 7 (3+4)
	// 3 + 100 > 7 => ErrInvalidField
	record := []byte{
		1, 0x01, 7, 0,
		0x01, 100, 0, // ValueSize=100, but total MeasSize=7
		't', 'e', 's', 't',
	}
	_, err := msgs.ParseMeasurementBlocks(record)
	assert.ErrorIs(t, err, msgs.ErrInvalidField)
}

func TestMsgs_ParseMeasurementBlocks_Empty(t *testing.T) {
	blocks, err := msgs.ParseMeasurementBlocks(nil)
	require.NoError(t, err)
	assert.Empty(t, blocks)
}

// ---------------------------------------------------------------------------
// Version (version.go)
// ---------------------------------------------------------------------------

func TestMsgs_GetVersion_RequestCode(t *testing.T) {
	var m msgs.GetVersion
	assert.Equal(t, codes.RequestGetVersion, m.RequestCode())
}

func TestMsgs_GetVersion_Unmarshal(t *testing.T) {
	orig := &msgs.GetVersion{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x10,
			RequestResponseCode: uint8(codes.RequestGetVersion),
		}},
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var parsed msgs.GetVersion
	require.NoError(t, parsed.Unmarshal(data))
	assert.Equal(t, uint8(0x10), parsed.Header.SPDMVersion)
}

func TestMsgs_VersionResponse_ResponseCode(t *testing.T) {
	var m msgs.VersionResponse
	assert.Equal(t, codes.ResponseVersion, m.ResponseCode())
}

func TestMsgs_VersionResponse_MarshalUnmarshalRoundTrip(t *testing.T) {
	orig := &msgs.VersionResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x10,
			RequestResponseCode: uint8(codes.ResponseVersion),
		}},
		VersionEntries: []uint16{0x1000, 0x1100, 0x1200},
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var parsed msgs.VersionResponse
	require.NoError(t, parsed.Unmarshal(data))
	assert.Equal(t, uint8(3), parsed.VersionNumberEntryCount)
	assert.Equal(t, orig.VersionEntries, parsed.VersionEntries)
}

func TestMsgs_VersionResponse_UnmarshalShortBuffer(t *testing.T) {
	var m msgs.VersionResponse
	assert.ErrorIs(t, m.Unmarshal(make([]byte, msgs.HeaderSize+1)), msgs.ErrShortBuffer)
	// Header says 2 entries but buffer is too short
	buf := []byte{0x10, uint8(codes.ResponseVersion), 0, 0, 0, 2}
	assert.ErrorIs(t, m.Unmarshal(buf), msgs.ErrShortBuffer)
}

// ---------------------------------------------------------------------------
// Capabilities (capabilities.go)
// ---------------------------------------------------------------------------

func TestMsgs_GetCapabilities_RequestCode(t *testing.T) {
	var m msgs.GetCapabilities
	assert.Equal(t, codes.RequestGetCapabilities, m.RequestCode())
}

func TestMsgs_GetCapabilities_MarshalUnmarshalRoundTrip(t *testing.T) {
	orig := &msgs.GetCapabilities{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetCapabilities),
		}},
		CTExponent:       10,
		Flags:            0x0000FFFF,
		DataTransferSize: 4096,
		MaxSPDMmsgSize:   4096,
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var parsed msgs.GetCapabilities
	require.NoError(t, parsed.Unmarshal(data))
	assert.Equal(t, orig.CTExponent, parsed.CTExponent)
	assert.Equal(t, orig.Flags, parsed.Flags)
	assert.Equal(t, orig.DataTransferSize, parsed.DataTransferSize)
	assert.Equal(t, orig.MaxSPDMmsgSize, parsed.MaxSPDMmsgSize)
}

func TestMsgs_GetCapabilities_UnmarshalShortBuffer(t *testing.T) {
	var m msgs.GetCapabilities
	assert.ErrorIs(t, m.Unmarshal(make([]byte, msgs.HeaderSize+3)), msgs.ErrShortBuffer)
}

func TestMsgs_CapabilitiesResponse_ResponseCode(t *testing.T) {
	var m msgs.CapabilitiesResponse
	assert.Equal(t, codes.ResponseCapabilities, m.ResponseCode())
}

func TestMsgs_CapabilitiesResponse_MarshalUnmarshalRoundTrip(t *testing.T) {
	orig := &msgs.CapabilitiesResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseCapabilities),
		}},
		CTExponent:       12,
		Flags:            0x00001234,
		DataTransferSize: 8192,
		MaxSPDMmsgSize:   8192,
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var parsed msgs.CapabilitiesResponse
	require.NoError(t, parsed.Unmarshal(data))
	assert.Equal(t, orig.CTExponent, parsed.CTExponent)
	assert.Equal(t, orig.Flags, parsed.Flags)
	assert.Equal(t, orig.DataTransferSize, parsed.DataTransferSize)
}

// ---------------------------------------------------------------------------
// Algorithms (algorithms.go)
// ---------------------------------------------------------------------------

func TestMsgs_NegotiateAlgorithms_RequestCode(t *testing.T) {
	var m msgs.NegotiateAlgorithms
	assert.Equal(t, codes.RequestNegotiateAlgorithms, m.RequestCode())
}

func TestMsgs_NegotiateAlgorithms_MarshalUnmarshalRoundTrip(t *testing.T) {
	orig := &msgs.NegotiateAlgorithms{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestNegotiateAlgorithms),
			Param1:              2, // number of AlgStructs
		}},
		MeasurementSpecification: 0x01,
		OtherParamsSupport:       0x02,
		BaseAsymAlgo:             0x00000060,
		BaseHashAlgo:             0x00000002,
		AlgStructs: []msgs.AlgStructTable{
			{AlgType: msgs.AlgTypeDHE, AlgCount: 0x20, AlgSupported: 0x0008},
			{AlgType: msgs.AlgTypeAEAD, AlgCount: 0x20, AlgSupported: 0x0002},
		},
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var parsed msgs.NegotiateAlgorithms
	require.NoError(t, parsed.Unmarshal(data))
	assert.Equal(t, orig.BaseAsymAlgo, parsed.BaseAsymAlgo)
	assert.Equal(t, orig.BaseHashAlgo, parsed.BaseHashAlgo)
	assert.Equal(t, orig.OtherParamsSupport, parsed.OtherParamsSupport)
	require.Len(t, parsed.AlgStructs, 2)
	assert.Equal(t, orig.AlgStructs[0].AlgType, parsed.AlgStructs[0].AlgType)
	assert.Equal(t, orig.AlgStructs[1].AlgSupported, parsed.AlgStructs[1].AlgSupported)
}

func TestMsgs_NegotiateAlgorithms_UnmarshalShortBuffer(t *testing.T) {
	var m msgs.NegotiateAlgorithms
	assert.ErrorIs(t, m.Unmarshal(make([]byte, 31)), msgs.ErrShortBuffer)
}

func TestMsgs_AlgorithmsResponse_ResponseCode(t *testing.T) {
	var m msgs.AlgorithmsResponse
	assert.Equal(t, codes.ResponseAlgorithms, m.ResponseCode())
}

func TestMsgs_AlgorithmsResponse_MarshalUnmarshalRoundTrip(t *testing.T) {
	orig := &msgs.AlgorithmsResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseAlgorithms),
			Param1:              1,
		}},
		MeasurementSpecificationSel: 0x01,
		OtherParamsSelection:        0x02,
		MeasurementHashAlgo:         0x00000002,
		BaseAsymSel:                 0x00000060,
		BaseHashSel:                 0x00000002,
		AlgStructs: []msgs.AlgStructTable{
			{AlgType: msgs.AlgTypeDHE, AlgCount: 0x20, AlgSupported: 0x0008},
		},
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var parsed msgs.AlgorithmsResponse
	require.NoError(t, parsed.Unmarshal(data))
	assert.Equal(t, orig.BaseAsymSel, parsed.BaseAsymSel)
	assert.Equal(t, orig.BaseHashSel, parsed.BaseHashSel)
	assert.Equal(t, orig.MeasurementHashAlgo, parsed.MeasurementHashAlgo)
	require.Len(t, parsed.AlgStructs, 1)
	assert.Equal(t, orig.AlgStructs[0].AlgSupported, parsed.AlgStructs[0].AlgSupported)
}

func TestMsgs_AlgorithmsResponse_UnmarshalShortBuffer(t *testing.T) {
	var m msgs.AlgorithmsResponse
	assert.ErrorIs(t, m.Unmarshal(make([]byte, 35)), msgs.ErrShortBuffer)
}

// ---------------------------------------------------------------------------
// Certificate (certificate.go)
// ---------------------------------------------------------------------------

func TestMsgs_GetCertificate_RequestCode(t *testing.T) {
	var m msgs.GetCertificate
	assert.Equal(t, codes.RequestGetCertificate, m.RequestCode())
}

func TestMsgs_GetCertificate_MarshalUnmarshalRoundTrip(t *testing.T) {
	orig := &msgs.GetCertificate{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetCertificate),
			Param1:              0x01,
		}},
		Offset: 0x0100,
		Length: 0x0400,
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var parsed msgs.GetCertificate
	require.NoError(t, parsed.Unmarshal(data))
	assert.Equal(t, uint16(0x0100), parsed.Offset)
	assert.Equal(t, uint16(0x0400), parsed.Length)
	assert.Equal(t, uint8(0x01), parsed.SlotID())
}

func TestMsgs_GetCertificate_UnmarshalShortBuffer(t *testing.T) {
	var m msgs.GetCertificate
	assert.ErrorIs(t, m.Unmarshal(make([]byte, msgs.HeaderSize+3)), msgs.ErrShortBuffer)
}

func TestMsgs_CertificateResponse_ResponseCode(t *testing.T) {
	var m msgs.CertificateResponse
	assert.Equal(t, codes.ResponseCertificate, m.ResponseCode())
}

func TestMsgs_CertificateResponse_MarshalUnmarshalRoundTrip(t *testing.T) {
	certChain := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	orig := &msgs.CertificateResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseCertificate),
			Param1:              0x02,
		}},
		PortionLength:   uint16(len(certChain)),
		RemainderLength: 0x1000,
		CertChain:       certChain,
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var parsed msgs.CertificateResponse
	require.NoError(t, parsed.Unmarshal(data))
	assert.Equal(t, uint16(len(certChain)), parsed.PortionLength)
	assert.Equal(t, uint16(0x1000), parsed.RemainderLength)
	assert.Equal(t, certChain, parsed.CertChain)
	assert.Equal(t, uint8(0x02), parsed.SlotID())
}

func TestMsgs_CertificateResponse_UnmarshalShortBuffer(t *testing.T) {
	var m msgs.CertificateResponse
	assert.ErrorIs(t, m.Unmarshal(make([]byte, msgs.HeaderSize+3)), msgs.ErrShortBuffer)

	// Header says portion_length=10 but buffer is too short
	buf := []byte{0x12, uint8(codes.ResponseCertificate), 0, 0, 10, 0, 0, 0}
	assert.ErrorIs(t, m.Unmarshal(buf), msgs.ErrShortBuffer)
}

// ---------------------------------------------------------------------------
// Finish (finish.go)
// ---------------------------------------------------------------------------

func TestMsgs_Finish_RequestCode(t *testing.T) {
	var m msgs.Finish
	assert.Equal(t, codes.RequestFinish, m.RequestCode())
}

func TestMsgs_Finish_UnmarshalHeaderOnly(t *testing.T) {
	orig := &msgs.Finish{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestFinish),
			Param1:              0x01,
			Param2:              0x00,
		}},
		Signature:  bytes.Repeat([]byte{0xAA}, 64),
		VerifyData: bytes.Repeat([]byte{0xBB}, 32),
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var parsed msgs.Finish
	require.NoError(t, parsed.Unmarshal(data))
	assert.Equal(t, uint8(0x12), parsed.Header.SPDMVersion)
	assert.Equal(t, uint8(0x01), parsed.Header.Param1)
	assert.True(t, parsed.SignatureIncluded())
}

func TestMsgs_Finish_UnmarshalWithSizes(t *testing.T) {
	sigSize := 64
	hashSize := 32
	orig := &msgs.Finish{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestFinish),
			Param1:              0x01, // signature included
			Param2:              0x00,
		}},
		Signature:  bytes.Repeat([]byte{0xAA}, sigSize),
		VerifyData: bytes.Repeat([]byte{0xBB}, hashSize),
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var parsed msgs.Finish
	require.NoError(t, parsed.UnmarshalWithSizes(data, sigSize, hashSize))
	assert.Equal(t, orig.Signature, parsed.Signature)
	assert.Equal(t, orig.VerifyData, parsed.VerifyData)
}

func TestMsgs_Finish_UnmarshalWithSizesNoSignature(t *testing.T) {
	hashSize := 32
	orig := &msgs.Finish{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestFinish),
			Param1:              0x00, // no signature
		}},
		VerifyData: bytes.Repeat([]byte{0xCC}, hashSize),
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var parsed msgs.Finish
	require.NoError(t, parsed.UnmarshalWithSizes(data, 64, hashSize))
	assert.Nil(t, parsed.Signature)
	assert.Equal(t, orig.VerifyData, parsed.VerifyData)
}

func TestMsgs_Finish_UnmarshalWithSizesShortBuffer(t *testing.T) {
	var m msgs.Finish
	assert.ErrorIs(t, m.UnmarshalWithSizes(make([]byte, 3), 64, 32), msgs.ErrShortBuffer)

	// Has header + signature bit set, but not enough for signature
	buf := []byte{0x12, uint8(codes.RequestFinish), 0x01, 0x00, 0xAA}
	assert.ErrorIs(t, m.UnmarshalWithSizes(buf, 64, 32), msgs.ErrShortBuffer)
}

func TestMsgs_FinishResponse_ResponseCode(t *testing.T) {
	var m msgs.FinishResponse
	assert.Equal(t, codes.ResponseFinishRsp, m.ResponseCode())
}

func TestMsgs_FinishResponse_UnmarshalHeaderOnly(t *testing.T) {
	orig := &msgs.FinishResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseFinishRsp),
		}},
		VerifyData: bytes.Repeat([]byte{0xDD}, 32),
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var parsed msgs.FinishResponse
	require.NoError(t, parsed.Unmarshal(data))
	assert.Equal(t, uint8(0x12), parsed.Header.SPDMVersion)
	assert.Nil(t, parsed.VerifyData)
}

func TestMsgs_FinishResponse_UnmarshalWithHashSize(t *testing.T) {
	hashSize := 32
	orig := &msgs.FinishResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseFinishRsp),
		}},
		VerifyData: bytes.Repeat([]byte{0xEE}, hashSize),
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var parsed msgs.FinishResponse
	require.NoError(t, parsed.UnmarshalWithHashSize(data, hashSize))
	assert.Equal(t, orig.VerifyData, parsed.VerifyData)
}

// ---------------------------------------------------------------------------
// PSK (psk.go)
// ---------------------------------------------------------------------------

func TestMsgs_PSKFinish_RequestCode(t *testing.T) {
	var m msgs.PSKFinish
	assert.Equal(t, codes.RequestPSKFinish, m.RequestCode())
}

func TestMsgs_PSKFinish_UnmarshalHeaderOnly(t *testing.T) {
	orig := &msgs.PSKFinish{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestPSKFinish),
		}},
		VerifyData: bytes.Repeat([]byte{0xFF}, 32),
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var parsed msgs.PSKFinish
	require.NoError(t, parsed.Unmarshal(data))
	assert.Equal(t, uint8(0x12), parsed.Header.SPDMVersion)
	assert.Nil(t, parsed.VerifyData) // header-only unmarshal
}

func TestMsgs_PSKFinish_MarshalUnmarshalRoundTrip(t *testing.T) {
	orig := &msgs.PSKFinish{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestPSKFinish),
		}},
		VerifyData: bytes.Repeat([]byte{0xAB}, 48),
	}
	data, err := orig.Marshal()
	require.NoError(t, err)
	assert.Len(t, data, msgs.HeaderSize+48)

	// Unmarshal only parses header
	var parsed msgs.PSKFinish
	require.NoError(t, parsed.Unmarshal(data))
	assert.Equal(t, orig.Header.SPDMVersion, parsed.Header.SPDMVersion)
}

func TestMsgs_PSKFinishResponse_ResponseCode(t *testing.T) {
	var m msgs.PSKFinishResponse
	assert.Equal(t, codes.ResponsePSKFinishRsp, m.ResponseCode())
}

func TestMsgs_PSKFinishResponse_MarshalUnmarshalRoundTrip(t *testing.T) {
	orig := &msgs.PSKFinishResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponsePSKFinishRsp),
		}},
	}
	data, err := orig.Marshal()
	require.NoError(t, err)
	assert.Len(t, data, msgs.HeaderSize)

	var parsed msgs.PSKFinishResponse
	require.NoError(t, parsed.Unmarshal(data))
	assert.Equal(t, orig.Header.SPDMVersion, parsed.Header.SPDMVersion)
}

// ---------------------------------------------------------------------------
// PSKExchange (psk.go) - bonus coverage
// ---------------------------------------------------------------------------

func TestMsgs_PSKExchange_MarshalUnmarshalRoundTrip(t *testing.T) {
	orig := &msgs.PSKExchange{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestPSKExchange),
		}},
		ReqSessionID: 0x1234,
		PSKHint:      []byte("hint"),
		Context:      []byte("ctx"),
		OpaqueData:   []byte{0x01, 0x02},
	}
	data, err := orig.Marshal()
	require.NoError(t, err)

	var parsed msgs.PSKExchange
	require.NoError(t, parsed.Unmarshal(data))
	assert.Equal(t, uint16(0x1234), parsed.ReqSessionID)
	assert.Equal(t, []byte("hint"), parsed.PSKHint)
	assert.Equal(t, []byte("ctx"), parsed.Context)
	assert.Equal(t, []byte{0x01, 0x02}, parsed.OpaqueData)
}

func TestMsgs_PSKExchange_UnmarshalShortBuffer(t *testing.T) {
	var m msgs.PSKExchange
	assert.ErrorIs(t, m.Unmarshal(make([]byte, msgs.HeaderSize+7)), msgs.ErrShortBuffer)
}

// ---------------------------------------------------------------------------
// MeasurementsResponse marshal/unmarshal (measurements.go)
// ---------------------------------------------------------------------------

func TestMsgs_MeasurementsResponse_MarshalUnmarshalRoundTrip(t *testing.T) {
	record := []byte{
		1, 0x01, 7, 0,
		0x01, 4, 0,
		't', 'e', 's', 't',
	}
	orig := &msgs.MeasurementsResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseMeasurements),
		}},
		NumberOfBlocks:       1,
		MeasurementRecordLen: uint32(len(record)),
		MeasurementRecord:    record,
		OpaqueData:           []byte{0xAA, 0xBB},
	}
	for i := range orig.Nonce {
		orig.Nonce[i] = byte(i)
	}

	data, err := orig.Marshal()
	require.NoError(t, err)

	var parsed msgs.MeasurementsResponse
	require.NoError(t, parsed.Unmarshal(data))
	assert.Equal(t, uint8(1), parsed.NumberOfBlocks)
	assert.Equal(t, uint32(len(record)), parsed.MeasurementRecordLen)
	assert.Equal(t, record, parsed.MeasurementRecord)
	assert.Equal(t, orig.Nonce, parsed.Nonce)
	assert.Equal(t, orig.OpaqueData, parsed.OpaqueData)
}

func TestMsgs_MeasurementsResponse_UnmarshalShortBuffer(t *testing.T) {
	var m msgs.MeasurementsResponse
	assert.ErrorIs(t, m.Unmarshal(make([]byte, msgs.HeaderSize+3)), msgs.ErrShortBuffer)

	// Header + block count + record length says 100 bytes but not present
	buf := []byte{0x12, uint8(codes.ResponseMeasurements), 0, 0, 1, 100, 0, 0}
	assert.ErrorIs(t, m.Unmarshal(buf), msgs.ErrShortBuffer)
}
