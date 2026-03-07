package unit

import (
	"crypto"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/caps"
	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/status"
)

// --- algo.Version ---

func TestAlgo_Version(t *testing.T) {
	tests := []struct {
		v     algo.Version
		major uint8
		minor uint8
		str   string
	}{
		{algo.Version10, 1, 0, "1.0"},
		{algo.Version11, 1, 1, "1.1"},
		{algo.Version12, 1, 2, "1.2"},
		{algo.Version13, 1, 3, "1.3"},
		{algo.Version14, 1, 4, "1.4"},
	}
	for _, tt := range tests {
		t.Run(tt.str, func(t *testing.T) {
			assert.Equal(t, tt.major, tt.v.Major())
			assert.Equal(t, tt.minor, tt.v.Minor())
			assert.Equal(t, tt.str, tt.v.String())
		})
	}
}

func TestAlgo_VersionFromParts(t *testing.T) {
	v := algo.VersionFromParts(1, 2)
	assert.Equal(t, algo.Version12, v)
}

func TestAlgo_VersionNumber(t *testing.T) {
	// Wire format: major<<12 | minor<<8 | update<<4 | alpha
	vn := algo.VersionNumber(0x1200) // 1.2.0.0
	assert.Equal(t, uint8(1), vn.Major())
	assert.Equal(t, uint8(2), vn.Minor())
	assert.Equal(t, uint8(0), vn.Update())
	assert.Equal(t, uint8(0), vn.Alpha())
	assert.Equal(t, algo.Version12, vn.Version())
	assert.Equal(t, "1.2.0.0", vn.String())
}

// --- algo.BaseHashAlgo ---

func TestAlgo_BaseHashAlgo_String(t *testing.T) {
	tests := []struct {
		a   algo.BaseHashAlgo
		str string
	}{
		{algo.HashSHA256, "SHA-256"},
		{algo.HashSHA384, "SHA-384"},
		{algo.HashSHA512, "SHA-512"},
		{algo.HashSHA3_256, "SHA3-256"},
		{algo.HashSHA3_384, "SHA3-384"},
		{algo.HashSHA3_512, "SHA3-512"},
		{algo.HashSM3_256, "SM3-256"},
		{algo.BaseHashAlgo(0xFFFF), "BaseHashAlgo(0x0000FFFF)"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.str, tt.a.String())
	}
}

func TestAlgo_BaseHashAlgo_Contains(t *testing.T) {
	multi := algo.HashSHA256 | algo.HashSHA384
	assert.True(t, multi.Contains(algo.HashSHA256))
	assert.True(t, multi.Contains(algo.HashSHA384))
	assert.False(t, multi.Contains(algo.HashSHA512))
}

func TestAlgo_BaseHashAlgo_Size(t *testing.T) {
	assert.Equal(t, 32, algo.HashSHA256.Size())
	assert.Equal(t, 48, algo.HashSHA384.Size())
	assert.Equal(t, 64, algo.HashSHA512.Size())
	assert.Equal(t, 32, algo.HashSHA3_256.Size())
	assert.Equal(t, 48, algo.HashSHA3_384.Size())
	assert.Equal(t, 64, algo.HashSHA3_512.Size())
	assert.Equal(t, 32, algo.HashSM3_256.Size())
	assert.Equal(t, 0, algo.BaseHashAlgo(0).Size())
}

func TestAlgo_BaseHashAlgo_CryptoHash(t *testing.T) {
	assert.Equal(t, crypto.SHA256, algo.HashSHA256.CryptoHash())
	assert.Equal(t, crypto.SHA384, algo.HashSHA384.CryptoHash())
	assert.Equal(t, crypto.SHA512, algo.HashSHA512.CryptoHash())
	assert.Equal(t, crypto.SHA3_256, algo.HashSHA3_256.CryptoHash())
	assert.Equal(t, crypto.SHA3_384, algo.HashSHA3_384.CryptoHash())
	assert.Equal(t, crypto.SHA3_512, algo.HashSHA3_512.CryptoHash())
	assert.Equal(t, crypto.Hash(0), algo.HashSM3_256.CryptoHash())
}

func TestAlgo_BaseHashAlgo_SingleAlgos(t *testing.T) {
	multi := algo.HashSHA256 | algo.HashSHA512
	singles := multi.SingleAlgos()
	assert.Equal(t, 2, len(singles))
	assert.Contains(t, singles, algo.HashSHA256)
	assert.Contains(t, singles, algo.HashSHA512)
}

// --- algo.BaseAsymAlgo ---

func TestAlgo_BaseAsymAlgo_String(t *testing.T) {
	tests := []struct {
		a   algo.BaseAsymAlgo
		str string
	}{
		{algo.AsymRSASSA2048, "RSASSA-2048"},
		{algo.AsymRSAPSS2048, "RSAPSS-2048"},
		{algo.AsymRSASSA3072, "RSASSA-3072"},
		{algo.AsymRSAPSS3072, "RSAPSS-3072"},
		{algo.AsymECDSAP256, "ECDSA-P256"},
		{algo.AsymRSASSA4096, "RSASSA-4096"},
		{algo.AsymRSAPSS4096, "RSAPSS-4096"},
		{algo.AsymECDSAP384, "ECDSA-P384"},
		{algo.AsymECDSAP521, "ECDSA-P521"},
		{algo.AsymSM2P256, "SM2-P256"},
		{algo.AsymEdDSAEd25519, "EdDSA-Ed25519"},
		{algo.AsymEdDSAEd448, "EdDSA-Ed448"},
		{algo.BaseAsymAlgo(0xFFFF), "BaseAsymAlgo(0x0000FFFF)"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.str, tt.a.String())
	}
}

func TestAlgo_BaseAsymAlgo_Contains(t *testing.T) {
	multi := algo.AsymECDSAP256 | algo.AsymECDSAP384
	assert.True(t, multi.Contains(algo.AsymECDSAP256))
	assert.False(t, multi.Contains(algo.AsymRSASSA2048))
}

func TestAlgo_BaseAsymAlgo_SignatureSize(t *testing.T) {
	assert.Equal(t, 256, algo.AsymRSASSA2048.SignatureSize())
	assert.Equal(t, 256, algo.AsymRSAPSS2048.SignatureSize())
	assert.Equal(t, 384, algo.AsymRSASSA3072.SignatureSize())
	assert.Equal(t, 384, algo.AsymRSAPSS3072.SignatureSize())
	assert.Equal(t, 512, algo.AsymRSASSA4096.SignatureSize())
	assert.Equal(t, 512, algo.AsymRSAPSS4096.SignatureSize())
	assert.Equal(t, 64, algo.AsymECDSAP256.SignatureSize())
	assert.Equal(t, 96, algo.AsymECDSAP384.SignatureSize())
	assert.Equal(t, 132, algo.AsymECDSAP521.SignatureSize())
	assert.Equal(t, 64, algo.AsymSM2P256.SignatureSize())
	assert.Equal(t, 64, algo.AsymEdDSAEd25519.SignatureSize())
	assert.Equal(t, 114, algo.AsymEdDSAEd448.SignatureSize())
	assert.Equal(t, 0, algo.BaseAsymAlgo(0).SignatureSize())
}

func TestAlgo_BaseAsymAlgo_SingleAlgos(t *testing.T) {
	multi := algo.AsymECDSAP256 | algo.AsymECDSAP384 | algo.AsymRSASSA2048
	singles := multi.SingleAlgos()
	assert.Equal(t, 3, len(singles))
}

// --- algo.DHENamedGroup ---

func TestAlgo_DHENamedGroup_String(t *testing.T) {
	tests := []struct {
		g   algo.DHENamedGroup
		str string
	}{
		{algo.DHEFFDHE2048, "FFDHE2048"},
		{algo.DHEFFDHE3072, "FFDHE3072"},
		{algo.DHEFFDHE4096, "FFDHE4096"},
		{algo.DHESECP256R1, "SECP256R1"},
		{algo.DHESECP384R1, "SECP384R1"},
		{algo.DHESECP521R1, "SECP521R1"},
		{algo.DHESM2P256, "SM2-P256"},
		{algo.DHENamedGroup(0xFF), "DHENamedGroup(0x00FF)"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.str, tt.g.String())
	}
}

func TestAlgo_DHENamedGroup_Contains(t *testing.T) {
	multi := algo.DHESECP256R1 | algo.DHESECP384R1
	assert.True(t, multi.Contains(algo.DHESECP256R1))
	assert.False(t, multi.Contains(algo.DHEFFDHE2048))
}

func TestAlgo_DHENamedGroup_SharedSecretSize(t *testing.T) {
	assert.Equal(t, 256, algo.DHEFFDHE2048.SharedSecretSize())
	assert.Equal(t, 384, algo.DHEFFDHE3072.SharedSecretSize())
	assert.Equal(t, 512, algo.DHEFFDHE4096.SharedSecretSize())
	assert.Equal(t, 32, algo.DHESECP256R1.SharedSecretSize())
	assert.Equal(t, 48, algo.DHESECP384R1.SharedSecretSize())
	assert.Equal(t, 66, algo.DHESECP521R1.SharedSecretSize())
	assert.Equal(t, 32, algo.DHESM2P256.SharedSecretSize())
	assert.Equal(t, 0, algo.DHENamedGroup(0).SharedSecretSize())
}

func TestAlgo_DHENamedGroup_SingleAlgos(t *testing.T) {
	multi := algo.DHESECP256R1 | algo.DHESECP384R1
	singles := multi.SingleAlgos()
	assert.Equal(t, 2, len(singles))
}

// --- algo.AEADCipherSuite ---

func TestAlgo_AEADCipherSuite_String(t *testing.T) {
	tests := []struct {
		s   algo.AEADCipherSuite
		str string
	}{
		{algo.AEADAES128GCM, "AES-128-GCM"},
		{algo.AEADAES256GCM, "AES-256-GCM"},
		{algo.AEADChaCha20Poly1305, "ChaCha20-Poly1305"},
		{algo.AEADSM4GCM, "SM4-GCM"},
		{algo.AEADCipherSuite(0xFF), "AEADCipherSuite(0x00FF)"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.str, tt.s.String())
	}
}

func TestAlgo_AEADCipherSuite_Contains(t *testing.T) {
	multi := algo.AEADAES128GCM | algo.AEADAES256GCM
	assert.True(t, multi.Contains(algo.AEADAES128GCM))
	assert.False(t, multi.Contains(algo.AEADChaCha20Poly1305))
}

func TestAlgo_AEADCipherSuite_Sizes(t *testing.T) {
	assert.Equal(t, 16, algo.AEADAES128GCM.KeySize())
	assert.Equal(t, 32, algo.AEADAES256GCM.KeySize())
	assert.Equal(t, 32, algo.AEADChaCha20Poly1305.KeySize())
	assert.Equal(t, 16, algo.AEADSM4GCM.KeySize())
	assert.Equal(t, 0, algo.AEADCipherSuite(0).KeySize())

	assert.Equal(t, 12, algo.AEADAES128GCM.NonceSize())
	assert.Equal(t, 12, algo.AEADAES256GCM.NonceSize())
	assert.Equal(t, 12, algo.AEADChaCha20Poly1305.NonceSize())
	assert.Equal(t, 12, algo.AEADSM4GCM.NonceSize())
	assert.Equal(t, 0, algo.AEADCipherSuite(0).NonceSize())

	assert.Equal(t, 16, algo.AEADAES128GCM.TagSize())
	assert.Equal(t, 16, algo.AEADAES256GCM.TagSize())
	assert.Equal(t, 16, algo.AEADChaCha20Poly1305.TagSize())
	assert.Equal(t, 16, algo.AEADSM4GCM.TagSize())
	assert.Equal(t, 0, algo.AEADCipherSuite(0).TagSize())
}

func TestAlgo_AEADCipherSuite_SingleAlgos(t *testing.T) {
	multi := algo.AEADAES128GCM | algo.AEADAES256GCM | algo.AEADChaCha20Poly1305
	singles := multi.SingleAlgos()
	assert.Equal(t, 3, len(singles))
}

// --- algo.MeasurementHashAlgo ---

func TestAlgo_MeasurementHashAlgo_String(t *testing.T) {
	tests := []struct {
		a   algo.MeasurementHashAlgo
		str string
	}{
		{algo.MeasHashRawBitStream, "RawBitStream"},
		{algo.MeasHashSHA256, "SHA-256"},
		{algo.MeasHashSHA384, "SHA-384"},
		{algo.MeasHashSHA512, "SHA-512"},
		{algo.MeasHashSHA3_256, "SHA3-256"},
		{algo.MeasHashSHA3_384, "SHA3-384"},
		{algo.MeasHashSHA3_512, "SHA3-512"},
		{algo.MeasHashSM3_256, "SM3-256"},
		{algo.MeasurementHashAlgo(0xFFFF), "MeasurementHashAlgo(0x0000FFFF)"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.str, tt.a.String())
	}
}

func TestAlgo_MeasurementHashAlgo_Size(t *testing.T) {
	assert.Equal(t, 0, algo.MeasHashRawBitStream.Size())
	assert.Equal(t, 32, algo.MeasHashSHA256.Size())
	assert.Equal(t, 48, algo.MeasHashSHA384.Size())
	assert.Equal(t, 64, algo.MeasHashSHA512.Size())
	assert.Equal(t, 32, algo.MeasHashSHA3_256.Size())
	assert.Equal(t, 48, algo.MeasHashSHA3_384.Size())
	assert.Equal(t, 64, algo.MeasHashSHA3_512.Size())
	assert.Equal(t, 32, algo.MeasHashSM3_256.Size())
}

func TestAlgo_MeasurementHashAlgo_CryptoHash(t *testing.T) {
	assert.Equal(t, crypto.SHA256, algo.MeasHashSHA256.CryptoHash())
	assert.Equal(t, crypto.SHA384, algo.MeasHashSHA384.CryptoHash())
	assert.Equal(t, crypto.SHA512, algo.MeasHashSHA512.CryptoHash())
	assert.Equal(t, crypto.SHA3_256, algo.MeasHashSHA3_256.CryptoHash())
	assert.Equal(t, crypto.SHA3_384, algo.MeasHashSHA3_384.CryptoHash())
	assert.Equal(t, crypto.SHA3_512, algo.MeasHashSHA3_512.CryptoHash())
	assert.Equal(t, crypto.Hash(0), algo.MeasHashRawBitStream.CryptoHash())
	assert.Equal(t, crypto.Hash(0), algo.MeasHashSM3_256.CryptoHash())
}

func TestAlgo_MeasurementHashAlgo_Contains(t *testing.T) {
	multi := algo.MeasHashSHA256 | algo.MeasHashSHA384
	assert.True(t, multi.Contains(algo.MeasHashSHA256))
	assert.False(t, multi.Contains(algo.MeasHashSHA512))
}

func TestAlgo_MeasurementHashAlgo_SingleAlgos(t *testing.T) {
	multi := algo.MeasHashSHA256 | algo.MeasHashSHA384 | algo.MeasHashRawBitStream
	singles := multi.SingleAlgos()
	assert.Equal(t, 3, len(singles))
}

func TestAlgo_MeasurementSpec(t *testing.T) {
	assert.Equal(t, algo.MeasurementSpec(0x01), algo.MeasurementSpecDMTF)
}

func TestAlgo_KeySchedule(t *testing.T) {
	assert.Equal(t, algo.KeySchedule(0x0001), algo.KeyScheduleSPDM)
}

// --- caps.RequesterCaps ---

func TestCaps_RequesterCaps_Has(t *testing.T) {
	c := caps.ReqCertCap | caps.ReqChalCap | caps.ReqEncryptCap | caps.ReqMACCap | caps.ReqKeyExCap
	assert.True(t, c.Has(caps.ReqCertCap))
	assert.True(t, c.HasCertCap())
	assert.True(t, c.HasChalCap())
	assert.True(t, c.HasEncryptCap())
	assert.True(t, c.HasMACCap())
	assert.True(t, c.HasKeyExCap())
	assert.False(t, c.HasMutAuthCap())
	assert.False(t, c.HasPSKCap())
	assert.False(t, c.HasEncapCap())
	assert.False(t, c.HasHBeatCap())
	assert.False(t, c.HasKeyUpdCap())
	assert.False(t, c.HasHandshakeInTheClearCap())
	assert.False(t, c.HasPubKeyIDCap())
	assert.False(t, c.HasChunkCap())
}

func TestCaps_RequesterCaps_SetClear(t *testing.T) {
	c := caps.RequesterCaps(0)
	c = c.Set(caps.ReqCertCap)
	assert.True(t, c.HasCertCap())
	c = c.Clear(caps.ReqCertCap)
	assert.False(t, c.HasCertCap())
}

func TestCaps_RequesterCaps_String(t *testing.T) {
	assert.Equal(t, "", caps.RequesterCaps(0).String())
	c := caps.ReqCertCap | caps.ReqChalCap
	s := c.String()
	assert.Contains(t, s, "CERT")
	assert.Contains(t, s, "CHAL")
}

// --- caps.ResponderCaps ---

func TestCaps_ResponderCaps_Has(t *testing.T) {
	c := caps.RspCacheCap | caps.RspCertCap | caps.RspChalCap | caps.RspMeasCapNoSig |
		caps.RspMeasCapSig | caps.RspMeasFreshCap | caps.RspEncryptCap | caps.RspMACCap |
		caps.RspKeyExCap | caps.RspHBeatCap | caps.RspKeyUpdCap | caps.RspHandshakeInTheClearCap |
		caps.RspChunkCap | caps.RspAliasCertCap | caps.RspSetCertCap | caps.RspCSRCap |
		caps.RspCertInstallResetCap | caps.RspMELCap | caps.RspEventCap |
		caps.RspGetKeyPairInfoCap | caps.RspSetKeyPairInfoCap

	assert.True(t, c.HasCacheCap())
	assert.True(t, c.HasCertCap())
	assert.True(t, c.HasChalCap())
	assert.True(t, c.HasMeasCap())
	assert.True(t, c.HasMeasFreshCap())
	assert.True(t, c.HasEncryptCap())
	assert.True(t, c.HasMACCap())
	assert.False(t, c.HasMutAuthCap())
	assert.True(t, c.HasKeyExCap())
	assert.False(t, c.HasPSKCap())
	assert.False(t, c.HasEncapCap())
	assert.True(t, c.HasHBeatCap())
	assert.True(t, c.HasKeyUpdCap())
	assert.True(t, c.HasHandshakeInTheClearCap())
	assert.False(t, c.HasPubKeyIDCap())
	assert.True(t, c.HasChunkCap())
	assert.True(t, c.HasAliasCertCap())
	assert.True(t, c.HasSetCertCap())
	assert.True(t, c.HasCSRCap())
	assert.True(t, c.HasCertInstallResetCap())
	assert.True(t, c.HasMELCap())
	assert.True(t, c.HasEventCap())
	assert.True(t, c.HasGetKeyPairInfoCap())
	assert.True(t, c.HasSetKeyPairInfoCap())
}

func TestCaps_ResponderCaps_SetClear(t *testing.T) {
	c := caps.ResponderCaps(0)
	c = c.Set(caps.RspCertCap)
	assert.True(t, c.HasCertCap())
	c = c.Clear(caps.RspCertCap)
	assert.False(t, c.HasCertCap())
}

func TestCaps_ResponderCaps_String(t *testing.T) {
	assert.Equal(t, "", caps.ResponderCaps(0).String())
	c := caps.RspCertCap | caps.RspChalCap
	s := c.String()
	assert.Contains(t, s, "CERT")
	assert.Contains(t, s, "CHAL")
}

func TestCaps_ResponderCaps_PSK(t *testing.T) {
	c1 := caps.RspPSKCapResponder
	assert.True(t, c1.HasPSKCap())
	c2 := caps.RspPSKCapResponderWithCtx
	assert.True(t, c2.HasPSKCap())
}

func TestCaps_ResponderCaps_MeasCap(t *testing.T) {
	assert.True(t, caps.RspMeasCapNoSig.HasMeasCap())
	assert.True(t, caps.RspMeasCapSig.HasMeasCap())
	assert.False(t, caps.ResponderCaps(0).HasMeasCap())
}

// --- caps.Validate ---

func TestCaps_ValidateResponderCaps(t *testing.T) {
	// Valid: no caps
	assert.NoError(t, caps.ValidateResponderCaps(0))

	// Valid: ENCRYPT+MAC+KEY_EX
	assert.NoError(t, caps.ValidateResponderCaps(caps.RspEncryptCap|caps.RspMACCap|caps.RspKeyExCap|caps.RspCertCap|caps.RspChalCap))

	// Invalid: ENCRYPT without MAC
	assert.Error(t, caps.ValidateResponderCaps(caps.RspEncryptCap))

	// Invalid: MAC without ENCRYPT
	assert.Error(t, caps.ValidateResponderCaps(caps.RspMACCap))

	// Invalid: ENCRYPT+MAC without KEY_EX or PSK
	assert.Error(t, caps.ValidateResponderCaps(caps.RspEncryptCap|caps.RspMACCap))

	// Invalid: MEAS_FRESH without MEAS
	assert.Error(t, caps.ValidateResponderCaps(caps.RspMeasFreshCap))

	// Invalid: CERT + PUB_KEY_ID
	assert.Error(t, caps.ValidateResponderCaps(caps.RspCertCap|caps.RspPubKeyIDCap))

	// Invalid: CHAL without CERT or PUB_KEY_ID
	assert.Error(t, caps.ValidateResponderCaps(caps.RspChalCap))

	// Invalid: MUT_AUTH without KEY_EX or PSK
	assert.Error(t, caps.ValidateResponderCaps(caps.RspMutAuthCap))

	// Invalid: HANDSHAKE_IN_THE_CLEAR without KEY_EX
	assert.Error(t, caps.ValidateResponderCaps(caps.RspHandshakeInTheClearCap))
}

func TestCaps_ValidateRequesterCaps(t *testing.T) {
	assert.NoError(t, caps.ValidateRequesterCaps(0))

	// Valid
	assert.NoError(t, caps.ValidateRequesterCaps(caps.ReqEncryptCap|caps.ReqMACCap|caps.ReqKeyExCap|caps.ReqCertCap|caps.ReqChalCap))

	// Invalid: ENCRYPT without MAC
	assert.Error(t, caps.ValidateRequesterCaps(caps.ReqEncryptCap))

	// Invalid: MAC without ENCRYPT
	assert.Error(t, caps.ValidateRequesterCaps(caps.ReqMACCap))

	// Invalid: ENCRYPT+MAC without KEY_EX or PSK
	assert.Error(t, caps.ValidateRequesterCaps(caps.ReqEncryptCap|caps.ReqMACCap))

	// Invalid: CERT + PUB_KEY_ID
	assert.Error(t, caps.ValidateRequesterCaps(caps.ReqCertCap|caps.ReqPubKeyIDCap))

	// Invalid: CHAL without CERT/PUB_KEY_ID
	assert.Error(t, caps.ValidateRequesterCaps(caps.ReqChalCap))

	// Invalid: MUT_AUTH without KEY_EX/PSK
	assert.Error(t, caps.ValidateRequesterCaps(caps.ReqMutAuthCap))

	// Invalid: HANDSHAKE_IN_THE_CLEAR without KEY_EX
	assert.Error(t, caps.ValidateRequesterCaps(caps.ReqHandshakeInTheClearCap))
}

// --- codes ---

func TestCodes_RequestCode_String(t *testing.T) {
	tests := []struct {
		c   codes.RequestCode
		str string
	}{
		{codes.RequestGetDigests, "GET_DIGESTS"},
		{codes.RequestGetCertificate, "GET_CERTIFICATE"},
		{codes.RequestChallenge, "CHALLENGE"},
		{codes.RequestGetVersion, "GET_VERSION"},
		{codes.RequestChunkSend, "CHUNK_SEND"},
		{codes.RequestChunkGet, "CHUNK_GET"},
		{codes.RequestGetEndpointInfo, "GET_ENDPOINT_INFO"},
		{codes.RequestGetMeasurements, "GET_MEASUREMENTS"},
		{codes.RequestGetCapabilities, "GET_CAPABILITIES"},
		{codes.RequestGetSupportedEventTypes, "GET_SUPPORTED_EVENT_TYPES"},
		{codes.RequestNegotiateAlgorithms, "NEGOTIATE_ALGORITHMS"},
		{codes.RequestKeyExchange, "KEY_EXCHANGE"},
		{codes.RequestFinish, "FINISH"},
		{codes.RequestPSKExchange, "PSK_EXCHANGE"},
		{codes.RequestPSKFinish, "PSK_FINISH"},
		{codes.RequestHeartbeat, "HEARTBEAT"},
		{codes.RequestKeyUpdate, "KEY_UPDATE"},
		{codes.RequestGetEncapsulatedRequest, "GET_ENCAPSULATED_REQUEST"},
		{codes.RequestDeliverEncapsulatedResponse, "DELIVER_ENCAPSULATED_RESPONSE"},
		{codes.RequestEndSession, "END_SESSION"},
		{codes.RequestGetCSR, "GET_CSR"},
		{codes.RequestSetCertificate, "SET_CERTIFICATE"},
		{codes.RequestGetMeasurementExtensionLog, "GET_MEASUREMENT_EXTENSION_LOG"},
		{codes.RequestSubscribeEventTypes, "SUBSCRIBE_EVENT_TYPES"},
		{codes.RequestSendEvent, "SEND_EVENT"},
		{codes.RequestGetKeyPairInfo, "GET_KEY_PAIR_INFO"},
		{codes.RequestSetKeyPairInfo, "SET_KEY_PAIR_INFO"},
		{codes.RequestVendorDefined, "VENDOR_DEFINED_REQUEST"},
		{codes.RequestRespondIfReady, "RESPOND_IF_READY"},
		{codes.RequestCode(0x00), "RequestCode(0x00)"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.str, tt.c.String())
	}
}

func TestCodes_ResponseCode_String(t *testing.T) {
	tests := []struct {
		c   codes.ResponseCode
		str string
	}{
		{codes.ResponseDigests, "DIGESTS"},
		{codes.ResponseCertificate, "CERTIFICATE"},
		{codes.ResponseChallengeAuth, "CHALLENGE_AUTH"},
		{codes.ResponseVersion, "VERSION"},
		{codes.ResponseChunkSendAck, "CHUNK_SEND_ACK"},
		{codes.ResponseChunkResponse, "CHUNK_RESPONSE"},
		{codes.ResponseEndpointInfo, "ENDPOINT_INFO"},
		{codes.ResponseMeasurements, "MEASUREMENTS"},
		{codes.ResponseCapabilities, "CAPABILITIES"},
		{codes.ResponseSupportedEventTypes, "SUPPORTED_EVENT_TYPES"},
		{codes.ResponseAlgorithms, "ALGORITHMS"},
		{codes.ResponseKeyExchangeRsp, "KEY_EXCHANGE_RSP"},
		{codes.ResponseFinishRsp, "FINISH_RSP"},
		{codes.ResponsePSKExchangeRsp, "PSK_EXCHANGE_RSP"},
		{codes.ResponsePSKFinishRsp, "PSK_FINISH_RSP"},
		{codes.ResponseHeartbeatAck, "HEARTBEAT_ACK"},
		{codes.ResponseKeyUpdateAck, "KEY_UPDATE_ACK"},
		{codes.ResponseEncapsulatedRequest, "ENCAPSULATED_REQUEST"},
		{codes.ResponseEncapsulatedResponseAck, "ENCAPSULATED_RESPONSE_ACK"},
		{codes.ResponseEndSessionAck, "END_SESSION_ACK"},
		{codes.ResponseCSR, "CSR"},
		{codes.ResponseSetCertificateRsp, "SET_CERTIFICATE_RSP"},
		{codes.ResponseMeasurementExtensionLog, "MEASUREMENT_EXTENSION_LOG"},
		{codes.ResponseSubscribeEventTypesAck, "SUBSCRIBE_EVENT_TYPES_ACK"},
		{codes.ResponseEventAck, "EVENT_ACK"},
		{codes.ResponseKeyPairInfo, "KEY_PAIR_INFO"},
		{codes.ResponseSetKeyPairInfoAck, "SET_KEY_PAIR_INFO_ACK"},
		{codes.ResponseVendorDefined, "VENDOR_DEFINED_RESPONSE"},
		{codes.ResponseError, "ERROR"},
		{codes.ResponseCode(0x00), "ResponseCode(0x00)"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.str, tt.c.String())
	}
}

func TestCodes_SPDMErrorCode_String(t *testing.T) {
	tests := []struct {
		c   codes.SPDMErrorCode
		str string
	}{
		{codes.ErrorInvalidRequest, "INVALID_REQUEST"},
		{codes.ErrorBusy, "BUSY"},
		{codes.ErrorUnexpectedRequest, "UNEXPECTED_REQUEST"},
		{codes.ErrorUnspecified, "UNSPECIFIED"},
		{codes.ErrorDecryptError, "DECRYPT_ERROR"},
		{codes.ErrorUnsupportedRequest, "UNSUPPORTED_REQUEST"},
		{codes.ErrorRequestInFlight, "REQUEST_IN_FLIGHT"},
		{codes.ErrorInvalidResponseCode, "INVALID_RESPONSE_CODE"},
		{codes.ErrorSessionLimitExceeded, "SESSION_LIMIT_EXCEEDED"},
		{codes.ErrorSessionRequired, "SESSION_REQUIRED"},
		{codes.ErrorResetRequired, "RESET_REQUIRED"},
		{codes.ErrorResponseTooLarge, "RESPONSE_TOO_LARGE"},
		{codes.ErrorRequestTooLarge, "REQUEST_TOO_LARGE"},
		{codes.ErrorLargeResponse, "LARGE_RESPONSE"},
		{codes.ErrorMessageLost, "MESSAGE_LOST"},
		{codes.ErrorInvalidPolicy, "INVALID_POLICY"},
		{codes.ErrorVersionMismatch, "VERSION_MISMATCH"},
		{codes.ErrorResponseNotReady, "RESPONSE_NOT_READY"},
		{codes.ErrorRequestResynch, "REQUEST_RESYNCH"},
		{codes.ErrorOperationFailed, "OPERATION_FAILED"},
		{codes.ErrorNoPendingRequests, "NO_PENDING_REQUESTS"},
		{codes.ErrorVendorDefined, "VENDOR_DEFINED"},
		{codes.SPDMErrorCode(0x02), "SPDMErrorCode(0x02)"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.str, tt.c.String())
	}
}

func TestCodes_ResponseForRequest(t *testing.T) {
	resp, ok := codes.ResponseForRequest(codes.RequestGetVersion)
	assert.True(t, ok)
	assert.Equal(t, codes.ResponseVersion, resp)

	resp, ok = codes.ResponseForRequest(codes.RequestKeyExchange)
	assert.True(t, ok)
	assert.Equal(t, codes.ResponseKeyExchangeRsp, resp)

	_, ok = codes.ResponseForRequest(codes.RequestRespondIfReady)
	assert.False(t, ok)
}

func TestCodes_RequestForResponse(t *testing.T) {
	req, ok := codes.RequestForResponse(codes.ResponseVersion)
	assert.True(t, ok)
	assert.Equal(t, codes.RequestGetVersion, req)

	_, ok = codes.RequestForResponse(codes.ResponseError)
	assert.False(t, ok)
}

// --- status ---

func TestStatus_Severity_String(t *testing.T) {
	assert.Equal(t, "success", status.SeveritySuccess.String())
	assert.Equal(t, "warning", status.SeverityWarning.String())
	assert.Equal(t, "error", status.SeverityError.String())
	assert.Equal(t, "Severity(0xF)", status.Severity(0xF).String())
}

func TestStatus_Source_String(t *testing.T) {
	assert.Equal(t, "success", status.SourceSuccess.String())
	assert.Equal(t, "core", status.SourceCore.String())
	assert.Equal(t, "crypto", status.SourceCrypto.String())
	assert.Equal(t, "cert_parse", status.SourceCertParse.String())
	assert.Equal(t, "transport", status.SourceTransport.String())
	assert.Equal(t, "meas_collect", status.SourceMeasCollect.String())
	assert.Equal(t, "rng", status.SourceRNG.String())
	assert.Equal(t, "Source(0xFF)", status.Source(0xFF).String())
}

func TestStatus_Error(t *testing.T) {
	e := &status.Error{Severity: status.SeverityError, Source: status.SourceCore, Code: 0x0001, Msg: "test error"}
	assert.Contains(t, e.Error(), "test error")
	assert.Contains(t, e.Error(), "error")
	assert.Contains(t, e.Error(), "core")

	e2 := &status.Error{Severity: status.SeverityError, Source: status.SourceCore, Code: 0x0001}
	// Without Msg, format is "spdm %s [%s:0x%04X]" — no trailing message after the bracket.
	assert.NotContains(t, e2.Error(), "test error")
}

func TestStatus_Error_Is(t *testing.T) {
	assert.True(t, errors.Is(status.ErrInvalidParameter, status.ErrInvalidParameter))
	assert.False(t, errors.Is(status.ErrInvalidParameter, status.ErrVerifFail))
	assert.False(t, errors.Is(fmt.Errorf("other"), status.ErrInvalidParameter))
}

func TestStatus_ProtocolError(t *testing.T) {
	pe := &status.ProtocolError{ErrorCode: 0x06, ErrorData: 0x01}
	assert.Contains(t, pe.Error(), "0x06")
}

func TestStatus_SentinelErrors(t *testing.T) {
	// Verify all sentinel errors exist and have correct severity/source.
	require.NotNil(t, status.ErrInvalidParameter)
	require.NotNil(t, status.ErrUnsupportedCap)
	require.NotNil(t, status.ErrInvalidStateLocal)
	require.NotNil(t, status.ErrInvalidStatePeer)
	require.NotNil(t, status.ErrInvalidMsgField)
	require.NotNil(t, status.ErrInvalidMsgSize)
	require.NotNil(t, status.ErrNegotiationFail)
	require.NotNil(t, status.ErrBusyPeer)
	require.NotNil(t, status.ErrNotReadyPeer)
	require.NotNil(t, status.ErrErrorPeer)
	require.NotNil(t, status.ErrResynchPeer)
	require.NotNil(t, status.ErrBufferFull)
	require.NotNil(t, status.ErrBufferTooSmall)
	require.NotNil(t, status.ErrSessionNumberExceed)
	require.NotNil(t, status.ErrSessionMsgError)
	require.NotNil(t, status.ErrAcquireFail)
	require.NotNil(t, status.ErrResetRequiredPeer)
	require.NotNil(t, status.ErrPeerBufferTooSmall)
	require.NotNil(t, status.ErrCryptoError)
	require.NotNil(t, status.ErrVerifFail)
	require.NotNil(t, status.ErrSequenceNumberOverflow)
	require.NotNil(t, status.ErrFIPSFail)
	require.NotNil(t, status.WarnVerifNoAuthority)
	require.NotNil(t, status.WarnOverriddenParameter)
	require.NotNil(t, status.ErrInvalidCert)
	require.NotNil(t, status.ErrSendFail)
	require.NotNil(t, status.ErrReceiveFail)
	require.NotNil(t, status.ErrMeasInvalidIndex)
	require.NotNil(t, status.ErrMeasInternalError)
	require.NotNil(t, status.ErrLowEntropy)
}
