package algo

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBaseHashAlgoString(t *testing.T) {
	tests := []struct {
		algo BaseHashAlgo
		want string
	}{
		{HashSHA256, "SHA-256"},
		{HashSHA384, "SHA-384"},
		{HashSHA512, "SHA-512"},
		{HashSHA3_256, "SHA3-256"},
		{HashSHA3_384, "SHA3-384"},
		{HashSHA3_512, "SHA3-512"},
		{HashSM3_256, "SM3-256"},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, tc.algo.String(), "BaseHashAlgo(0x%X).String()", uint32(tc.algo))
	}
}

func TestBaseHashAlgoStringUnknown(t *testing.T) {
	unknown := BaseHashAlgo(0x80000000)
	s := unknown.String()
	assert.NotEmpty(t, s, "unknown BaseHashAlgo.String() should not be empty")
	assert.NotEqual(t, "SHA-256", s)
	assert.NotEqual(t, "SHA-384", s)
}

func TestBaseHashAlgoSize(t *testing.T) {
	tests := []struct {
		algo BaseHashAlgo
		want int
	}{
		{HashSHA256, 32},
		{HashSHA384, 48},
		{HashSHA512, 64},
		{HashSHA3_256, 32},
		{HashSHA3_384, 48},
		{HashSHA3_512, 64},
		{HashSM3_256, 32},
		{BaseHashAlgo(0xFF), 0}, // unknown
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, tc.algo.Size(), "%s.Size()", tc.algo)
	}
}

func TestBaseHashAlgoCryptoHash(t *testing.T) {
	tests := []struct {
		algo BaseHashAlgo
		want crypto.Hash
	}{
		{HashSHA256, crypto.SHA256},
		{HashSHA384, crypto.SHA384},
		{HashSHA512, crypto.SHA512},
		{HashSHA3_256, crypto.SHA3_256},
		{HashSHA3_384, crypto.SHA3_384},
		{HashSHA3_512, crypto.SHA3_512},
		{HashSM3_256, 0},
		{BaseHashAlgo(0xFF), 0},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, tc.algo.CryptoHash(), "%s.CryptoHash()", tc.algo)
	}
}

func TestBaseHashAlgoContains(t *testing.T) {
	mask := HashSHA256 | HashSHA384
	assert.True(t, mask.Contains(HashSHA256), "mask should contain SHA256")
	assert.True(t, mask.Contains(HashSHA384), "mask should contain SHA384")
	assert.False(t, mask.Contains(HashSHA512), "mask should not contain SHA512")
}

func TestBaseHashAlgoSingleAlgos(t *testing.T) {
	mask := HashSHA256 | HashSHA512
	algos := mask.SingleAlgos()
	require.Len(t, algos, 2)
	assert.Equal(t, HashSHA256, algos[0])
	assert.Equal(t, HashSHA512, algos[1])

	// Single algo
	algos = HashSHA384.SingleAlgos()
	require.Len(t, algos, 1)
	assert.Equal(t, HashSHA384, algos[0])

	// Empty
	algos = BaseHashAlgo(0).SingleAlgos()
	assert.Empty(t, algos)
}

func TestBaseAsymAlgoString(t *testing.T) {
	tests := []struct {
		algo BaseAsymAlgo
		want string
	}{
		{AsymRSASSA2048, "RSASSA-2048"},
		{AsymRSAPSS2048, "RSAPSS-2048"},
		{AsymRSASSA3072, "RSASSA-3072"},
		{AsymRSAPSS3072, "RSAPSS-3072"},
		{AsymECDSAP256, "ECDSA-P256"},
		{AsymRSASSA4096, "RSASSA-4096"},
		{AsymRSAPSS4096, "RSAPSS-4096"},
		{AsymECDSAP384, "ECDSA-P384"},
		{AsymECDSAP521, "ECDSA-P521"},
		{AsymSM2P256, "SM2-P256"},
		{AsymEdDSAEd25519, "EdDSA-Ed25519"},
		{AsymEdDSAEd448, "EdDSA-Ed448"},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, tc.algo.String(), "BaseAsymAlgo(0x%X).String()", uint32(tc.algo))
	}
}

func TestBaseAsymAlgoStringUnknown(t *testing.T) {
	unknown := BaseAsymAlgo(0x10000000)
	s := unknown.String()
	assert.NotEmpty(t, s, "unknown BaseAsymAlgo.String() should not be empty")
}

func TestBaseAsymAlgoSignatureSize(t *testing.T) {
	tests := []struct {
		algo BaseAsymAlgo
		want int
	}{
		{AsymRSASSA2048, 256},
		{AsymRSAPSS2048, 256},
		{AsymRSASSA3072, 384},
		{AsymRSAPSS3072, 384},
		{AsymRSASSA4096, 512},
		{AsymRSAPSS4096, 512},
		{AsymECDSAP256, 64},
		{AsymECDSAP384, 96},
		{AsymECDSAP521, 132},
		{AsymSM2P256, 64},
		{AsymEdDSAEd25519, 64},
		{AsymEdDSAEd448, 114},
		{BaseAsymAlgo(0xFFFF), 0},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, tc.algo.SignatureSize(), "%s.SignatureSize()", tc.algo)
	}
}

func TestBaseAsymAlgoContains(t *testing.T) {
	mask := AsymECDSAP256 | AsymECDSAP384
	assert.True(t, mask.Contains(AsymECDSAP256), "should contain P256")
	assert.False(t, mask.Contains(AsymRSASSA2048), "should not contain RSASSA2048")
}

func TestBaseAsymAlgoSingleAlgos(t *testing.T) {
	mask := AsymRSASSA2048 | AsymECDSAP521 | AsymEdDSAEd448
	algos := mask.SingleAlgos()
	require.Len(t, algos, 3)
	assert.Equal(t, AsymRSASSA2048, algos[0])
	assert.Equal(t, AsymECDSAP521, algos[1])
	assert.Equal(t, AsymEdDSAEd448, algos[2])
}

func TestDHENamedGroupString(t *testing.T) {
	tests := []struct {
		group DHENamedGroup
		want  string
	}{
		{DHEFFDHE2048, "FFDHE2048"},
		{DHEFFDHE3072, "FFDHE3072"},
		{DHEFFDHE4096, "FFDHE4096"},
		{DHESECP256R1, "SECP256R1"},
		{DHESECP384R1, "SECP384R1"},
		{DHESECP521R1, "SECP521R1"},
		{DHESM2P256, "SM2-P256"},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, tc.group.String(), "DHENamedGroup(0x%X).String()", uint16(tc.group))
	}
}

func TestDHENamedGroupStringUnknown(t *testing.T) {
	unknown := DHENamedGroup(0x8000)
	assert.NotEmpty(t, unknown.String(), "unknown DHENamedGroup.String() should not be empty")
}

func TestDHENamedGroupSharedSecretSize(t *testing.T) {
	tests := []struct {
		group DHENamedGroup
		want  int
	}{
		{DHEFFDHE2048, 256},
		{DHEFFDHE3072, 384},
		{DHEFFDHE4096, 512},
		{DHESECP256R1, 32},
		{DHESECP384R1, 48},
		{DHESECP521R1, 66},
		{DHESM2P256, 32},
		{DHENamedGroup(0x8000), 0},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, tc.group.SharedSecretSize(), "%s.SharedSecretSize()", tc.group)
	}
}

func TestDHENamedGroupContains(t *testing.T) {
	mask := DHESECP256R1 | DHESECP384R1
	assert.True(t, mask.Contains(DHESECP256R1), "should contain SECP256R1")
	assert.False(t, mask.Contains(DHEFFDHE2048), "should not contain FFDHE2048")
}

func TestDHENamedGroupSingleAlgos(t *testing.T) {
	mask := DHEFFDHE2048 | DHESECP521R1
	algos := mask.SingleAlgos()
	require.Len(t, algos, 2)
	assert.Equal(t, DHEFFDHE2048, algos[0])
	assert.Equal(t, DHESECP521R1, algos[1])
}

func TestAEADCipherSuiteString(t *testing.T) {
	tests := []struct {
		suite AEADCipherSuite
		want  string
	}{
		{AEADAES128GCM, "AES-128-GCM"},
		{AEADAES256GCM, "AES-256-GCM"},
		{AEADChaCha20Poly1305, "ChaCha20-Poly1305"},
		{AEADSM4GCM, "SM4-GCM"},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, tc.suite.String(), "AEADCipherSuite(0x%X).String()", uint16(tc.suite))
	}
}

func TestAEADCipherSuiteStringUnknown(t *testing.T) {
	unknown := AEADCipherSuite(0x8000)
	assert.NotEmpty(t, unknown.String(), "unknown AEADCipherSuite.String() should not be empty")
}

func TestAEADCipherSuiteKeySize(t *testing.T) {
	tests := []struct {
		suite AEADCipherSuite
		want  int
	}{
		{AEADAES128GCM, 16},
		{AEADAES256GCM, 32},
		{AEADChaCha20Poly1305, 32},
		{AEADSM4GCM, 16},
		{AEADCipherSuite(0x8000), 0},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, tc.suite.KeySize(), "%s.KeySize()", tc.suite)
	}
}

func TestAEADCipherSuiteNonceSize(t *testing.T) {
	for _, s := range []AEADCipherSuite{AEADAES128GCM, AEADAES256GCM, AEADChaCha20Poly1305, AEADSM4GCM} {
		assert.Equal(t, 12, s.NonceSize(), "%s.NonceSize()", s)
	}
	assert.Equal(t, 0, AEADCipherSuite(0x8000).NonceSize(), "unknown.NonceSize()")
}

func TestAEADCipherSuiteTagSize(t *testing.T) {
	for _, s := range []AEADCipherSuite{AEADAES128GCM, AEADAES256GCM, AEADChaCha20Poly1305, AEADSM4GCM} {
		assert.Equal(t, 16, s.TagSize(), "%s.TagSize()", s)
	}
	assert.Equal(t, 0, AEADCipherSuite(0x8000).TagSize(), "unknown.TagSize()")
}

func TestAEADCipherSuiteContains(t *testing.T) {
	mask := AEADAES128GCM | AEADChaCha20Poly1305
	assert.True(t, mask.Contains(AEADAES128GCM), "should contain AES128GCM")
	assert.False(t, mask.Contains(AEADAES256GCM), "should not contain AES256GCM")
}

func TestAEADCipherSuiteSingleAlgos(t *testing.T) {
	mask := AEADAES128GCM | AEADAES256GCM | AEADSM4GCM
	algos := mask.SingleAlgos()
	require.Len(t, algos, 3)
	assert.Equal(t, AEADAES128GCM, algos[0])
	assert.Equal(t, AEADAES256GCM, algos[1])
	assert.Equal(t, AEADSM4GCM, algos[2])
}

func TestMeasurementHashAlgoString(t *testing.T) {
	tests := []struct {
		algo MeasurementHashAlgo
		want string
	}{
		{MeasHashRawBitStream, "RawBitStream"},
		{MeasHashSHA256, "SHA-256"},
		{MeasHashSHA384, "SHA-384"},
		{MeasHashSHA512, "SHA-512"},
		{MeasHashSHA3_256, "SHA3-256"},
		{MeasHashSHA3_384, "SHA3-384"},
		{MeasHashSHA3_512, "SHA3-512"},
		{MeasHashSM3_256, "SM3-256"},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, tc.algo.String(), "MeasurementHashAlgo(0x%X).String()", uint32(tc.algo))
	}
}

func TestMeasurementHashAlgoSize(t *testing.T) {
	tests := []struct {
		algo MeasurementHashAlgo
		want int
	}{
		{MeasHashRawBitStream, 0},
		{MeasHashSHA256, 32},
		{MeasHashSHA384, 48},
		{MeasHashSHA512, 64},
		{MeasHashSHA3_256, 32},
		{MeasHashSHA3_384, 48},
		{MeasHashSHA3_512, 64},
		{MeasHashSM3_256, 32},
		{MeasurementHashAlgo(0xFFFF), 0},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, tc.algo.Size(), "%s.Size()", tc.algo)
	}
}

func TestMeasurementHashAlgoCryptoHash(t *testing.T) {
	tests := []struct {
		algo MeasurementHashAlgo
		want crypto.Hash
	}{
		{MeasHashSHA256, crypto.SHA256},
		{MeasHashSHA384, crypto.SHA384},
		{MeasHashSHA512, crypto.SHA512},
		{MeasHashSHA3_256, crypto.SHA3_256},
		{MeasHashSHA3_384, crypto.SHA3_384},
		{MeasHashSHA3_512, crypto.SHA3_512},
		{MeasHashRawBitStream, 0},
		{MeasHashSM3_256, 0},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, tc.algo.CryptoHash(), "%s.CryptoHash()", tc.algo)
	}
}

func TestMeasurementHashAlgoContainsAndSingleAlgos(t *testing.T) {
	mask := MeasHashSHA256 | MeasHashSHA512
	assert.True(t, mask.Contains(MeasHashSHA256), "should contain SHA256")
	assert.False(t, mask.Contains(MeasHashSHA384), "should not contain SHA384")
	algos := mask.SingleAlgos()
	require.Len(t, algos, 2)
}

func TestMeasurementSpecAndKeySchedule(t *testing.T) {
	assert.Equal(t, MeasurementSpec(0x01), MeasurementSpecDMTF)
	assert.Equal(t, KeySchedule(0x0001), KeyScheduleSPDM)
}

func TestVersionEncoding(t *testing.T) {
	tests := []struct {
		ver   Version
		major uint8
		minor uint8
		str   string
	}{
		{Version10, 1, 0, "1.0"},
		{Version11, 1, 1, "1.1"},
		{Version12, 1, 2, "1.2"},
		{Version13, 1, 3, "1.3"},
		{Version14, 1, 4, "1.4"},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.major, tc.ver.Major(), "%s.Major()", tc.ver)
		assert.Equal(t, tc.minor, tc.ver.Minor(), "%s.Minor()", tc.ver)
		assert.Equal(t, tc.str, tc.ver.String(), "Version(0x%X).String()", uint16(tc.ver))
	}
}

func TestVersionFromParts(t *testing.T) {
	v := VersionFromParts(1, 2)
	assert.Equal(t, Version12, v)
	v = VersionFromParts(2, 0)
	assert.Equal(t, uint8(2), v.Major())
	assert.Equal(t, uint8(0), v.Minor())
}

func TestVersionNumber(t *testing.T) {
	// SPDM 1.2.0.0 on wire: 0x1200
	vn := VersionNumber(0x1200)
	assert.Equal(t, uint8(1), vn.Major())
	assert.Equal(t, uint8(2), vn.Minor())
	assert.Equal(t, uint8(0), vn.Update())
	assert.Equal(t, uint8(0), vn.Alpha())
	assert.Equal(t, Version12, vn.Version())
	assert.Equal(t, "1.2.0.0", vn.String())

	// Test with non-zero update/alpha: 1.3.2.1 = 0x1321
	vn2 := VersionNumber(0x1321)
	assert.Equal(t, uint8(1), vn2.Major())
	assert.Equal(t, uint8(3), vn2.Minor())
	assert.Equal(t, uint8(2), vn2.Update())
	assert.Equal(t, uint8(1), vn2.Alpha())
	assert.Equal(t, Version13, vn2.Version())
}

func TestNoDuplicateConstants(t *testing.T) {
	// BaseHashAlgo
	hashValues := map[BaseHashAlgo]string{}
	for _, tc := range []struct {
		v BaseHashAlgo
		n string
	}{
		{HashSHA256, "SHA256"}, {HashSHA384, "SHA384"}, {HashSHA512, "SHA512"},
		{HashSHA3_256, "SHA3_256"}, {HashSHA3_384, "SHA3_384"}, {HashSHA3_512, "SHA3_512"},
		{HashSM3_256, "SM3_256"},
	} {
		assert.False(t, hashValues[tc.v] != "" && hashValues[tc.v] != tc.n,
			"duplicate BaseHashAlgo value 0x%X: %s and %s", uint32(tc.v), hashValues[tc.v], tc.n)
		hashValues[tc.v] = tc.n
	}

	// BaseAsymAlgo
	asymValues := map[BaseAsymAlgo]string{}
	for _, tc := range []struct {
		v BaseAsymAlgo
		n string
	}{
		{AsymRSASSA2048, "RSASSA2048"}, {AsymRSAPSS2048, "RSAPSS2048"},
		{AsymRSASSA3072, "RSASSA3072"}, {AsymRSAPSS3072, "RSAPSS3072"},
		{AsymECDSAP256, "ECDSAP256"}, {AsymRSASSA4096, "RSASSA4096"},
		{AsymRSAPSS4096, "RSAPSS4096"}, {AsymECDSAP384, "ECDSAP384"},
		{AsymECDSAP521, "ECDSAP521"}, {AsymSM2P256, "SM2P256"},
		{AsymEdDSAEd25519, "Ed25519"}, {AsymEdDSAEd448, "Ed448"},
	} {
		assert.False(t, asymValues[tc.v] != "" && asymValues[tc.v] != tc.n,
			"duplicate BaseAsymAlgo value 0x%X: %s and %s", uint32(tc.v), asymValues[tc.v], tc.n)
		asymValues[tc.v] = tc.n
	}

	// DHENamedGroup
	dheValues := map[DHENamedGroup]string{}
	for _, tc := range []struct {
		v DHENamedGroup
		n string
	}{
		{DHEFFDHE2048, "FFDHE2048"}, {DHEFFDHE3072, "FFDHE3072"}, {DHEFFDHE4096, "FFDHE4096"},
		{DHESECP256R1, "SECP256R1"}, {DHESECP384R1, "SECP384R1"}, {DHESECP521R1, "SECP521R1"},
		{DHESM2P256, "SM2P256"},
	} {
		assert.False(t, dheValues[tc.v] != "" && dheValues[tc.v] != tc.n,
			"duplicate DHENamedGroup value 0x%X: %s and %s", uint16(tc.v), dheValues[tc.v], tc.n)
		dheValues[tc.v] = tc.n
	}

	// AEADCipherSuite
	aeadValues := map[AEADCipherSuite]string{}
	for _, tc := range []struct {
		v AEADCipherSuite
		n string
	}{
		{AEADAES128GCM, "AES128GCM"}, {AEADAES256GCM, "AES256GCM"},
		{AEADChaCha20Poly1305, "ChaCha20"}, {AEADSM4GCM, "SM4GCM"},
	} {
		assert.False(t, aeadValues[tc.v] != "" && aeadValues[tc.v] != tc.n,
			"duplicate AEADCipherSuite value 0x%X: %s and %s", uint16(tc.v), aeadValues[tc.v], tc.n)
		aeadValues[tc.v] = tc.n
	}
}

func TestAllStringsNonEmpty(t *testing.T) {
	for _, h := range allBaseHashAlgos {
		assert.NotEmpty(t, h.String(), "BaseHashAlgo(0x%X).String() is empty", uint32(h))
	}
	for _, a := range allBaseAsymAlgos {
		assert.NotEmpty(t, a.String(), "BaseAsymAlgo(0x%X).String() is empty", uint32(a))
	}
	for _, d := range allDHENamedGroups {
		assert.NotEmpty(t, d.String(), "DHENamedGroup(0x%X).String() is empty", uint16(d))
	}
	for _, s := range allAEADCipherSuites {
		assert.NotEmpty(t, s.String(), "AEADCipherSuite(0x%X).String() is empty", uint16(s))
	}
	for _, m := range allMeasHashAlgos {
		assert.NotEmpty(t, m.String(), "MeasurementHashAlgo(0x%X).String() is empty", uint32(m))
	}
}

func TestSingleAlgosAllBitsSet(t *testing.T) {
	// All hash bits set
	allHash := HashSHA256 | HashSHA384 | HashSHA512 | HashSHA3_256 | HashSHA3_384 | HashSHA3_512 | HashSM3_256
	assert.Equal(t, 7, len(allHash.SingleAlgos()), "all hash SingleAlgos")

	// All asym bits set
	allAsym := AsymRSASSA2048 | AsymRSAPSS2048 | AsymRSASSA3072 | AsymRSAPSS3072 |
		AsymECDSAP256 | AsymRSASSA4096 | AsymRSAPSS4096 | AsymECDSAP384 |
		AsymECDSAP521 | AsymSM2P256 | AsymEdDSAEd25519 | AsymEdDSAEd448
	assert.Equal(t, 12, len(allAsym.SingleAlgos()), "all asym SingleAlgos")

	// All DHE bits set
	allDHE := DHEFFDHE2048 | DHEFFDHE3072 | DHEFFDHE4096 | DHESECP256R1 | DHESECP384R1 | DHESECP521R1 | DHESM2P256
	assert.Equal(t, 7, len(allDHE.SingleAlgos()), "all DHE SingleAlgos")

	// All AEAD bits set
	allAEAD := AEADAES128GCM | AEADAES256GCM | AEADChaCha20Poly1305 | AEADSM4GCM
	assert.Equal(t, 4, len(allAEAD.SingleAlgos()), "all AEAD SingleAlgos")
}
