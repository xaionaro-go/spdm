package stdlib

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/emmansun/gmsm/sm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/spdm/pkg/gen/algo"
)

// --- Hash tests ---

func TestHashDigestSize(t *testing.T) {
	tests := []struct {
		algo algo.BaseHashAlgo
		size int
	}{
		{algo.HashSHA256, 32},
		{algo.HashSHA384, 48},
		{algo.HashSHA512, 64},
		{algo.HashSHA3_256, 32},
		{algo.HashSHA3_384, 48},
		{algo.HashSHA3_512, 64},
	}
	p := &StdHashProvider{}
	for _, tc := range tests {
		t.Run(tc.algo.String(), func(t *testing.T) {
			h, err := p.NewHash(tc.algo)
			require.NoError(t, err)
			h.Write([]byte("test data"))
			digest := h.Sum(nil)
			assert.Len(t, digest, tc.size)
		})
	}
}

func TestHashSM3_256(t *testing.T) {
	p := &StdHashProvider{}
	h, err := p.NewHash(algo.HashSM3_256)
	require.NoError(t, err)
	h.Write([]byte("test data"))
	digest := h.Sum(nil)
	assert.Len(t, digest, 32)
}

func TestHashUnsupported(t *testing.T) {
	p := &StdHashProvider{}
	_, err := p.NewHash(algo.BaseHashAlgo(0x80000000))
	require.Error(t, err)
}

// --- Verify tests ---

func TestVerifyECDSAP256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	digest := make([]byte, 32)
	_, err = rand.Read(digest)
	require.NoError(t, err)

	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	require.NoError(t, err)
	sig := encodeRawRS(r, s, 32)

	v := &StdVerifier{}
	require.NoError(t, v.Verify(algo.AsymECDSAP256, &key.PublicKey, digest, sig))

	// Tamper digest and expect failure.
	digest[0] ^= 0xFF
	require.Error(t, v.Verify(algo.AsymECDSAP256, &key.PublicKey, digest, sig))
}

func TestVerifyECDSAP384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	digest := make([]byte, 48)
	_, err = rand.Read(digest)
	require.NoError(t, err)

	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	require.NoError(t, err)
	sig := encodeRawRS(r, s, 48)

	v := &StdVerifier{}
	require.NoError(t, v.Verify(algo.AsymECDSAP384, &key.PublicKey, digest, sig))
}

func TestVerifyECDSAWrongKeyType(t *testing.T) {
	v := &StdVerifier{}
	err := v.Verify(algo.AsymECDSAP256, "not-a-key", []byte{0}, make([]byte, 64))
	require.Error(t, err)
}

func TestVerifyECDSAWrongSigLen(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	v := &StdVerifier{}
	// Wrong signature length (expected 64 for P256).
	err = v.Verify(algo.AsymECDSAP256, &key.PublicKey, make([]byte, 32), make([]byte, 32))
	require.Error(t, err)
}

func TestVerifyRSASSA2048(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	h := sha256.Sum256([]byte("SPDM RSA test message"))
	digest := h[:]

	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	require.NoError(t, err)

	v := &StdVerifier{}
	require.NoError(t, v.Verify(algo.AsymRSASSA2048, &key.PublicKey, digest, sig))

	// Tamper digest.
	digest[0] ^= 0xFF
	require.Error(t, v.Verify(algo.AsymRSASSA2048, &key.PublicKey, digest, sig))
}

func TestVerifyRSASSAWrongKeyType(t *testing.T) {
	v := &StdVerifier{}
	err := v.Verify(algo.AsymRSASSA2048, "not-a-key", make([]byte, 32), make([]byte, 256))
	require.Error(t, err)
}

func TestVerifyRSASSAUnsupportedDigestSize(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	v := &StdVerifier{}
	// Digest of unusual length (not 32, 48, or 64).
	err = v.Verify(algo.AsymRSASSA2048, &key.PublicKey, make([]byte, 20), make([]byte, 256))
	require.Error(t, err)
}

func TestVerifyRSAPSS2048(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	h := sha256.Sum256([]byte("SPDM RSA-PSS test"))
	digest := h[:]

	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
	require.NoError(t, err)

	v := &StdVerifier{}
	require.NoError(t, v.Verify(algo.AsymRSAPSS2048, &key.PublicKey, digest, sig))

	// Tamper digest.
	digest[0] ^= 0xFF
	require.Error(t, v.Verify(algo.AsymRSAPSS2048, &key.PublicKey, digest, sig))
}

func TestVerifyRSAPSSWrongKeyType(t *testing.T) {
	v := &StdVerifier{}
	err := v.Verify(algo.AsymRSAPSS2048, "not-a-key", make([]byte, 32), make([]byte, 256))
	require.Error(t, err)
}

func TestVerifyRSAPSSUnsupportedDigestSize(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	v := &StdVerifier{}
	err = v.Verify(algo.AsymRSAPSS2048, &key.PublicKey, make([]byte, 20), make([]byte, 256))
	require.Error(t, err)
}

func TestVerifyRSAPSSSHA384(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	h := sha512.Sum384([]byte("SPDM RSA-PSS SHA384 test"))
	digest := h[:]

	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA384, digest, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
	require.NoError(t, err)

	v := &StdVerifier{}
	require.NoError(t, v.Verify(algo.AsymRSAPSS2048, &key.PublicKey, digest, sig))
}

func TestVerifyRSAPSSSHA512(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	h := sha512.Sum512([]byte("SPDM RSA-PSS SHA512 test"))
	digest := h[:]

	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA512, digest, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
	require.NoError(t, err)

	v := &StdVerifier{}
	require.NoError(t, v.Verify(algo.AsymRSAPSS2048, &key.PublicKey, digest, sig))
}

func TestVerifyEd25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	message := []byte("SPDM test message for Ed25519")
	sig := ed25519.Sign(priv, message)

	v := &StdVerifier{}
	require.NoError(t, v.Verify(algo.AsymEdDSAEd25519, pub, message, sig))

	// Tamper message.
	message[0] ^= 0xFF
	require.Error(t, v.Verify(algo.AsymEdDSAEd25519, pub, message, sig))
}

func TestVerifyEd25519WrongKeyType(t *testing.T) {
	v := &StdVerifier{}
	err := v.Verify(algo.AsymEdDSAEd25519, "not-a-key", []byte("msg"), make([]byte, 64))
	require.Error(t, err)
}

func TestVerifyEd448(t *testing.T) {
	pub, priv, err := ed448.GenerateKey(rand.Reader)
	require.NoError(t, err)
	message := []byte("SPDM test message for Ed448")
	sig := ed448.Sign(priv, message, "")

	v := &StdVerifier{}
	require.NoError(t, v.Verify(algo.AsymEdDSAEd448, pub, message, sig))

	// Tamper message.
	message[0] ^= 0xFF
	require.Error(t, v.Verify(algo.AsymEdDSAEd448, pub, message, sig))
}

func TestVerifyEd448WrongKeyType(t *testing.T) {
	v := &StdVerifier{}
	err := v.Verify(algo.AsymEdDSAEd448, "not-a-key", []byte("msg"), make([]byte, 114))
	require.Error(t, err)
}

func TestVerifySM2P256(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// SM2 verification uses a pre-computed hash/digest.
	digest := make([]byte, 32)
	_, err = rand.Read(digest)
	require.NoError(t, err)

	r, s, err := sm2.Sign(rand.Reader, &key.PrivateKey, digest)
	require.NoError(t, err)
	sig := encodeRawRS(r, s, 32)

	v := &StdVerifier{}
	require.NoError(t, v.Verify(algo.AsymSM2P256, &key.PublicKey, digest, sig))

	// Tamper digest.
	digest[0] ^= 0xFF
	require.Error(t, v.Verify(algo.AsymSM2P256, &key.PublicKey, digest, sig))
}

func TestVerifySM2WrongKeyType(t *testing.T) {
	v := &StdVerifier{}
	err := v.Verify(algo.AsymSM2P256, "not-a-key", make([]byte, 32), make([]byte, 64))
	require.Error(t, err)
}

func TestVerifySM2WrongSigLen(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	require.NoError(t, err)
	v := &StdVerifier{}
	err = v.Verify(algo.AsymSM2P256, &key.PublicKey, make([]byte, 32), make([]byte, 32))
	require.Error(t, err)
}

func TestVerifyUnsupportedAlgo(t *testing.T) {
	v := &StdVerifier{}
	err := v.Verify(algo.BaseAsymAlgo(0x80000000), nil, nil, nil)
	require.Error(t, err)
}

// --- DHE tests ---

func TestDHESECP256R1(t *testing.T) {
	testDHERoundTrip(t, algo.DHESECP256R1, 32)
}

func TestDHESECP384R1(t *testing.T) {
	testDHERoundTrip(t, algo.DHESECP384R1, 48)
}

func TestDHESECP521R1(t *testing.T) {
	testDHERoundTrip(t, algo.DHESECP521R1, 66)
}

func testDHERoundTrip(t *testing.T, group algo.DHENamedGroup, secretLen int) {
	t.Helper()
	ka := &StdKeyAgreement{}

	privA, pubA, err := ka.GenerateDHE(group)
	require.NoError(t, err)
	privB, pubB, err := ka.GenerateDHE(group)
	require.NoError(t, err)

	secretA, err := ka.ComputeDHE(group, privA, pubB)
	require.NoError(t, err)
	secretB, err := ka.ComputeDHE(group, privB, pubA)
	require.NoError(t, err)

	require.Len(t, secretA, secretLen)
	assert.Equal(t, secretA, secretB)
}

func TestDHEFFDHE2048Supported(t *testing.T) {
	ka := &StdKeyAgreement{}
	_, pub, err := ka.GenerateDHE(algo.DHEFFDHE2048)
	require.NoError(t, err)
	require.Len(t, pub, 256)
}

func TestDHESM2P256(t *testing.T) {
	testDHERoundTrip(t, algo.DHESM2P256, 32)
}

func TestDHEUnsupportedGroup(t *testing.T) {
	ka := &StdKeyAgreement{}
	_, _, err := ka.GenerateDHE(algo.DHENamedGroup(0x8000))
	require.Error(t, err)
}

func TestComputeDHEWrongKeyType(t *testing.T) {
	ka := &StdKeyAgreement{}
	_, err := ka.ComputeDHE(algo.DHESECP256R1, "not-a-key", []byte{0})
	require.Error(t, err)
}

func TestComputeDHEBadPeerPublic(t *testing.T) {
	ka := &StdKeyAgreement{}
	priv, _, err := ka.GenerateDHE(algo.DHESECP256R1)
	require.NoError(t, err)
	_, err = ka.ComputeDHE(algo.DHESECP256R1, priv, []byte{0xFF})
	require.Error(t, err)
}

func TestComputeDHESM2WrongKeyType(t *testing.T) {
	ka := &StdKeyAgreement{}
	_, err := ka.ComputeDHE(algo.DHESM2P256, "not-a-key", make([]byte, 64))
	require.Error(t, err)
}

func TestComputeDHESM2BadPeerPublic(t *testing.T) {
	ka := &StdKeyAgreement{}
	priv, _, err := ka.GenerateDHE(algo.DHESM2P256)
	require.NoError(t, err)
	// Invalid peer public key bytes should fail parsing.
	_, err = ka.ComputeDHE(algo.DHESM2P256, priv, []byte{0xFF})
	require.Error(t, err)
}

func TestComputeDHEUnsupportedGroup(t *testing.T) {
	ka := &StdKeyAgreement{}
	_, err := ka.ComputeDHE(algo.DHENamedGroup(0x8000), nil, nil)
	require.Error(t, err)
}

// --- AEAD tests ---

func TestAEADAES128GCM(t *testing.T) {
	testAEAD(t, algo.AEADAES128GCM, 16)
}

func TestAEADAES256GCM(t *testing.T) {
	testAEAD(t, algo.AEADAES256GCM, 32)
}

func TestAEADChaCha20Poly1305(t *testing.T) {
	testAEAD(t, algo.AEADChaCha20Poly1305, 32)
}

func testAEAD(t *testing.T, suite algo.AEADCipherSuite, keySize int) {
	t.Helper()
	a := &StdAEAD{}

	key := make([]byte, keySize)
	_, err := rand.Read(key)
	require.NoError(t, err)
	nonce := make([]byte, suite.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	plaintext := []byte("hello SPDM world")
	aad := []byte("additional data")

	ciphertext, err := a.Seal(suite, key, nonce, plaintext, aad)
	require.NoError(t, err)

	got, err := a.Open(suite, key, nonce, ciphertext, aad)
	require.NoError(t, err)
	require.Equal(t, string(plaintext), string(got))

	// Tamper ciphertext.
	ciphertext[0] ^= 0xFF
	_, err = a.Open(suite, key, nonce, ciphertext, aad)
	require.Error(t, err)
}

func TestAEADSM4GCM(t *testing.T) {
	testAEAD(t, algo.AEADSM4GCM, 16)
}

func TestAEADUnsupportedSuite(t *testing.T) {
	a := &StdAEAD{}
	_, err := a.Seal(algo.AEADCipherSuite(0x8000), make([]byte, 16), make([]byte, 12), nil, nil)
	require.Error(t, err)
	_, err = a.Open(algo.AEADCipherSuite(0x8000), make([]byte, 16), make([]byte, 12), nil, nil)
	require.Error(t, err)
}

func TestSealBadKey(t *testing.T) {
	a := &StdAEAD{}
	// AES requires 16 or 32 byte key; 5 bytes is invalid.
	_, err := a.Seal(algo.AEADAES128GCM, make([]byte, 5), make([]byte, 12), nil, nil)
	require.Error(t, err)
}

func TestOpenBadKey(t *testing.T) {
	a := &StdAEAD{}
	_, err := a.Open(algo.AEADAES128GCM, make([]byte, 5), make([]byte, 12), nil, nil)
	require.Error(t, err)
}

// --- Suite test ---

func TestNewSuite(t *testing.T) {
	s := NewSuite(nil, nil)
	require.NotNil(t, s.Hash)
	require.NotNil(t, s.Verifier)
	require.NotNil(t, s.KeyAgreement)
	require.NotNil(t, s.AEAD)
	require.NotNil(t, s.Random)
}

// --- hashForDigestSize test ---

func TestHashForDigestSize(t *testing.T) {
	tests := []struct {
		size int
		want crypto.Hash
	}{
		{32, crypto.SHA256},
		{48, crypto.SHA384},
		{64, crypto.SHA512},
		{20, 0}, // unsupported
	}
	for _, tc := range tests {
		got := hashForDigestSize(tc.size)
		assert.Equal(t, tc.want, got, "hashForDigestSize(%d)", tc.size)
	}
}

// encodeRawRS encodes r, s as fixed-size big-endian byte slices concatenated.
func encodeRawRS(r, s *big.Int, componentLen int) []byte {
	sig := make([]byte, componentLen*2)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[componentLen-len(rBytes):componentLen], rBytes)
	copy(sig[2*componentLen-len(sBytes):2*componentLen], sBytes)
	return sig
}
