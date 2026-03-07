package unit

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/spdm/internal/testutil"
	"github.com/xaionaro-go/spdm/pkg/crypto/stdlib"
	"github.com/xaionaro-go/spdm/pkg/gen/algo"
)

func TestVerify_RSASSA2048(t *testing.T) {
	_, _, leafKey := testutil.TestCerts(t, "rsa-2048")
	rsaPriv := leafKey.(*rsa.PrivateKey)

	message := []byte("test message for RSASSA verification")
	digest := sha256.Sum256(message)

	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaPriv, crypto.SHA256, digest[:])
	require.NoError(t, err)

	v := &stdlib.StdVerifier{}
	err = v.Verify(algo.AsymRSASSA2048, &rsaPriv.PublicKey, digest[:], sig)
	assert.NoError(t, err)
}

func TestVerify_RSAPSS2048(t *testing.T) {
	_, _, leafKey := testutil.TestCerts(t, "rsa-2048")
	rsaPriv := leafKey.(*rsa.PrivateKey)

	message := []byte("test message for RSAPSS verification")
	digest := sha256.Sum256(message)

	sig, err := rsa.SignPSS(rand.Reader, rsaPriv, crypto.SHA256, digest[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
	require.NoError(t, err)

	v := &stdlib.StdVerifier{}
	err = v.Verify(algo.AsymRSAPSS2048, &rsaPriv.PublicKey, digest[:], sig)
	assert.NoError(t, err)
}

func TestVerify_Ed25519(t *testing.T) {
	_, _, leafKey := testutil.TestCerts(t, "ed25519")
	edPriv := leafKey.(ed25519.PrivateKey)
	edPub := edPriv.Public().(ed25519.PublicKey)

	message := []byte("test message for Ed25519 verification")
	sig := ed25519.Sign(edPriv, message)

	v := &stdlib.StdVerifier{}
	// For Ed25519, "digest" is the full message (Ed25519 hashes internally).
	err := v.Verify(algo.AsymEdDSAEd25519, edPub, message, sig)
	assert.NoError(t, err)
}

func TestVerify_RSASSAWrongKeyType(t *testing.T) {
	_, _, leafKey := testutil.TestCerts(t, "ecdsa-p256")
	ecPub := leafKey.Public()

	v := &stdlib.StdVerifier{}
	err := v.Verify(algo.AsymRSASSA2048, ecPub, []byte("digest"), []byte("sig"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected *rsa.PublicKey")
}

func TestVerify_RSAPSSWrongKeyType(t *testing.T) {
	_, _, leafKey := testutil.TestCerts(t, "ecdsa-p256")
	ecPub := leafKey.Public()

	v := &stdlib.StdVerifier{}
	err := v.Verify(algo.AsymRSAPSS2048, ecPub, []byte("digest"), []byte("sig"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected *rsa.PublicKey")
}

func TestVerify_Ed25519WrongKeyType(t *testing.T) {
	_, _, leafKey := testutil.TestCerts(t, "rsa-2048")
	rsaPub := leafKey.Public()

	v := &stdlib.StdVerifier{}
	err := v.Verify(algo.AsymEdDSAEd25519, rsaPub, []byte("message"), []byte("sig"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected ed25519.PublicKey")
}

func TestVerify_Ed448WrongKeyType(t *testing.T) {
	v := &stdlib.StdVerifier{}
	err := v.Verify(algo.AsymEdDSAEd448, "not-a-key", []byte("message"), make([]byte, 114))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected ed448.PublicKey")
}

func TestVerify_HashForDigestSizeUnknown(t *testing.T) {
	_, _, leafKey := testutil.TestCerts(t, "rsa-2048")
	rsaPriv := leafKey.(*rsa.PrivateKey)

	// 17 bytes is not a standard hash size (32, 48, or 64).
	badDigest := make([]byte, 17)

	v := &stdlib.StdVerifier{}
	err := v.Verify(algo.AsymRSASSA2048, &rsaPriv.PublicKey, badDigest, []byte("sig"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported digest size")
}
