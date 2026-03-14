package stdlib

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/spdm/pkg/gen/algo"
)

func TestFFDHE2048RoundTrip(t *testing.T) {
	testFFDHERoundTrip(t, algo.DHEFFDHE2048, 256)
}

func TestFFDHE3072RoundTrip(t *testing.T) {
	testFFDHERoundTrip(t, algo.DHEFFDHE3072, 384)
}

func TestFFDHE4096RoundTrip(t *testing.T) {
	testFFDHERoundTrip(t, algo.DHEFFDHE4096, 512)
}

func testFFDHERoundTrip(t *testing.T, group algo.DHENamedGroup, expectedSize int) {
	t.Helper()
	ka := &StdKeyAgreement{}

	kpA, err := ka.GenerateDHE(group)
	require.NoError(t, err)
	pubA := kpA.PublicKey()
	require.Len(t, pubA, expectedSize)

	kpB, err := ka.GenerateDHE(group)
	require.NoError(t, err)
	pubB := kpB.PublicKey()
	require.Len(t, pubB, expectedSize)

	secretA, err := kpA.ComputeSharedSecret(pubB)
	require.NoError(t, err)
	require.Len(t, secretA, expectedSize)

	secretB, err := kpB.ComputeSharedSecret(pubA)
	require.NoError(t, err)
	require.Len(t, secretB, expectedSize)

	assert.Equal(t, secretA, secretB, "shared secrets must match")
}

func TestFFDHEComputeInvalidPeerPublicKeyZero(t *testing.T) {
	ka := &StdKeyAgreement{}
	kp, err := ka.GenerateDHE(algo.DHEFFDHE2048)
	require.NoError(t, err)

	// Peer public key = 0 (all zeros) should be rejected.
	_, err = kp.ComputeSharedSecret(make([]byte, 256))
	require.Error(t, err)
}

func TestFFDHEComputeInvalidPeerPublicKeyOne(t *testing.T) {
	ka := &StdKeyAgreement{}
	kp, err := ka.GenerateDHE(algo.DHEFFDHE2048)
	require.NoError(t, err)

	// Peer public key = 1 should be rejected.
	one := make([]byte, 256)
	one[255] = 1
	_, err = kp.ComputeSharedSecret(one)
	require.Error(t, err)
}

func TestPadBigEndianSmallValue(t *testing.T) {
	// Value that is shorter than target size — exercises the padding branch.
	n := big.NewInt(42)
	result := padBigEndian(n, 32)
	assert.Len(t, result, 32)
	// First 31 bytes should be zero padding.
	for i := 0; i < 31; i++ {
		assert.Equal(t, byte(0), result[i], "byte %d should be zero", i)
	}
	assert.Equal(t, byte(42), result[31])
}

func TestMustParsePrimePanicsOnInvalidHex(t *testing.T) {
	assert.Panics(t, func() {
		mustParsePrime("ZZZZ_not_hex_at_all_padding_for_32_chars")
	})
}

func TestGenerateFFDHEUnsupportedGroup(t *testing.T) {
	_, _, err := generateFFDHE(algo.DHENamedGroup(0x9999))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported FFDHE group")
}

func TestComputeFFDHEUnsupportedGroup(t *testing.T) {
	_, err := computeFFDHE(
		algo.DHENamedGroup(0x9999),
		&FFDHEPrivateKey{Group: algo.DHENamedGroup(0x9999)},
		make([]byte, 256),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported FFDHE group")
}
