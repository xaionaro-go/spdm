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

	privA, pubA, err := ka.GenerateDHE(group)
	require.NoError(t, err)
	require.Len(t, pubA, expectedSize)

	privB, pubB, err := ka.GenerateDHE(group)
	require.NoError(t, err)
	require.Len(t, pubB, expectedSize)

	secretA, err := ka.ComputeDHE(group, privA, pubB)
	require.NoError(t, err)
	require.Len(t, secretA, expectedSize)

	secretB, err := ka.ComputeDHE(group, privB, pubA)
	require.NoError(t, err)
	require.Len(t, secretB, expectedSize)

	assert.Equal(t, secretA, secretB, "shared secrets must match")
}

func TestFFDHEComputeWrongKeyType(t *testing.T) {
	ka := &StdKeyAgreement{}
	_, err := ka.ComputeDHE(algo.DHEFFDHE2048, "not-a-key", make([]byte, 256))
	require.Error(t, err)
}

func TestFFDHEComputeInvalidPeerPublicKeyZero(t *testing.T) {
	ka := &StdKeyAgreement{}
	priv, _, err := ka.GenerateDHE(algo.DHEFFDHE2048)
	require.NoError(t, err)

	// Peer public key = 0 (all zeros) should be rejected.
	_, err = ka.ComputeDHE(algo.DHEFFDHE2048, priv, make([]byte, 256))
	require.Error(t, err)
}

func TestFFDHEComputeInvalidPeerPublicKeyOne(t *testing.T) {
	ka := &StdKeyAgreement{}
	priv, _, err := ka.GenerateDHE(algo.DHEFFDHE2048)
	require.NoError(t, err)

	// Peer public key = 1 should be rejected.
	one := make([]byte, 256)
	one[255] = 1
	_, err = ka.ComputeDHE(algo.DHEFFDHE2048, priv, one)
	require.Error(t, err)
}

func TestFFDHEComputeGroupMismatch(t *testing.T) {
	ka := &StdKeyAgreement{}
	priv, _, err := ka.GenerateDHE(algo.DHEFFDHE2048)
	require.NoError(t, err)

	_, pubB, err := ka.GenerateDHE(algo.DHEFFDHE3072)
	require.NoError(t, err)

	// Mismatched group should fail.
	_, err = ka.ComputeDHE(algo.DHEFFDHE3072, priv, pubB)
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
		&ffdhePrivateKey{Group: algo.DHENamedGroup(0x9999)},
		make([]byte, 256),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported FFDHE group")
}
