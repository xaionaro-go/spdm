package stdlib

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/xaionaro-go/spdm/pkg/gen/algo"
)

// ffdhePrivateKey holds the private key material for an FFDHE key exchange.
type ffdhePrivateKey struct {
	Group algo.DHENamedGroup
	X     *big.Int
}

// ffdheParams holds the prime modulus and generator for an FFDHE group.
type ffdheParams struct {
	P    *big.Int
	G    *big.Int
	Size int // public key / shared secret size in bytes
}

var ffdheGroupParams map[algo.DHENamedGroup]*ffdheParams

func init() {
	ffdheGroupParams = map[algo.DHENamedGroup]*ffdheParams{
		algo.DHEFFDHE2048: {
			P:    mustParsePrime(ffdhe2048PrimeHex),
			G:    big.NewInt(2),
			Size: 256,
		},
		algo.DHEFFDHE3072: {
			P:    mustParsePrime(ffdhe3072PrimeHex),
			G:    big.NewInt(2),
			Size: 384,
		},
		algo.DHEFFDHE4096: {
			P:    mustParsePrime(ffdhe4096PrimeHex),
			G:    big.NewInt(2),
			Size: 512,
		},
	}
}

func mustParsePrime(hex string) *big.Int {
	p, ok := new(big.Int).SetString(hex, 16)
	if !ok {
		panic(fmt.Sprintf("failed to parse FFDHE prime: %s", hex[:32]+"..."))
	}
	return p
}

// generateFFDHE generates a random private key and the corresponding public key
// for the given FFDHE group. The public key is g^x mod p, returned as a
// fixed-size big-endian byte slice.
func generateFFDHE(group algo.DHENamedGroup) (*ffdhePrivateKey, []byte, error) {
	params, ok := ffdheGroupParams[group]
	if !ok {
		return nil, nil, ErrUnsupportedDHEGroup{Name: "FFDHE", Group: group}
	}

	// Private key x must satisfy 2 <= x <= p-2.
	// We generate x in [2, p-2] by generating in [0, p-4] and adding 2.
	pMinus3 := new(big.Int).Sub(params.P, big.NewInt(3))
	x, err := rand.Int(rand.Reader, pMinus3)
	if err != nil {
		return nil, nil, ErrGenerateKey{Group: "FFDHE", Err: err}
	}
	x.Add(x, big.NewInt(2))

	// Public key = g^x mod p.
	pub := new(big.Int).Exp(params.G, x, params.P)

	pubBytes := padBigEndian(pub, params.Size)
	return &ffdhePrivateKey{Group: group, X: x}, pubBytes, nil
}

// computeFFDHE computes the shared secret peerPublic^x mod p for the given
// FFDHE group, returning a fixed-size big-endian byte slice.
func computeFFDHE(
	group algo.DHENamedGroup,
	priv *ffdhePrivateKey,
	peerPublic []byte,
) ([]byte, error) {
	params, ok := ffdheGroupParams[group]
	if !ok {
		return nil, ErrUnsupportedDHEGroup{Name: "FFDHE", Group: group}
	}

	if priv.Group != group {
		return nil, ErrFFDHEGroupMismatch{Expected: group, Got: priv.Group}
	}

	peer := new(big.Int).SetBytes(peerPublic)

	// Validate peer public key: must be in [2, p-2].
	if peer.Cmp(big.NewInt(1)) <= 0 || peer.Cmp(new(big.Int).Sub(params.P, big.NewInt(1))) >= 0 {
		return nil, ErrInvalidFFDHEKey{}
	}

	// Shared secret = peerPublic^x mod p.
	secret := new(big.Int).Exp(peer, priv.X, params.P)

	return padBigEndian(secret, params.Size), nil
}

// padBigEndian returns the big-endian representation of n, zero-padded to
// exactly size bytes. If n requires more than size bytes, it is truncated
// to the least significant size bytes (should not happen for valid FFDHE values).
func padBigEndian(n *big.Int, size int) []byte {
	b := n.Bytes()
	if len(b) >= size {
		return b[len(b)-size:]
	}

	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

// RFC 7919 FFDHE prime parameters (hex, without separators).
// Verified against OpenSSL's built-in named groups.
// Generator g = 2 for all groups.

const ffdhe2048PrimeHex = "" +
	"FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1" +
	"D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9" +
	"7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561" +
	"2433F51F5F066ED0856365553DED1AF3B557135E7F57C935" +
	"984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735" +
	"30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB" +
	"B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19" +
	"0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61" +
	"9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73" +
	"3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA" +
	"886B423861285C97FFFFFFFFFFFFFFFF"

const ffdhe3072PrimeHex = "" +
	"FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1" +
	"D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9" +
	"7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561" +
	"2433F51F5F066ED0856365553DED1AF3B557135E7F57C935" +
	"984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735" +
	"30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB" +
	"B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19" +
	"0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61" +
	"9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73" +
	"3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA" +
	"886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C0238" +
	"61B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C" +
	"AEFE130985139270B4130C93BC437944F4FD4452E2D74DD3" +
	"64F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D" +
	"ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF" +
	"3C1B20EE3FD59D7C25E41D2B66C62E37FFFFFFFFFFFFFFFF"

const ffdhe4096PrimeHex = "" +
	"FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1" +
	"D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9" +
	"7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561" +
	"2433F51F5F066ED0856365553DED1AF3B557135E7F57C935" +
	"984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735" +
	"30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB" +
	"B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19" +
	"0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61" +
	"9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73" +
	"3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA" +
	"886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C0238" +
	"61B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C" +
	"AEFE130985139270B4130C93BC437944F4FD4452E2D74DD3" +
	"64F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D" +
	"ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF" +
	"3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB" +
	"7930E9E4E58857B6AC7D5F42D69F6D187763CF1D55034004" +
	"87F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832" +
	"A907600A918130C46DC778F971AD0038092999A333CB8B7A1" +
	"A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF8" +
	"EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E655F6AF" +
	"FFFFFFFFFFFFFF"
