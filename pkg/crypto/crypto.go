// Package crypto defines interfaces for the SPDM cryptographic operations per DSP0274 Section 12.
package crypto

import (
	"context"
	gocrypto "crypto"
	"crypto/x509"
	"hash"
	"io"

	"github.com/xaionaro-go/spdm/pkg/gen/algo"
)

// HashProvider creates hash functions for SPDM base hash algorithms per DSP0274 Table 21.
type HashProvider interface {
	NewHash(a algo.BaseHashAlgo) (hash.Hash, error)
}

// Verifier verifies asymmetric signatures per DSP0274 Section 15.
type Verifier interface {
	Verify(a algo.BaseAsymAlgo, pub gocrypto.PublicKey, digest, sig []byte) error
}

// KeyAgreement performs Diffie-Hellman key exchange per DSP0274 Section 10.12.
type KeyAgreement interface {
	GenerateDHE(group algo.DHENamedGroup) (privateKey interface{}, publicKey []byte, err error)
	ComputeDHE(group algo.DHENamedGroup, privateKey interface{}, peerPublic []byte) (sharedSecret []byte, err error)
}

// AEAD performs authenticated encryption with associated data per DSP0277 Section 6.
type AEAD interface {
	Seal(suite algo.AEADCipherSuite, key, nonce, plaintext, aad []byte) ([]byte, error)
	Open(suite algo.AEADCipherSuite, key, nonce, ciphertext, aad []byte) ([]byte, error)
}

// PSKProvider resolves pre-shared keys by hint per DSP0274 Section 10.12.
type PSKProvider interface {
	Lookup(ctx context.Context, hint []byte) (psk []byte, err error)
}

// Suite groups all cryptographic providers needed by an SPDM endpoint per DSP0274 Section 12.
type Suite struct {
	Hash         HashProvider
	Signer       gocrypto.Signer
	Verifier     Verifier
	KeyAgreement KeyAgreement
	AEAD         AEAD
	CertPool     *x509.CertPool
	Random       io.Reader
}
