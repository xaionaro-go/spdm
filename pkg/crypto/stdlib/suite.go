package stdlib

import (
	gocrypto "crypto"
	"crypto/rand"
	"crypto/x509"

	"github.com/xaionaro-go/spdm/pkg/crypto"
)

// NewSuite returns a Suite wired to Go standard library cryptographic primitives.
func NewSuite(signer gocrypto.Signer, certPool *x509.CertPool) *crypto.Suite {
	return &crypto.Suite{
		Hash:         &StdHashProvider{},
		Signer:       signer,
		Verifier:     &StdVerifier{},
		KeyAgreement: &StdKeyAgreement{},
		AEAD:         &StdAEAD{},
		CertPool:     certPool,
		Random:       rand.Reader,
	}
}
