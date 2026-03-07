package stdlib

import (
	gocrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"math/big"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/emmansun/gmsm/sm2"
	"github.com/xaionaro-go/spdm/pkg/gen/algo"
)

// StdVerifier implements crypto.Verifier using the Go standard library.
type StdVerifier struct{}

func (v *StdVerifier) Verify(a algo.BaseAsymAlgo, pub gocrypto.PublicKey, digest, sig []byte) error {
	switch a {
	case algo.AsymRSASSA2048, algo.AsymRSASSA3072, algo.AsymRSASSA4096:
		return v.verifyRSASSA(pub, digest, sig)
	case algo.AsymRSAPSS2048, algo.AsymRSAPSS3072, algo.AsymRSAPSS4096:
		return v.verifyRSAPSS(pub, digest, sig)
	case algo.AsymECDSAP256, algo.AsymECDSAP384, algo.AsymECDSAP521:
		return v.verifyECDSA(a, pub, digest, sig)
	case algo.AsymEdDSAEd25519:
		return v.verifyEd25519(pub, digest, sig)
	case algo.AsymEdDSAEd448:
		return v.verifyEd448(pub, digest, sig)
	case algo.AsymSM2P256:
		return v.verifySM2(pub, digest, sig)
	default:
		return ErrUnsupportedAsymAlgorithm{Algorithm: a}
	}
}

func (v *StdVerifier) verifyRSASSA(pub gocrypto.PublicKey, digest, sig []byte) error {
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return ErrUnexpectedKeyType{Expected: "*rsa.PublicKey", Got: pub}
	}
	hashAlgo := hashForDigestSize(len(digest))
	if hashAlgo == 0 {
		return ErrUnsupportedDigestSize{Size: len(digest), Algorithm: "RSA"}
	}
	return rsa.VerifyPKCS1v15(rsaPub, hashAlgo, digest, sig)
}

func (v *StdVerifier) verifyRSAPSS(pub gocrypto.PublicKey, digest, sig []byte) error {
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return ErrUnexpectedKeyType{Expected: "*rsa.PublicKey", Got: pub}
	}
	hashAlgo := hashForDigestSize(len(digest))
	if hashAlgo == 0 {
		return ErrUnsupportedDigestSize{Size: len(digest), Algorithm: "RSA-PSS"}
	}
	return rsa.VerifyPSS(rsaPub, hashAlgo, digest, sig, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
}

// verifyECDSA verifies an SPDM ECDSA signature in raw r||s format.
func (v *StdVerifier) verifyECDSA(a algo.BaseAsymAlgo, pub gocrypto.PublicKey, digest, sig []byte) error {
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return ErrUnexpectedKeyType{Expected: "*ecdsa.PublicKey", Got: pub}
	}
	// SPDM uses raw r||s concatenation, each component is half the signature.
	componentLen := a.SignatureSize() / 2
	if len(sig) != a.SignatureSize() {
		return ErrInvalidSignatureLength{Expected: a.SignatureSize(), Got: len(sig)}
	}
	r := new(big.Int).SetBytes(sig[:componentLen])
	s := new(big.Int).SetBytes(sig[componentLen:])
	if !ecdsa.Verify(ecPub, digest, r, s) {
		return ErrVerificationFailed{Algorithm: "ECDSA"}
	}
	return nil
}

// verifyEd25519 verifies an Ed25519 signature. For EdDSA, the digest parameter
// is the full message (Ed25519 hashes internally).
func (v *StdVerifier) verifyEd25519(pub gocrypto.PublicKey, message, sig []byte) error {
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return ErrUnexpectedKeyType{Expected: "ed25519.PublicKey", Got: pub}
	}
	if !ed25519.Verify(edPub, message, sig) {
		return ErrVerificationFailed{Algorithm: "Ed25519"}
	}
	return nil
}

// verifyEd448 verifies an Ed448 signature. Like Ed25519, the digest parameter
// is the full message (Ed448 hashes internally).
func (v *StdVerifier) verifyEd448(pub gocrypto.PublicKey, message, sig []byte) error {
	edPub, ok := pub.(ed448.PublicKey)
	if !ok {
		return ErrUnexpectedKeyType{Expected: "ed448.PublicKey", Got: pub}
	}
	if !ed448.Verify(edPub, message, sig, "") {
		return ErrVerificationFailed{Algorithm: "Ed448"}
	}
	return nil
}

// verifySM2 verifies an SM2 signature in raw r||s format.
func (v *StdVerifier) verifySM2(pub gocrypto.PublicKey, digest, sig []byte) error {
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return ErrUnexpectedKeyType{Expected: "*ecdsa.PublicKey", Got: pub}
	}

	const componentLen = 32
	if len(sig) != 2*componentLen {
		return ErrInvalidSignatureLength{Expected: 2 * componentLen, Got: len(sig)}
	}

	r := new(big.Int).SetBytes(sig[:componentLen])
	s := new(big.Int).SetBytes(sig[componentLen:])
	if !sm2.Verify(ecPub, digest, r, s) {
		return ErrVerificationFailed{Algorithm: "SM2"}
	}
	return nil
}

// hashForDigestSize returns the crypto.Hash matching the given digest byte length.
func hashForDigestSize(size int) gocrypto.Hash {
	switch size {
	case 32:
		return gocrypto.SHA256
	case 48:
		return gocrypto.SHA384
	case 64:
		return gocrypto.SHA512
	default:
		return 0
	}
}
