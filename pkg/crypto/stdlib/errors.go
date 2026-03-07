package stdlib

import (
	"fmt"

	"github.com/xaionaro-go/spdm/pkg/gen/algo"
)

// ErrGenerateKey indicates a failure to generate a key for the given group/algorithm.
type ErrGenerateKey struct {
	Group string
	Err   error
}

func (e ErrGenerateKey) Error() string {
	return "generating " + e.Group + " key: " + e.Err.Error()
}

func (e ErrGenerateKey) Unwrap() error {
	return e.Err
}

// ErrUnexpectedKeyType indicates that a key argument had an unexpected concrete type.
type ErrUnexpectedKeyType struct {
	Expected string
	Got      any
}

func (e ErrUnexpectedKeyType) Error() string {
	return fmt.Sprintf("expected %s, got %T", e.Expected, e.Got)
}

func (e ErrUnexpectedKeyType) Unwrap() error {
	return nil
}

// ErrParsePublicKey indicates a failure to parse a peer's public key.
type ErrParsePublicKey struct {
	Err error
}

func (e ErrParsePublicKey) Error() string {
	return "parsing peer public key: " + e.Err.Error()
}

func (e ErrParsePublicKey) Unwrap() error {
	return e.Err
}

// ErrComputeSharedSecret indicates a failure to compute a shared secret.
type ErrComputeSharedSecret struct {
	Group string
	Err   error
}

func (e ErrComputeSharedSecret) Error() string {
	return "computing " + e.Group + " shared secret: " + e.Err.Error()
}

func (e ErrComputeSharedSecret) Unwrap() error {
	return e.Err
}

// ErrUnsupportedDHEGroup indicates that the requested DHE group is not supported.
type ErrUnsupportedDHEGroup struct {
	// Name is the kind of DHE group (e.g. "DHE", "FFDHE").
	Name  string
	Group algo.DHENamedGroup
}

func (e ErrUnsupportedDHEGroup) Error() string {
	return "unsupported " + e.Name + " group: " + e.Group.String()
}

func (e ErrUnsupportedDHEGroup) Unwrap() error {
	return nil
}

// ErrUnsupportedHashAlgorithm indicates that the requested hash algorithm is not supported.
type ErrUnsupportedHashAlgorithm struct {
	Algorithm algo.BaseHashAlgo
}

func (e ErrUnsupportedHashAlgorithm) Error() string {
	return "unsupported hash algorithm: " + e.Algorithm.String()
}

func (e ErrUnsupportedHashAlgorithm) Unwrap() error {
	return nil
}

// ErrUnsupportedAsymAlgorithm indicates that the requested asymmetric algorithm is not supported.
type ErrUnsupportedAsymAlgorithm struct {
	Algorithm algo.BaseAsymAlgo
}

func (e ErrUnsupportedAsymAlgorithm) Error() string {
	return "unsupported asymmetric algorithm: " + e.Algorithm.String()
}

func (e ErrUnsupportedAsymAlgorithm) Unwrap() error {
	return nil
}

// ErrUnsupportedAEADSuite indicates that the requested AEAD cipher suite is not supported.
type ErrUnsupportedAEADSuite struct {
	Suite algo.AEADCipherSuite
}

func (e ErrUnsupportedAEADSuite) Error() string {
	return "unsupported AEAD cipher suite: " + e.Suite.String()
}

func (e ErrUnsupportedAEADSuite) Unwrap() error {
	return nil
}

// ErrUnsupportedDigestSize indicates that the digest size is not valid for the given algorithm.
type ErrUnsupportedDigestSize struct {
	Size      int
	Algorithm string
}

func (e ErrUnsupportedDigestSize) Error() string {
	return fmt.Sprintf("unsupported digest size %d for %s", e.Size, e.Algorithm)
}

func (e ErrUnsupportedDigestSize) Unwrap() error {
	return nil
}

// ErrVerificationFailed indicates that a signature verification did not succeed.
type ErrVerificationFailed struct {
	Algorithm string
}

func (e ErrVerificationFailed) Error() string {
	return e.Algorithm + " verification failed"
}

func (e ErrVerificationFailed) Unwrap() error {
	return nil
}

// ErrInvalidSignatureLength indicates that the signature had an unexpected length.
type ErrInvalidSignatureLength struct {
	Expected int
	Got      int
}

func (e ErrInvalidSignatureLength) Error() string {
	return fmt.Sprintf("expected signature length %d, got %d", e.Expected, e.Got)
}

func (e ErrInvalidSignatureLength) Unwrap() error {
	return nil
}

// ErrInvalidFFDHEKey indicates that a peer FFDHE public key is out of the valid range.
type ErrInvalidFFDHEKey struct{}

func (e ErrInvalidFFDHEKey) Error() string {
	return "invalid FFDHE peer public key: out of range [2, p-2]"
}

func (e ErrInvalidFFDHEKey) Unwrap() error {
	return nil
}

// ErrFFDHEGroupMismatch indicates that the private key's group does not match the requested group.
type ErrFFDHEGroupMismatch struct {
	Expected algo.DHENamedGroup
	Got      algo.DHENamedGroup
}

func (e ErrFFDHEGroupMismatch) Error() string {
	return "private key group " + e.Got.String() + " does not match requested group " + e.Expected.String()
}

func (e ErrFFDHEGroupMismatch) Unwrap() error {
	return nil
}

// ErrCreateCipher indicates a failure to create a block cipher.
type ErrCreateCipher struct {
	Algorithm string
	Err       error
}

func (e ErrCreateCipher) Error() string {
	return "creating " + e.Algorithm + " cipher: " + e.Err.Error()
}

func (e ErrCreateCipher) Unwrap() error {
	return e.Err
}

// ErrCreateAEAD indicates a failure to create an AEAD from a block cipher.
type ErrCreateAEAD struct {
	Algorithm string
	Err       error
}

func (e ErrCreateAEAD) Error() string {
	return "creating " + e.Algorithm + ": " + e.Err.Error()
}

func (e ErrCreateAEAD) Unwrap() error {
	return e.Err
}

// ErrAEADOpen indicates that AEAD decryption/authentication failed.
type ErrAEADOpen struct {
	Err error
}

func (e ErrAEADOpen) Error() string {
	return "AEAD open failed: " + e.Err.Error()
}

func (e ErrAEADOpen) Unwrap() error {
	return e.Err
}
