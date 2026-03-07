package session

import (
	"github.com/xaionaro-go/spdm/pkg/gen/algo"
)

// ErrHKDFOutputTooLarge indicates that the requested HKDF-Expand output
// exceeds the maximum allowed length (255 * HashLen).
type ErrHKDFOutputTooLarge struct{}

func (e ErrHKDFOutputTooLarge) Error() string {
	return "spdm: HKDF-Expand output too large"
}

func (e ErrHKDFOutputTooLarge) Unwrap() error {
	return nil
}

// ErrUnsupportedAEADSuite indicates that the requested AEAD cipher suite is not supported.
type ErrUnsupportedAEADSuite struct {
	Suite algo.AEADCipherSuite
}

func (e ErrUnsupportedAEADSuite) Error() string {
	return "spdm: unsupported AEAD cipher suite: " + e.Suite.String()
}

func (e ErrUnsupportedAEADSuite) Unwrap() error {
	return nil
}
