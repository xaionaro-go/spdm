package stdlib

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"github.com/emmansun/gmsm/sm3"
	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"golang.org/x/crypto/sha3"
)

// StdHashProvider implements crypto.HashProvider using the Go standard library.
type StdHashProvider struct{}

func (p *StdHashProvider) NewHash(a algo.BaseHashAlgo) (hash.Hash, error) {
	switch a {
	case algo.HashSHA256:
		return sha256.New(), nil
	case algo.HashSHA384:
		return sha512.New384(), nil
	case algo.HashSHA512:
		return sha512.New(), nil
	case algo.HashSHA3_256:
		return sha3.New256(), nil
	case algo.HashSHA3_384:
		return sha3.New384(), nil
	case algo.HashSHA3_512:
		return sha3.New512(), nil
	case algo.HashSM3_256:
		return sm3.New(), nil
	default:
		return nil, ErrUnsupportedHashAlgorithm{Algorithm: a}
	}
}
