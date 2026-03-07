package algo

import (
	"crypto"
	"fmt"
)

// MeasurementHashAlgo represents SPDM measurement hash algorithm bitmask.
type MeasurementHashAlgo uint32

const (
	MeasHashRawBitStream MeasurementHashAlgo = 0x00000001
	MeasHashSHA256       MeasurementHashAlgo = 0x00000002
	MeasHashSHA384       MeasurementHashAlgo = 0x00000004
	MeasHashSHA512       MeasurementHashAlgo = 0x00000008
	MeasHashSHA3_256     MeasurementHashAlgo = 0x00000010
	MeasHashSHA3_384     MeasurementHashAlgo = 0x00000020
	MeasHashSHA3_512     MeasurementHashAlgo = 0x00000040
	MeasHashSM3_256      MeasurementHashAlgo = 0x00000080
)

var allMeasHashAlgos = []MeasurementHashAlgo{
	MeasHashRawBitStream, MeasHashSHA256, MeasHashSHA384, MeasHashSHA512,
	MeasHashSHA3_256, MeasHashSHA3_384, MeasHashSHA3_512, MeasHashSM3_256,
}

func (a MeasurementHashAlgo) String() string {
	switch a {
	case MeasHashRawBitStream:
		return "RawBitStream"
	case MeasHashSHA256:
		return "SHA-256"
	case MeasHashSHA384:
		return "SHA-384"
	case MeasHashSHA512:
		return "SHA-512"
	case MeasHashSHA3_256:
		return "SHA3-256"
	case MeasHashSHA3_384:
		return "SHA3-384"
	case MeasHashSHA3_512:
		return "SHA3-512"
	case MeasHashSM3_256:
		return "SM3-256"
	default:
		return fmt.Sprintf("MeasurementHashAlgo(0x%08X)", uint32(a))
	}
}

// Contains reports whether the bitmask a has the bit(s) in other set.
func (a MeasurementHashAlgo) Contains(other MeasurementHashAlgo) bool { return a&other != 0 }

// Size returns the digest size in bytes for a single algorithm.
// Returns 0 for RawBitStream (variable size), unknown, or multi-bit values.
func (a MeasurementHashAlgo) Size() int {
	switch a {
	case MeasHashSHA256, MeasHashSHA3_256, MeasHashSM3_256:
		return 32
	case MeasHashSHA384, MeasHashSHA3_384:
		return 48
	case MeasHashSHA512, MeasHashSHA3_512:
		return 64
	default:
		return 0
	}
}

// CryptoHash maps to a crypto.Hash value. Returns 0 for unsupported algorithms
// (including RawBitStream and SM3).
func (a MeasurementHashAlgo) CryptoHash() crypto.Hash {
	switch a {
	case MeasHashSHA256:
		return crypto.SHA256
	case MeasHashSHA384:
		return crypto.SHA384
	case MeasHashSHA512:
		return crypto.SHA512
	case MeasHashSHA3_256:
		return crypto.SHA3_256
	case MeasHashSHA3_384:
		return crypto.SHA3_384
	case MeasHashSHA3_512:
		return crypto.SHA3_512
	default:
		return 0
	}
}

// SingleAlgos returns individual algorithms set in the bitmask.
func (a MeasurementHashAlgo) SingleAlgos() []MeasurementHashAlgo {
	var result []MeasurementHashAlgo
	for _, alg := range allMeasHashAlgos {
		if a&alg != 0 {
			result = append(result, alg)
		}
	}
	return result
}

// MeasurementSpec represents the measurement specification bitmask.
type MeasurementSpec uint8

const (
	// MeasurementSpecDMTF indicates the DMTF measurement specification.
	MeasurementSpecDMTF MeasurementSpec = 0x01
)

// KeySchedule represents the SPDM key schedule bitmask.
type KeySchedule uint16

const (
	// KeyScheduleSPDM indicates the SPDM key schedule.
	KeyScheduleSPDM KeySchedule = 0x0001
)
