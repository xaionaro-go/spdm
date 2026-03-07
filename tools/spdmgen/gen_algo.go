package main

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/xaionaro-go/spdm/internal/cheader"
)

type algoConstant struct {
	cName     string
	goName    string
	stringVal string
}

var hashAlgoMapping = []algoConstant{
	{"SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256", "HashSHA256", "SHA-256"},
	{"SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384", "HashSHA384", "SHA-384"},
	{"SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512", "HashSHA512", "SHA-512"},
	{"SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256", "HashSHA3_256", "SHA3-256"},
	{"SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384", "HashSHA3_384", "SHA3-384"},
	{"SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512", "HashSHA3_512", "SHA3-512"},
	{"SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256", "HashSM3_256", "SM3-256"},
}

var asymAlgoMapping = []algoConstant{
	{"SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048", "AsymRSASSA2048", "RSASSA-2048"},
	{"SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048", "AsymRSAPSS2048", "RSAPSS-2048"},
	{"SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072", "AsymRSASSA3072", "RSASSA-3072"},
	{"SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072", "AsymRSAPSS3072", "RSAPSS-3072"},
	{"SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256", "AsymECDSAP256", "ECDSA-P256"},
	{"SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096", "AsymRSASSA4096", "RSASSA-4096"},
	{"SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096", "AsymRSAPSS4096", "RSAPSS-4096"},
	{"SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384", "AsymECDSAP384", "ECDSA-P384"},
	{"SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521", "AsymECDSAP521", "ECDSA-P521"},
	{"SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256", "AsymSM2P256", "SM2-P256"},
	{"SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519", "AsymEdDSAEd25519", "EdDSA-Ed25519"},
	{"SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448", "AsymEdDSAEd448", "EdDSA-Ed448"},
}

var dheAlgoMapping = []algoConstant{
	{"SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048", "DHEFFDHE2048", "FFDHE2048"},
	{"SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072", "DHEFFDHE3072", "FFDHE3072"},
	{"SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096", "DHEFFDHE4096", "FFDHE4096"},
	{"SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1", "DHESECP256R1", "SECP256R1"},
	{"SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1", "DHESECP384R1", "SECP384R1"},
	{"SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1", "DHESECP521R1", "SECP521R1"},
	{"SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256", "DHESM2P256", "SM2-P256"},
}

var aeadAlgoMapping = []algoConstant{
	{"SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM", "AEADAES128GCM", "AES-128-GCM"},
	{"SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM", "AEADAES256GCM", "AES-256-GCM"},
	{"SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305", "AEADChaCha20Poly1305", "ChaCha20-Poly1305"},
	{"SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AEAD_SM4_GCM", "AEADSM4GCM", "SM4-GCM"},
}

func generateAlgo(
	parsed *cheader.ParseResult,
	outDir string,
	verify bool,
) error {
	defineMap := buildDefineMap(parsed)

	if err := generateHashAlgo(defineMap, outDir, verify); err != nil {
		return fmt.Errorf("hash.go: %w", err)
	}

	if err := generateAsymAlgo(defineMap, outDir, verify); err != nil {
		return fmt.Errorf("asym.go: %w", err)
	}

	if err := generateDHEAlgo(defineMap, outDir, verify); err != nil {
		return fmt.Errorf("dhe.go: %w", err)
	}

	if err := generateAEADAlgo(defineMap, outDir, verify); err != nil {
		return fmt.Errorf("aead.go: %w", err)
	}

	return nil
}

func generateHashAlgo(
	defineMap map[string]uint64,
	outDir string,
	verify bool,
) error {
	var buf bytes.Buffer
	buf.WriteString(generatedHeader)
	buf.WriteString("package algo\n\n")
	buf.WriteString("import (\n\t\"crypto\"\n\t\"fmt\"\n)\n\n")
	buf.WriteString("// BaseHashAlgo represents SPDM base hash algorithm bitmask per DSP0274 Table 21.\n")
	buf.WriteString("type BaseHashAlgo uint32\n\n")

	buf.WriteString("const (\n")
	for _, m := range hashAlgoMapping {
		val, ok := defineMap[m.cName]
		if !ok {
			return fmt.Errorf("missing define %s", m.cName)
		}
		buf.WriteString(fmt.Sprintf("\t%-12s BaseHashAlgo = 0x%08X\n", m.goName, val))
	}
	buf.WriteString(")\n\n")

	// allBaseHashAlgos slice.
	buf.WriteString("var allBaseHashAlgos = []BaseHashAlgo{\n\t")
	names := make([]string, 0, len(hashAlgoMapping))
	for _, m := range hashAlgoMapping {
		names = append(names, m.goName)
	}
	// Group: first 3, then next 3, then 1.
	buf.WriteString(strings.Join(names[:3], ", "))
	buf.WriteString(",\n\t")
	buf.WriteString(strings.Join(names[3:6], ", "))
	buf.WriteString(",\n\t")
	buf.WriteString(names[6])
	buf.WriteString(",\n}\n\n")

	// String method.
	buf.WriteString("func (a BaseHashAlgo) String() string {\n\tswitch a {\n")
	for _, m := range hashAlgoMapping {
		buf.WriteString(fmt.Sprintf("\tcase %s:\n\t\treturn %q\n", m.goName, m.stringVal))
	}
	buf.WriteString("\tdefault:\n\t\treturn fmt.Sprintf(\"BaseHashAlgo(0x%08X)\", uint32(a))\n\t}\n}\n\n")

	// Contains method.
	buf.WriteString("// Contains reports whether the bitmask a has the bit(s) in other set.\n")
	buf.WriteString("func (a BaseHashAlgo) Contains(other BaseHashAlgo) bool { return a&other != 0 }\n\n")

	// Size method.
	buf.WriteString(`// Size returns the digest size in bytes for a single algorithm.
// Returns 0 for unknown or multi-bit values.
func (a BaseHashAlgo) Size() int {
	switch a {
	case HashSHA256, HashSHA3_256, HashSM3_256:
		return 32
	case HashSHA384, HashSHA3_384:
		return 48
	case HashSHA512, HashSHA3_512:
		return 64
	default:
		return 0
	}
}
`)
	buf.WriteString("\n")

	// CryptoHash method.
	buf.WriteString(`// CryptoHash maps to a crypto.Hash value. Returns 0 for unsupported algorithms.
func (a BaseHashAlgo) CryptoHash() crypto.Hash {
	switch a {
	case HashSHA256:
		return crypto.SHA256
	case HashSHA384:
		return crypto.SHA384
	case HashSHA512:
		return crypto.SHA512
	case HashSHA3_256:
		return crypto.SHA3_256
	case HashSHA3_384:
		return crypto.SHA3_384
	case HashSHA3_512:
		return crypto.SHA3_512
	default:
		return 0
	}
}
`)
	buf.WriteString("\n")

	// SingleAlgos method.
	buf.WriteString(`// SingleAlgos returns individual algorithms set in the bitmask.
func (a BaseHashAlgo) SingleAlgos() []BaseHashAlgo {
	var result []BaseHashAlgo
	for _, alg := range allBaseHashAlgos {
		if a&alg != 0 {
			result = append(result, alg)
		}
	}
	return result
}
`)

	return writeOrVerify(filepath.Join(outDir, "hash.go"), buf.Bytes(), verify)
}

func generateAsymAlgo(
	defineMap map[string]uint64,
	outDir string,
	verify bool,
) error {
	var buf bytes.Buffer
	buf.WriteString(generatedHeader)
	buf.WriteString("package algo\n\nimport \"fmt\"\n\n")
	buf.WriteString("// BaseAsymAlgo represents SPDM base asymmetric algorithm bitmask per DSP0274 Table 21.\n")
	buf.WriteString("type BaseAsymAlgo uint32\n\n")

	buf.WriteString("const (\n")
	for _, m := range asymAlgoMapping {
		val, ok := defineMap[m.cName]
		if !ok {
			return fmt.Errorf("missing define %s", m.cName)
		}
		buf.WriteString(fmt.Sprintf("\t%-16s BaseAsymAlgo = 0x%08X\n", m.goName, val))
	}
	buf.WriteString(")\n\n")

	// allBaseAsymAlgos slice.
	buf.WriteString("var allBaseAsymAlgos = []BaseAsymAlgo{\n\t")
	names := make([]string, 0, len(asymAlgoMapping))
	for _, m := range asymAlgoMapping {
		names = append(names, m.goName)
	}
	buf.WriteString(strings.Join(names[:4], ", "))
	buf.WriteString(",\n\t")
	buf.WriteString(strings.Join(names[4:8], ", "))
	buf.WriteString(",\n\t")
	buf.WriteString(strings.Join(names[8:], ", "))
	buf.WriteString(",\n}\n\n")

	// String method.
	buf.WriteString("func (a BaseAsymAlgo) String() string {\n\tswitch a {\n")
	for _, m := range asymAlgoMapping {
		buf.WriteString(fmt.Sprintf("\tcase %s:\n\t\treturn %q\n", m.goName, m.stringVal))
	}
	buf.WriteString("\tdefault:\n\t\treturn fmt.Sprintf(\"BaseAsymAlgo(0x%08X)\", uint32(a))\n\t}\n}\n\n")

	// Contains method.
	buf.WriteString("// Contains reports whether the bitmask a has the bit(s) in other set.\n")
	buf.WriteString("func (a BaseAsymAlgo) Contains(other BaseAsymAlgo) bool { return a&other != 0 }\n\n")

	// SignatureSize method.
	buf.WriteString(`// SignatureSize returns the signature size in bytes for a single algorithm.
// Returns 0 for unknown or multi-bit values.
func (a BaseAsymAlgo) SignatureSize() int {
	switch a {
	case AsymRSASSA2048, AsymRSAPSS2048:
		return 256
	case AsymRSASSA3072, AsymRSAPSS3072:
		return 384
	case AsymRSASSA4096, AsymRSAPSS4096:
		return 512
	case AsymECDSAP256:
		return 64
	case AsymECDSAP384:
		return 96
	case AsymECDSAP521:
		return 132
	case AsymSM2P256:
		return 64
	case AsymEdDSAEd25519:
		return 64
	case AsymEdDSAEd448:
		return 114
	default:
		return 0
	}
}
`)
	buf.WriteString("\n")

	// SingleAlgos method.
	buf.WriteString(`// SingleAlgos returns individual algorithms set in the bitmask.
func (a BaseAsymAlgo) SingleAlgos() []BaseAsymAlgo {
	var result []BaseAsymAlgo
	for _, alg := range allBaseAsymAlgos {
		if a&alg != 0 {
			result = append(result, alg)
		}
	}
	return result
}
`)

	return writeOrVerify(filepath.Join(outDir, "asym.go"), buf.Bytes(), verify)
}

func generateDHEAlgo(
	defineMap map[string]uint64,
	outDir string,
	verify bool,
) error {
	var buf bytes.Buffer
	buf.WriteString(generatedHeader)
	buf.WriteString("package algo\n\nimport \"fmt\"\n\n")
	buf.WriteString("// DHENamedGroup represents SPDM DHE named group bitmask per DSP0274 Table 21.\n")
	buf.WriteString("type DHENamedGroup uint16\n\n")

	buf.WriteString("const (\n")
	for _, m := range dheAlgoMapping {
		val, ok := defineMap[m.cName]
		if !ok {
			return fmt.Errorf("missing define %s", m.cName)
		}
		buf.WriteString(fmt.Sprintf("\t%-12s DHENamedGroup = 0x%04X\n", m.goName, val))
	}
	buf.WriteString(")\n\n")

	// allDHENamedGroups slice.
	buf.WriteString("var allDHENamedGroups = []DHENamedGroup{\n\t")
	names := make([]string, 0, len(dheAlgoMapping))
	for _, m := range dheAlgoMapping {
		names = append(names, m.goName)
	}
	buf.WriteString(strings.Join(names[:3], ", "))
	buf.WriteString(",\n\t")
	buf.WriteString(strings.Join(names[3:6], ", "))
	buf.WriteString(",\n\t")
	buf.WriteString(names[6])
	buf.WriteString(",\n}\n\n")

	// String method.
	buf.WriteString("func (g DHENamedGroup) String() string {\n\tswitch g {\n")
	for _, m := range dheAlgoMapping {
		buf.WriteString(fmt.Sprintf("\tcase %s:\n\t\treturn %q\n", m.goName, m.stringVal))
	}
	buf.WriteString("\tdefault:\n\t\treturn fmt.Sprintf(\"DHENamedGroup(0x%04X)\", uint16(g))\n\t}\n}\n\n")

	// Contains method.
	buf.WriteString("// Contains reports whether the bitmask g has the bit(s) in other set.\n")
	buf.WriteString("func (g DHENamedGroup) Contains(other DHENamedGroup) bool { return g&other != 0 }\n\n")

	// SharedSecretSize method.
	buf.WriteString(`// SharedSecretSize returns the shared secret size in bytes for a single named group.
// Returns 0 for unknown or multi-bit values.
func (g DHENamedGroup) SharedSecretSize() int {
	switch g {
	case DHEFFDHE2048:
		return 256
	case DHEFFDHE3072:
		return 384
	case DHEFFDHE4096:
		return 512
	case DHESECP256R1:
		return 32
	case DHESECP384R1:
		return 48
	case DHESECP521R1:
		return 66
	case DHESM2P256:
		return 32
	default:
		return 0
	}
}
`)
	buf.WriteString("\n")

	// DHEPublicKeySize method.
	buf.WriteString(`// DHEPublicKeySize returns the DHE exchange data (public key) size in bytes
// per DSP0274 Table 21. For ECDHE this is 2*coordinate_size (x+y without 0x04
// prefix). For FFDHE this equals the shared secret size.
// Returns 0 for unknown or multi-bit values.
func (g DHENamedGroup) DHEPublicKeySize() int {
	switch g {
	case DHEFFDHE2048:
		return 256
	case DHEFFDHE3072:
		return 384
	case DHEFFDHE4096:
		return 512
	case DHESECP256R1:
		return 64
	case DHESECP384R1:
		return 96
	case DHESECP521R1:
		return 132
	case DHESM2P256:
		return 64
	default:
		return 0
	}
}
`)
	buf.WriteString("\n")

	// SingleAlgos method.
	buf.WriteString(`// SingleAlgos returns individual named groups set in the bitmask.
func (g DHENamedGroup) SingleAlgos() []DHENamedGroup {
	var result []DHENamedGroup
	for _, ng := range allDHENamedGroups {
		if g&ng != 0 {
			result = append(result, ng)
		}
	}
	return result
}
`)

	return writeOrVerify(filepath.Join(outDir, "dhe.go"), buf.Bytes(), verify)
}

func generateAEADAlgo(
	defineMap map[string]uint64,
	outDir string,
	verify bool,
) error {
	var buf bytes.Buffer
	buf.WriteString(generatedHeader)
	buf.WriteString("package algo\n\nimport \"fmt\"\n\n")
	buf.WriteString("// AEADCipherSuite represents SPDM AEAD cipher suite bitmask per DSP0274 Table 21.\n")
	buf.WriteString("type AEADCipherSuite uint16\n\n")

	buf.WriteString("const (\n")
	for _, m := range aeadAlgoMapping {
		val, ok := defineMap[m.cName]
		if !ok {
			return fmt.Errorf("missing define %s", m.cName)
		}
		buf.WriteString(fmt.Sprintf("\t%-20s AEADCipherSuite = 0x%04X\n", m.goName, val))
	}
	buf.WriteString(")\n\n")

	// allAEADCipherSuites slice.
	buf.WriteString("var allAEADCipherSuites = []AEADCipherSuite{\n\t")
	names := make([]string, 0, len(aeadAlgoMapping))
	for _, m := range aeadAlgoMapping {
		names = append(names, m.goName)
	}
	buf.WriteString(strings.Join(names, ", "))
	buf.WriteString(",\n}\n\n")

	// String method.
	buf.WriteString("func (s AEADCipherSuite) String() string {\n\tswitch s {\n")
	for _, m := range aeadAlgoMapping {
		buf.WriteString(fmt.Sprintf("\tcase %s:\n\t\treturn %q\n", m.goName, m.stringVal))
	}
	buf.WriteString("\tdefault:\n\t\treturn fmt.Sprintf(\"AEADCipherSuite(0x%04X)\", uint16(s))\n\t}\n}\n\n")

	// Contains method.
	buf.WriteString("// Contains reports whether the bitmask s has the bit(s) in other set.\n")
	buf.WriteString("func (s AEADCipherSuite) Contains(other AEADCipherSuite) bool { return s&other != 0 }\n\n")

	// KeySize method.
	buf.WriteString(`// KeySize returns the key size in bytes for a single cipher suite.
// Returns 0 for unknown or multi-bit values.
func (s AEADCipherSuite) KeySize() int {
	switch s {
	case AEADAES128GCM, AEADSM4GCM:
		return 16
	case AEADAES256GCM, AEADChaCha20Poly1305:
		return 32
	default:
		return 0
	}
}
`)
	buf.WriteString("\n")

	// NonceSize method.
	buf.WriteString(`// NonceSize returns the nonce/IV size in bytes. All supported suites use 12 bytes.
// Returns 0 for unknown values.
func (s AEADCipherSuite) NonceSize() int {
	switch s {
	case AEADAES128GCM, AEADAES256GCM, AEADChaCha20Poly1305, AEADSM4GCM:
		return 12
	default:
		return 0
	}
}
`)
	buf.WriteString("\n")

	// TagSize method.
	buf.WriteString(`// TagSize returns the authentication tag size in bytes. All supported suites use 16 bytes.
// Returns 0 for unknown values.
func (s AEADCipherSuite) TagSize() int {
	switch s {
	case AEADAES128GCM, AEADAES256GCM, AEADChaCha20Poly1305, AEADSM4GCM:
		return 16
	default:
		return 0
	}
}
`)
	buf.WriteString("\n")

	// SingleAlgos method.
	buf.WriteString(`// SingleAlgos returns individual cipher suites set in the bitmask.
func (s AEADCipherSuite) SingleAlgos() []AEADCipherSuite {
	var result []AEADCipherSuite
	for _, cs := range allAEADCipherSuites {
		if s&cs != 0 {
			result = append(result, cs)
		}
	}
	return result
}
`)

	return writeOrVerify(filepath.Join(outDir, "aead.go"), buf.Bytes(), verify)
}
