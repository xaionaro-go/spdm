package session

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"

	"github.com/xaionaro-go/spdm/pkg/gen/algo"
)

var (
	ErrDecryptFailed    = errors.New("spdm: decryption failed")
	ErrSequenceOverflow = errors.New("spdm: sequence number overflow")
)

// NewAEADCipher creates an AEAD cipher for the given suite and key.
func NewAEADCipher(suite algo.AEADCipherSuite, key []byte) (cipher.AEAD, error) {
	switch suite {
	case algo.AEADAES128GCM, algo.AEADAES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case algo.AEADChaCha20Poly1305:
		// Dynamically import to avoid hard dependency — use the golang.org/x/crypto version
		// For now, we'll use a direct import approach
		return newChaCha20Poly1305(key)
	default:
		return nil, &ErrUnsupportedAEADSuite{Suite: suite}
	}
}

// BuildNonce XORs the base IV with the sequence number to produce the per-record nonce
// per DSP0277 Section 6. The sequence number is encoded in little-endian and XOR'd
// at the beginning of the nonce (index 0).
// seqNumSize controls how many bytes of the sequence number are XOR'd (typically 8).
func BuildNonce(iv []byte, seqNum uint64, seqNumSize int) []byte {
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	for i := 0; i < seqNumSize && i < len(nonce); i++ {
		nonce[i] ^= byte(seqNum >> (8 * i))
	}
	return nonce
}

// SecuredMessageHeader represents the authenticated data header for a secured SPDM message.
type SecuredMessageHeader struct {
	SessionID uint32
	// SequenceNumber is transport-specific; for simplicity we use a uint64.
	Length uint16 // length of remaining data (cipher_header + encrypted_data + tag)
}

// EncodeSecuredMessage encrypts an SPDM message for a session
// per DSP0277 Section 6 (Secured Messages).
// seqNumSize is the transport-specific sequence number size (0=NONE, 2=MCTP, 8=TCP).
// It controls both the record header AAD and the nonce XOR.
// Returns the complete secured message including the A-data header.
func EncodeSecuredMessage(
	suite algo.AEADCipherSuite,
	key, iv []byte,
	seqNum uint64,
	sessionID uint32,
	plaintext []byte,
	encryptionRequired bool,
	seqNumSize int,
) ([]byte, error) {
	aead, err := NewAEADCipher(suite, key)
	if err != nil {
		return nil, err
	}

	nonce := BuildNonce(iv, seqNum, seqNumSize)

	if encryptionRequired {
		appDataLen := len(plaintext)
		plainWithHeader := make([]byte, 2+appDataLen)
		binary.LittleEndian.PutUint16(plainWithHeader, uint16(appDataLen))
		copy(plainWithHeader[2:], plaintext)

		encLen := len(plainWithHeader)
		totalLen := encLen + aead.Overhead()

		// AAD: session_id (4) + seqNum (seqNumSize) + length (2)
		aadLen := 4 + seqNumSize + 2
		aad := make([]byte, aadLen)
		binary.LittleEndian.PutUint32(aad, sessionID)
		writeSeqNum(aad[4:4+seqNumSize], seqNum, seqNumSize)
		binary.LittleEndian.PutUint16(aad[4+seqNumSize:], uint16(totalLen))

		ciphertext := aead.Seal(nil, nonce, plainWithHeader, aad)

		result := make([]byte, 0, len(aad)+len(ciphertext))
		result = append(result, aad...)
		result = append(result, ciphertext...)
		return result, nil
	}

	// AUTH-only mode: MAC over plaintext, no encryption
	aadHeaderLen := 4 + seqNumSize + 2
	totalLen := len(plaintext) + aead.Overhead()
	aad := make([]byte, aadHeaderLen+len(plaintext))
	binary.LittleEndian.PutUint32(aad, sessionID)
	writeSeqNum(aad[4:4+seqNumSize], seqNum, seqNumSize)
	binary.LittleEndian.PutUint16(aad[4+seqNumSize:], uint16(totalLen))
	copy(aad[aadHeaderLen:], plaintext)

	tag := aead.Seal(nil, nonce, nil, aad)

	result := make([]byte, 0, aadHeaderLen+len(plaintext)+len(tag))
	result = append(result, aad[:aadHeaderLen]...)
	result = append(result, plaintext...)
	result = append(result, tag...)
	return result, nil
}

// writeSeqNum writes the sequence number in little-endian to buf.
func writeSeqNum(buf []byte, seqNum uint64, size int) {
	for i := 0; i < size; i++ {
		buf[i] = byte(seqNum >> (8 * i))
	}
}

// DecodeSecuredMessage decrypts a secured SPDM message per DSP0277 Section 6.
// seqNumSize is the transport-specific sequence number size in the record header.
// Returns the session ID and decrypted application data.
func DecodeSecuredMessage(
	suite algo.AEADCipherSuite,
	key, iv []byte,
	seqNum uint64,
	encryptionRequired bool,
	securedMsg []byte,
	seqNumSize int,
) (uint32, []byte, error) {
	headerLen := 4 + seqNumSize + 2
	if len(securedMsg) < headerLen {
		return 0, nil, ErrDecryptFailed
	}

	aead, err := NewAEADCipher(suite, key)
	if err != nil {
		return 0, nil, err
	}

	sessionID := binary.LittleEndian.Uint32(securedMsg[:4])
	recordLen := int(binary.LittleEndian.Uint16(securedMsg[4+seqNumSize : headerLen]))

	if len(securedMsg) < headerLen+recordLen {
		return 0, nil, ErrDecryptFailed
	}

	nonce := BuildNonce(iv, seqNum, seqNumSize)

	if encryptionRequired {
		aad := securedMsg[:headerLen]
		ciphertext := securedMsg[headerLen : headerLen+recordLen]

		plainWithHeader, err := aead.Open(nil, nonce, ciphertext, aad)
		if err != nil {
			return 0, nil, ErrDecryptFailed
		}

		if len(plainWithHeader) < 2 {
			return 0, nil, ErrDecryptFailed
		}
		appDataLen := int(binary.LittleEndian.Uint16(plainWithHeader))
		if 2+appDataLen > len(plainWithHeader) {
			return 0, nil, ErrDecryptFailed
		}
		return sessionID, plainWithHeader[2 : 2+appDataLen], nil
	}

	// AUTH-only: verify MAC
	tagSize := aead.Overhead()
	if recordLen < tagSize {
		return 0, nil, ErrDecryptFailed
	}
	appDataLen := recordLen - tagSize
	aadFull := make([]byte, headerLen+appDataLen)
	copy(aadFull, securedMsg[:headerLen+appDataLen])
	tag := securedMsg[headerLen+appDataLen : headerLen+recordLen]

	_, err = aead.Open(nil, nonce, tag, aadFull)
	if err != nil {
		return 0, nil, ErrDecryptFailed
	}

	return sessionID, securedMsg[headerLen : headerLen+appDataLen], nil
}
