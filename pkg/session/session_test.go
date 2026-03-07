package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/spdm/pkg/gen/algo"
)

func sha256Hash() hash.Hash { return sha256.New() }

func newSHA256() func() hash.Hash { return sha256Hash }

func TestHKDFExtractExpand(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt := bytes.Repeat([]byte{0x00}, 13)
	info := []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9}

	prk := HKDFExtract(newSHA256(), salt, ikm)
	require.Len(t, prk, 32)

	okm, err := HKDFExpand(newSHA256(), prk, info, 42)
	require.NoError(t, err)
	require.Len(t, okm, 42)
}

func TestBinConcat(t *testing.T) {
	bc := binConcat(32, "spdm1.2 ", "key", nil)
	// Should be: 0x20 0x00 "spdm1.2 " "key"
	require.True(t, len(bc) >= 2, "too short")
	require.Equal(t, byte(0x20), bc[0])
	require.Equal(t, byte(0x00), bc[1])
	require.Equal(t, "spdm1.2 ", string(bc[2:10]))
	require.Equal(t, "key", string(bc[10:13]))
}

func TestVersionLabel(t *testing.T) {
	assert.Equal(t, "spdm1.2 ", VersionLabel(algo.Version12))
	assert.Equal(t, "spdm1.3 ", VersionLabel(algo.Version13))
}

func TestDeriveHandshakeSecret(t *testing.T) {
	sharedSecret := bytes.Repeat([]byte{0xAA}, 32)
	hs, err := DeriveHandshakeSecret(context.Background(), newSHA256(), algo.Version12, sharedSecret)
	require.NoError(t, err)
	require.Len(t, hs, 32)
	// Should be deterministic
	hs2, err := DeriveHandshakeSecret(context.Background(), newSHA256(), algo.Version12, sharedSecret)
	require.NoError(t, err)
	assert.Equal(t, hs, hs2)
}

func TestDeriveMasterSecret(t *testing.T) {
	hs := bytes.Repeat([]byte{0xBB}, 32)
	ms, err := DeriveMasterSecret(context.Background(), newSHA256(), algo.Version12, hs)
	require.NoError(t, err)
	require.Len(t, ms, 32)
}

func TestDeriveHandshakeKeys(t *testing.T) {
	hs := bytes.Repeat([]byte{0xCC}, 32)
	th1 := bytes.Repeat([]byte{0xDD}, 32)
	keys, err := DeriveHandshakeKeys(context.Background(), newSHA256(), algo.Version12, algo.AEADAES256GCM, hs, th1)
	require.NoError(t, err)
	require.Len(t, keys.RequestKey, 32)
	require.Len(t, keys.RequestIV, 12)
	require.Len(t, keys.RequestFinished, 32)
	// Request and response keys should differ
	assert.NotEqual(t, keys.RequestKey, keys.ResponseKey)
}

func TestDeriveDataKeys(t *testing.T) {
	ms := bytes.Repeat([]byte{0xEE}, 32)
	th2 := bytes.Repeat([]byte{0xFF}, 32)
	keys, err := DeriveDataKeys(context.Background(), newSHA256(), algo.Version12, algo.AEADAES256GCM, ms, th2)
	require.NoError(t, err)
	require.Len(t, keys.RequestKey, 32)
	require.Len(t, keys.ExportMasterSecret, 32)
}

func TestGenerateFinishedKey(t *testing.T) {
	finishedKey := bytes.Repeat([]byte{0x42}, 32)
	thHash := bytes.Repeat([]byte{0x43}, 32)
	verify := GenerateFinishedKey(context.Background(), newSHA256(), finishedKey, thHash)
	require.Len(t, verify, 32)
	// Deterministic
	verify2 := GenerateFinishedKey(context.Background(), newSHA256(), finishedKey, thHash)
	assert.Equal(t, verify, verify2)
}

func TestEncodeDecodeSecuredMessageAES256(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	iv := bytes.Repeat([]byte{0x02}, 12)
	plaintext := []byte("hello SPDM secured message")
	sessionID := uint32(0xDEADBEEF)

	encrypted, err := EncodeSecuredMessage(algo.AEADAES256GCM, key, iv, 0, sessionID, plaintext, true, 0)
	require.NoError(t, err)

	gotSID, decrypted, err := DecodeSecuredMessage(algo.AEADAES256GCM, key, iv, 0, true, encrypted, 0)
	require.NoError(t, err)
	assert.Equal(t, sessionID, gotSID)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncodeDecodeSecuredMessageChaCha20(t *testing.T) {
	key := bytes.Repeat([]byte{0x03}, 32)
	iv := bytes.Repeat([]byte{0x04}, 12)
	plaintext := []byte("chacha test")
	sessionID := uint32(0xCAFEBABE)

	encrypted, err := EncodeSecuredMessage(algo.AEADChaCha20Poly1305, key, iv, 1, sessionID, plaintext, true, 0)
	require.NoError(t, err)

	gotSID, decrypted, err := DecodeSecuredMessage(algo.AEADChaCha20Poly1305, key, iv, 1, true, encrypted, 0)
	require.NoError(t, err)
	assert.Equal(t, sessionID, gotSID)
	assert.Equal(t, plaintext, decrypted)
}

func TestTamperedCiphertextFails(t *testing.T) {
	key := bytes.Repeat([]byte{0x05}, 32)
	iv := bytes.Repeat([]byte{0x06}, 12)
	plaintext := []byte("tamper test")

	encrypted, err := EncodeSecuredMessage(algo.AEADAES256GCM, key, iv, 0, 0x1234, plaintext, true, 0)
	require.NoError(t, err)

	// Tamper with ciphertext
	encrypted[len(encrypted)-1] ^= 0xFF

	_, _, err = DecodeSecuredMessage(algo.AEADAES256GCM, key, iv, 0, true, encrypted, 0)
	require.Error(t, err)
}

func TestWrongSequenceNumberFails(t *testing.T) {
	key := bytes.Repeat([]byte{0x07}, 32)
	iv := bytes.Repeat([]byte{0x08}, 12)
	plaintext := []byte("seq test")

	// Use seqNumSize=8 so the sequence number affects the nonce and AAD
	encrypted, err := EncodeSecuredMessage(algo.AEADAES256GCM, key, iv, 0, 0x5678, plaintext, true, 8)
	require.NoError(t, err)

	// Decrypt with wrong sequence number — should fail due to nonce/AAD mismatch
	_, _, err = DecodeSecuredMessage(algo.AEADAES256GCM, key, iv, 1, true, encrypted, 8)
	require.Error(t, err)
}

func TestBuildNonce(t *testing.T) {
	iv := make([]byte, 12)
	iv[0] = 0x01

	// seqNumSize=0: no XOR, nonce == iv
	nonce0 := BuildNonce(iv, 1, 0)
	assert.Equal(t, byte(0x01), nonce0[0])

	// seqNumSize=8: XOR at index 0 with LE seqNum
	nonce1 := BuildNonce(iv, 1, 8)
	assert.Equal(t, byte(0x00), nonce1[0]) // 0x01 XOR 0x01
}

func TestSessionSequenceNumber(t *testing.T) {
	s := NewSession(1, algo.Version12, algo.HashSHA256, algo.AEADAES256GCM, true)
	seq, err := s.NextReqSeqNum()
	require.NoError(t, err)
	assert.Equal(t, uint64(0), seq)
	seq, err = s.NextReqSeqNum()
	require.NoError(t, err)
	assert.Equal(t, uint64(1), seq)
}

func TestSessionState(t *testing.T) {
	s := NewSession(1, algo.Version12, algo.HashSHA256, algo.AEADAES256GCM, true)
	assert.Equal(t, StateHandshake, s.State)
	assert.Equal(t, "handshake", s.State.String())
}

func TestSessionStateStrings(t *testing.T) {
	tests := []struct {
		s    State
		want string
	}{
		{StateNone, "none"},
		{StateHandshake, "handshake"},
		{StateEstablished, "established"},
		{StateEnded, "ended"},
		{State(99), "unknown"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, tt.s.String(), "State(%d)", tt.s)
	}
}

func TestNextRspSeqNum(t *testing.T) {
	s := NewSession(1, algo.Version12, algo.HashSHA256, algo.AEADAES256GCM, true)
	seq, err := s.NextRspSeqNum()
	require.NoError(t, err)
	assert.Equal(t, uint64(0), seq)
	seq, err = s.NextRspSeqNum()
	require.NoError(t, err)
	assert.Equal(t, uint64(1), seq)
}

func TestNextReqSeqNumOverflow(t *testing.T) {
	s := NewSession(1, algo.Version12, algo.HashSHA256, algo.AEADAES256GCM, true)
	s.ReqSeqNum = ^uint64(0)
	_, err := s.NextReqSeqNum()
	assert.Equal(t, ErrSequenceOverflow, err)
}

func TestNextRspSeqNumOverflow(t *testing.T) {
	s := NewSession(1, algo.Version12, algo.HashSHA256, algo.AEADAES256GCM, true)
	s.RspSeqNum = ^uint64(0)
	_, err := s.NextRspSeqNum()
	assert.Equal(t, ErrSequenceOverflow, err)
}

func TestVersionLabelUnknown(t *testing.T) {
	label := VersionLabel(algo.Version(0x15))
	assert.NotEqual(t, "spdm1.2 ", label)
	assert.NotEqual(t, "spdm1.3 ", label)
}

func TestEncodeDecodeAuthOnly(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	iv := bytes.Repeat([]byte{0x02}, 12)
	plaintext := []byte("auth-only message")
	sessionID := uint32(0x12345678)

	encrypted, err := EncodeSecuredMessage(algo.AEADAES256GCM, key, iv, 0, sessionID, plaintext, false, 0)
	require.NoError(t, err)

	gotSID, decrypted, err := DecodeSecuredMessage(algo.AEADAES256GCM, key, iv, 0, false, encrypted, 0)
	require.NoError(t, err)
	assert.Equal(t, sessionID, gotSID)
	assert.Equal(t, plaintext, decrypted)
}

func TestDecodeSecuredMessageTooShort(t *testing.T) {
	_, _, err := DecodeSecuredMessage(algo.AEADAES256GCM, nil, nil, 0, true, []byte{0x01, 0x02}, 0)
	assert.Equal(t, ErrDecryptFailed, err)
}

func TestDecodeSecuredMessageInvalidRecordLen(t *testing.T) {
	// Header with impossibly large record length.
	msg := make([]byte, 6)
	msg[4] = 0xFF
	msg[5] = 0xFF // recordLen = 65535

	_, _, err := DecodeSecuredMessage(algo.AEADAES256GCM, bytes.Repeat([]byte{0x01}, 32), make([]byte, 12), 0, true, msg, 0)
	assert.Equal(t, ErrDecryptFailed, err)
}

func TestUnsupportedAEADSuite(t *testing.T) {
	_, err := EncodeSecuredMessage(algo.AEADCipherSuite(0xFF), nil, nil, 0, 0, nil, true, 0)
	require.Error(t, err)
}

func TestHKDFExpandTooLarge(t *testing.T) {
	_, err := HKDFExpand(newSHA256(), make([]byte, 32), nil, 256*32+1)
	require.Error(t, err)
}

func TestHKDFExtractEmptySalt(t *testing.T) {
	result := HKDFExtract(newSHA256(), nil, []byte("test"))
	require.Len(t, result, 32)
}

func TestEncodeDecodeAES128GCM(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 16) // AES-128 key
	iv := bytes.Repeat([]byte{0x02}, 12)
	plaintext := []byte("aes128 test")
	sessionID := uint32(0xABCD)

	encrypted, err := EncodeSecuredMessage(algo.AEADAES128GCM, key, iv, 0, sessionID, plaintext, true, 0)
	require.NoError(t, err)

	gotSID, decrypted, err := DecodeSecuredMessage(algo.AEADAES128GCM, key, iv, 0, true, encrypted, 0)
	require.NoError(t, err)
	assert.Equal(t, sessionID, gotSID)
	assert.Equal(t, plaintext, decrypted)
}

func TestDeriveHandshakeKeysAES128(t *testing.T) {
	hs := bytes.Repeat([]byte{0xCC}, 32)
	th1 := bytes.Repeat([]byte{0xDD}, 32)
	keys, err := DeriveHandshakeKeys(context.Background(), newSHA256(), algo.Version12, algo.AEADAES128GCM, hs, th1)
	require.NoError(t, err)
	require.Len(t, keys.RequestKey, 16)
}

func TestDeriveHandshakeKeysVersion13(t *testing.T) {
	hs := bytes.Repeat([]byte{0xCC}, 32)
	th1 := bytes.Repeat([]byte{0xDD}, 32)
	keys, err := DeriveHandshakeKeys(context.Background(), newSHA256(), algo.Version13, algo.AEADAES256GCM, hs, th1)
	require.NoError(t, err)
	require.Len(t, keys.RequestKey, 32)
}

func TestDeriveDataKeysVersion13(t *testing.T) {
	ms := bytes.Repeat([]byte{0xEE}, 32)
	th2 := bytes.Repeat([]byte{0xFF}, 32)
	keys, err := DeriveDataKeys(context.Background(), newSHA256(), algo.Version13, algo.AEADAES256GCM, ms, th2)
	require.NoError(t, err)
	require.Len(t, keys.ExportMasterSecret, 32)
}

func TestDeriveHandshakeSecretVersion13(t *testing.T) {
	shared := bytes.Repeat([]byte{0xAA}, 32)
	hs, err := DeriveHandshakeSecret(context.Background(), newSHA256(), algo.Version13, shared)
	require.NoError(t, err)
	require.Len(t, hs, 32)
}

func TestDeriveMasterSecretVersion13(t *testing.T) {
	hs := bytes.Repeat([]byte{0xBB}, 32)
	ms, err := DeriveMasterSecret(context.Background(), newSHA256(), algo.Version13, hs)
	require.NoError(t, err)
	require.Len(t, ms, 32)
}

func TestDecodeAuthOnlyShortRecord(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	iv := bytes.Repeat([]byte{0x02}, 12)
	// Valid header but record length shorter than tag size.
	msg := make([]byte, 7)
	msg[4] = 1 // recordLen = 1 (less than 16-byte AES-GCM tag)
	msg[5] = 0
	msg[6] = 0xFF
	_, _, err := DecodeSecuredMessage(algo.AEADAES256GCM, key, iv, 0, false, msg, 0)
	assert.Equal(t, ErrDecryptFailed, err)
}

func TestNewAEADCipherChaCha(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	iv := bytes.Repeat([]byte{0x02}, 12)
	plaintext := []byte("chacha auth-only")
	sessionID := uint32(0x5555)

	// Test ChaCha20 in auth-only mode.
	encrypted, err := EncodeSecuredMessage(algo.AEADChaCha20Poly1305, key, iv, 0, sessionID, plaintext, false, 0)
	require.NoError(t, err)
	gotSID, decrypted, err := DecodeSecuredMessage(algo.AEADChaCha20Poly1305, key, iv, 0, false, encrypted, 0)
	require.NoError(t, err)
	assert.Equal(t, sessionID, gotSID)
	assert.Equal(t, plaintext, decrypted)
}

func TestNewAEADCipherSM4ReturnsError(t *testing.T) {
	// SM4-GCM is not supported by the Go stdlib; NewAEADCipher should return an error.
	_, err := NewAEADCipher(algo.AEADSM4GCM, bytes.Repeat([]byte{0x01}, 16))
	require.Error(t, err)
}

func TestNewAEADCipherInvalidAESKey(t *testing.T) {
	// AES with a wrong key size should fail at aes.NewCipher.
	_, err := NewAEADCipher(algo.AEADAES256GCM, []byte{0x01, 0x02, 0x03})
	require.Error(t, err)
}

func TestBuildNonceShortIV(t *testing.T) {
	iv := []byte{0x01, 0x02, 0x03, 0x04}
	// seqNumSize=2: XOR first 2 bytes
	nonce := BuildNonce(iv, 0x0201, 2)
	require.Len(t, nonce, 4)
	assert.Equal(t, byte(0x00), nonce[0]) // 0x01 XOR 0x01
	assert.Equal(t, byte(0x00), nonce[1]) // 0x02 XOR 0x02
}

func TestBuildNonceExact8Bytes(t *testing.T) {
	iv := make([]byte, 8)
	iv[0] = 0xFF
	nonce := BuildNonce(iv, 0xFF, 8)
	// 0xFF XOR 0xFF = 0x00
	assert.Equal(t, byte(0x00), nonce[0])
}

func TestDecodeSecuredMessageUnsupportedAEAD(t *testing.T) {
	// DecodeSecuredMessage with unsupported AEAD should propagate the NewAEADCipher error.
	msg := make([]byte, 20)
	msg[4] = 10
	_, _, err := DecodeSecuredMessage(algo.AEADSM4GCM, bytes.Repeat([]byte{0x01}, 16), make([]byte, 12), 0, true, msg, 0)
	require.Error(t, err)
}

func TestDecodeSecuredMessageBadAppDataLen(t *testing.T) {
	// Craft a valid encrypted message, then tamper with the inner application_data_length
	// to exceed the decrypted payload -- triggering the appDataLen validation branch.
	key := bytes.Repeat([]byte{0x01}, 32)
	iv := bytes.Repeat([]byte{0x02}, 12)

	aead, err := NewAEADCipher(algo.AEADAES256GCM, key)
	require.NoError(t, err)

	nonce := BuildNonce(iv, 0, 0)

	// Inner payload: appDataLen=0xFFFF but only 4 bytes of data
	plainWithHeader := []byte{0xFF, 0xFF, 0x01, 0x02, 0x03, 0x04}

	sessionID := uint32(0x1234)
	encLen := len(plainWithHeader) + aead.Overhead()
	aad := make([]byte, 6)
	aad[0] = byte(sessionID)
	aad[1] = byte(sessionID >> 8)
	aad[2] = byte(sessionID >> 16)
	aad[3] = byte(sessionID >> 24)
	aad[4] = byte(encLen)
	aad[5] = byte(encLen >> 8)

	ciphertext := aead.Seal(nil, nonce, plainWithHeader, aad)
	msg := append(aad, ciphertext...)

	_, _, err = DecodeSecuredMessage(algo.AEADAES256GCM, key, iv, 0, true, msg, 0)
	assert.Equal(t, ErrDecryptFailed, err)
}

func TestDecodeSecuredMessageEmptyPlaintext(t *testing.T) {
	// Encrypt an inner payload that is only 1 byte (less than the 2-byte header),
	// triggering the len(plainWithHeader) < 2 branch.
	key := bytes.Repeat([]byte{0x01}, 32)
	iv := bytes.Repeat([]byte{0x02}, 12)

	aead, err := NewAEADCipher(algo.AEADAES256GCM, key)
	require.NoError(t, err)

	nonce := BuildNonce(iv, 0, 0)

	// Inner payload is only 1 byte -- too short for a valid application_data_length header.
	plainWithHeader := []byte{0x42}

	sessionID := uint32(0x5678)
	encLen := len(plainWithHeader) + aead.Overhead()
	aad := make([]byte, 6)
	aad[0] = byte(sessionID)
	aad[1] = byte(sessionID >> 8)
	aad[2] = byte(sessionID >> 16)
	aad[3] = byte(sessionID >> 24)
	aad[4] = byte(encLen)
	aad[5] = byte(encLen >> 8)

	ciphertext := aead.Seal(nil, nonce, plainWithHeader, aad)
	msg := append(aad, ciphertext...)

	_, _, err = DecodeSecuredMessage(algo.AEADAES256GCM, key, iv, 0, true, msg, 0)
	assert.Equal(t, ErrDecryptFailed, err)
}

// fakeHash is a hash.Hash whose Size() is controllable via a shared counter.
// The first call to newFakeHash returns a hash with Size() = firstSize.
// Subsequent calls return Size() = restSize.
// This lets us force HKDFExpand to fail: the derive function sees a large hashSize
// and passes it as the requested length to HKDFExpand, but inside HKDFExpand
// the hash reports a tiny Size(), making length > 255*hashSize.
type fakeHash struct {
	hash.Hash
	size int
}

func (f *fakeHash) Size() int                   { return f.size }
func (f *fakeHash) BlockSize() int              { return 64 }
func (f *fakeHash) Reset()                      {}
func (f *fakeHash) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakeHash) Sum(b []byte) []byte {
	out := make([]byte, f.size)
	return append(b, out...)
}

// newFailAfterNHash returns a hash factory that works normally (Size()=bigSize)
// for the first normalCalls invocations, then switches to Size()=smallSize.
// When the derive function's hash reports a large Size, the requested HKDF output
// length is large. When HKDFExpand internally calls newHash().Size() and gets the
// small size, the length check fails (length > 255*smallSize).
func newFailAfterNHash(bigSize, smallSize, normalCalls int) func() hash.Hash {
	calls := 0
	return func() hash.Hash {
		calls++
		if calls <= normalCalls {
			return &fakeHash{size: bigSize}
		}
		return &fakeHash{size: smallSize}
	}
}

func TestDeriveHandshakeSecretReturnsExtract(t *testing.T) {
	// DeriveHandshakeSecret uses HKDF-Extract with zero salt (no HKDFExpand).
	newHash := func() hash.Hash { return algo.HashSHA256.CryptoHash().New() }
	result, err := DeriveHandshakeSecret(context.Background(), newHash, algo.Version12, make([]byte, 32))
	require.NoError(t, err)
	require.Len(t, result, 32)
}

func TestDeriveMasterSecretHKDFExpandError(t *testing.T) {
	h := newFailAfterNHash(512, 1, 1)
	_, err := DeriveMasterSecret(context.Background(), h, algo.Version12, make([]byte, 32))
	require.Error(t, err)
}

func TestDeriveHandshakeKeysHKDFExpandErrors(t *testing.T) {
	// DeriveHandshakeKeys has 8 HKDFExpand calls.
	// Each HKDFExpand uses 3 factory calls (1 for Size + 2 for hmac.New).
	// Plus 1 initial factory call for hashSize in the derive function.
	// To fail on HKDFExpand #K: normalCalls = 1 + 3*(K-1), so the Size() check
	// of HKDFExpand #K gets the small hash.
	//
	// HKDFExpand calls: reqHS(1), rspHS(2), reqKey(3), reqIV(4),
	//                   reqFinished(5), rspKey(6), rspIV(7), rspFinished(8)
	for k := 1; k <= 8; k++ {
		normalCalls := 1 + 3*(k-1)
		h := newFailAfterNHash(512, 1, normalCalls)
		_, err := DeriveHandshakeKeys(context.Background(), h, algo.Version12, algo.AEADAES256GCM,
			make([]byte, 512), make([]byte, 512))
		require.Error(t, err, "expected error from HKDFExpand #%d", k)
	}
}

func TestDeriveDataKeysHKDFExpandErrors(t *testing.T) {
	// DeriveDataKeys has 7 HKDFExpand calls:
	// reqAS(1), rspAS(2), reqKey(3), reqIV(4), rspKey(5), rspIV(6), expMaster(7)
	for k := 1; k <= 7; k++ {
		normalCalls := 1 + 3*(k-1)
		h := newFailAfterNHash(512, 1, normalCalls)
		_, err := DeriveDataKeys(context.Background(), h, algo.Version12, algo.AEADAES256GCM,
			make([]byte, 512), make([]byte, 512))
		require.Error(t, err, "expected error from HKDFExpand #%d", k)
	}
}

func TestDeriveHandshakeKeysChaCha20(t *testing.T) {
	hs := bytes.Repeat([]byte{0xCC}, 32)
	th1 := bytes.Repeat([]byte{0xDD}, 32)
	keys, err := DeriveHandshakeKeys(context.Background(), newSHA256(), algo.Version12, algo.AEADChaCha20Poly1305, hs, th1)
	require.NoError(t, err)
	require.Len(t, keys.RequestKey, 32)
	require.Len(t, keys.RequestIV, 12)
	require.Len(t, keys.ResponseKey, 32)
}

func TestDeriveDataKeysAES128(t *testing.T) {
	ms := bytes.Repeat([]byte{0xEE}, 32)
	th2 := bytes.Repeat([]byte{0xFF}, 32)
	keys, err := DeriveDataKeys(context.Background(), newSHA256(), algo.Version12, algo.AEADAES128GCM, ms, th2)
	require.NoError(t, err)
	require.Len(t, keys.RequestKey, 16)
	require.Len(t, keys.ResponseKey, 16)
	require.Len(t, keys.RequestIV, 12)
}

func TestEncodeSecuredMessageSM4Fails(t *testing.T) {
	_, err := EncodeSecuredMessage(algo.AEADSM4GCM, bytes.Repeat([]byte{0x01}, 16), make([]byte, 12), 0, 0, nil, true, 0)
	require.Error(t, err)
}

func TestAuthOnlyTamperFails(t *testing.T) {
	key := bytes.Repeat([]byte{0x09}, 32)
	iv := bytes.Repeat([]byte{0x0A}, 12)
	plaintext := []byte("auth tamper test")

	encrypted, err := EncodeSecuredMessage(algo.AEADAES256GCM, key, iv, 0, 0x1234, plaintext, false, 0)
	require.NoError(t, err)

	// Tamper with data.
	encrypted[7] ^= 0xFF

	_, _, err = DecodeSecuredMessage(algo.AEADAES256GCM, key, iv, 0, false, encrypted, 0)
	require.Error(t, err)
}

func TestDeriveUpdatedDataSecret(t *testing.T) {
	secret := bytes.Repeat([]byte{0xAA}, 32)

	newSecret, err := DeriveUpdatedDataSecret(newSHA256(), algo.Version12, secret)
	require.NoError(t, err)
	require.Len(t, newSecret, 32)
	assert.NotEqual(t, secret, newSecret)

	// Deterministic
	newSecret2, err := DeriveUpdatedDataSecret(newSHA256(), algo.Version12, secret)
	require.NoError(t, err)
	assert.Equal(t, newSecret, newSecret2)

	// Different version gives different result
	newSecret13, err := DeriveUpdatedDataSecret(newSHA256(), algo.Version13, secret)
	require.NoError(t, err)
	assert.NotEqual(t, newSecret, newSecret13)
}

func TestDeriveKeyAndIVFromSecret(t *testing.T) {
	secret := bytes.Repeat([]byte{0xBB}, 32)

	key, iv, err := DeriveKeyAndIVFromSecret(newSHA256(), algo.Version12, algo.AEADAES256GCM, secret)
	require.NoError(t, err)
	require.Len(t, key, 32)
	require.Len(t, iv, 12)

	// AES-128: 16-byte key
	key128, iv128, err := DeriveKeyAndIVFromSecret(newSHA256(), algo.Version12, algo.AEADAES128GCM, secret)
	require.NoError(t, err)
	require.Len(t, key128, 16)
	require.Len(t, iv128, 12)

	// ChaCha20: 32-byte key
	keyCC, ivCC, err := DeriveKeyAndIVFromSecret(newSHA256(), algo.Version12, algo.AEADChaCha20Poly1305, secret)
	require.NoError(t, err)
	require.Len(t, keyCC, 32)
	require.Len(t, ivCC, 12)
}

func TestUpdateRequestKeys(t *testing.T) {
	ctx := context.Background()

	sharedSecret := bytes.Repeat([]byte{0xAA}, 32)
	hs, err := DeriveHandshakeSecret(ctx, newSHA256(), algo.Version12, sharedSecret)
	require.NoError(t, err)

	ms, err := DeriveMasterSecret(ctx, newSHA256(), algo.Version12, hs)
	require.NoError(t, err)

	th2 := bytes.Repeat([]byte{0xFF}, 32)
	dataKeys, err := DeriveDataKeys(ctx, newSHA256(), algo.Version12, algo.AEADAES256GCM, ms, th2)
	require.NoError(t, err)

	s := NewSession(1, algo.Version12, algo.HashSHA256, algo.AEADAES256GCM, true)
	s.DataKeys = dataKeys
	s.ReqSeqNum = 42

	origReqKey := make([]byte, len(s.DataKeys.RequestKey))
	copy(origReqKey, s.DataKeys.RequestKey)

	err = s.UpdateRequestKeys(newSHA256())
	require.NoError(t, err)
	assert.Equal(t, uint64(0), s.ReqSeqNum, "request sequence number should reset to 0")
	assert.NotEqual(t, origReqKey, s.DataKeys.RequestKey, "request key should change")
}

func TestUpdateResponseKeys(t *testing.T) {
	ctx := context.Background()

	sharedSecret := bytes.Repeat([]byte{0xBB}, 32)
	hs, err := DeriveHandshakeSecret(ctx, newSHA256(), algo.Version12, sharedSecret)
	require.NoError(t, err)

	ms, err := DeriveMasterSecret(ctx, newSHA256(), algo.Version12, hs)
	require.NoError(t, err)

	th2 := bytes.Repeat([]byte{0xEE}, 32)
	dataKeys, err := DeriveDataKeys(ctx, newSHA256(), algo.Version12, algo.AEADAES256GCM, ms, th2)
	require.NoError(t, err)

	s := NewSession(2, algo.Version12, algo.HashSHA256, algo.AEADAES256GCM, true)
	s.DataKeys = dataKeys
	s.RspSeqNum = 99

	origRspKey := make([]byte, len(s.DataKeys.ResponseKey))
	copy(origRspKey, s.DataKeys.ResponseKey)

	err = s.UpdateResponseKeys(newSHA256())
	require.NoError(t, err)
	assert.Equal(t, uint64(0), s.RspSeqNum, "response sequence number should reset to 0")
	assert.NotEqual(t, origRspKey, s.DataKeys.ResponseKey, "response key should change")
}

func TestEncodeDecodeWithSeqNumSize2(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	iv := bytes.Repeat([]byte{0x22}, 12)
	plaintext := []byte("MCTP seqnum size 2")
	sessionID := uint32(0xAAAA)

	encrypted, err := EncodeSecuredMessage(algo.AEADAES256GCM, key, iv, 0x1234, sessionID, plaintext, true, 2)
	require.NoError(t, err)

	gotSID, decrypted, err := DecodeSecuredMessage(algo.AEADAES256GCM, key, iv, 0x1234, true, encrypted, 2)
	require.NoError(t, err)
	assert.Equal(t, sessionID, gotSID)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncodeDecodeWithSeqNumSize8(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, 32)
	iv := bytes.Repeat([]byte{0x44}, 12)
	plaintext := []byte("TCP seqnum size 8")
	sessionID := uint32(0xBBBB)

	encrypted, err := EncodeSecuredMessage(algo.AEADAES256GCM, key, iv, 42, sessionID, plaintext, true, 8)
	require.NoError(t, err)

	gotSID, decrypted, err := DecodeSecuredMessage(algo.AEADAES256GCM, key, iv, 42, true, encrypted, 8)
	require.NoError(t, err)
	assert.Equal(t, sessionID, gotSID)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncodeDecodeAuthOnlySeqNumSize2(t *testing.T) {
	key := bytes.Repeat([]byte{0x55}, 32)
	iv := bytes.Repeat([]byte{0x66}, 12)
	plaintext := []byte("auth-only MCTP")
	sessionID := uint32(0xCCCC)

	encrypted, err := EncodeSecuredMessage(algo.AEADAES256GCM, key, iv, 5, sessionID, plaintext, false, 2)
	require.NoError(t, err)

	gotSID, decrypted, err := DecodeSecuredMessage(algo.AEADAES256GCM, key, iv, 5, false, encrypted, 2)
	require.NoError(t, err)
	assert.Equal(t, sessionID, gotSID)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncodeDecodeAuthOnlySeqNumSize8(t *testing.T) {
	key := bytes.Repeat([]byte{0x77}, 32)
	iv := bytes.Repeat([]byte{0x88}, 12)
	plaintext := []byte("auth-only TCP")
	sessionID := uint32(0xDDDD)

	encrypted, err := EncodeSecuredMessage(algo.AEADAES256GCM, key, iv, 100, sessionID, plaintext, false, 8)
	require.NoError(t, err)

	gotSID, decrypted, err := DecodeSecuredMessage(algo.AEADAES256GCM, key, iv, 100, false, encrypted, 8)
	require.NoError(t, err)
	assert.Equal(t, sessionID, gotSID)
	assert.Equal(t, plaintext, decrypted)
}

func TestDecodeSecuredMessageTooShortSeqNumSize2(t *testing.T) {
	// headerLen = 4 + 2 + 2 = 8, message shorter than that
	_, _, err := DecodeSecuredMessage(algo.AEADAES256GCM, nil, nil, 0, true, make([]byte, 7), 2)
	assert.Equal(t, ErrDecryptFailed, err)
}

func TestDecodeSecuredMessageTooShortSeqNumSize8(t *testing.T) {
	// headerLen = 4 + 8 + 2 = 14, message shorter than that
	_, _, err := DecodeSecuredMessage(algo.AEADAES256GCM, nil, nil, 0, true, make([]byte, 13), 8)
	assert.Equal(t, ErrDecryptFailed, err)
}

func TestNewSessionFields(t *testing.T) {
	s := NewSession(42, algo.Version13, algo.HashSHA384, algo.AEADChaCha20Poly1305, false)
	assert.Equal(t, SessionID(42), s.ID)
	assert.Equal(t, StateHandshake, s.State)
	assert.Equal(t, algo.Version13, s.Version)
	assert.Equal(t, algo.HashSHA384, s.HashAlgo)
	assert.Equal(t, algo.AEADChaCha20Poly1305, s.AEAD)
	assert.False(t, s.EncryptionRequired)
}

func TestSessionStateTransitions(t *testing.T) {
	s := NewSession(1, algo.Version12, algo.HashSHA256, algo.AEADAES256GCM, true)
	assert.Equal(t, StateHandshake, s.State)

	s.State = StateEstablished
	assert.Equal(t, "established", s.State.String())

	s.State = StateEnded
	assert.Equal(t, "ended", s.State.String())

	s.State = StateNone
	assert.Equal(t, "none", s.State.String())
}

func TestEncodeDecodeChaChaSeqNumSize8(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)
	iv := bytes.Repeat([]byte{0xCD}, 12)
	plaintext := []byte("chacha with seqnum 8")
	sessionID := uint32(0xEEEE)

	encrypted, err := EncodeSecuredMessage(algo.AEADChaCha20Poly1305, key, iv, 7, sessionID, plaintext, true, 8)
	require.NoError(t, err)

	gotSID, decrypted, err := DecodeSecuredMessage(algo.AEADChaCha20Poly1305, key, iv, 7, true, encrypted, 8)
	require.NoError(t, err)
	assert.Equal(t, sessionID, gotSID)
	assert.Equal(t, plaintext, decrypted)
}

func TestDecodeAuthOnlyUnsupportedAEAD(t *testing.T) {
	msg := make([]byte, 20)
	msg[4] = 10
	_, _, err := DecodeSecuredMessage(algo.AEADSM4GCM, bytes.Repeat([]byte{0x01}, 16), make([]byte, 12), 0, false, msg, 0)
	require.Error(t, err)
}

func TestEncodeAuthOnlySM4Fails(t *testing.T) {
	_, err := EncodeSecuredMessage(algo.AEADSM4GCM, bytes.Repeat([]byte{0x01}, 16), make([]byte, 12), 0, 0, nil, false, 0)
	require.Error(t, err)
}

func TestDeriveKeyAndIVFromSecretDeterministic(t *testing.T) {
	secret := bytes.Repeat([]byte{0xCC}, 32)

	key1, iv1, err := DeriveKeyAndIVFromSecret(newSHA256(), algo.Version12, algo.AEADAES256GCM, secret)
	require.NoError(t, err)

	key2, iv2, err := DeriveKeyAndIVFromSecret(newSHA256(), algo.Version12, algo.AEADAES256GCM, secret)
	require.NoError(t, err)

	assert.Equal(t, key1, key2)
	assert.Equal(t, iv1, iv2)

	// Different version gives different result
	key13, _, err := DeriveKeyAndIVFromSecret(newSHA256(), algo.Version13, algo.AEADAES256GCM, secret)
	require.NoError(t, err)
	assert.NotEqual(t, key1, key13)
}

func TestUpdateRequestKeysErrorPaths(t *testing.T) {
	ctx := context.Background()

	sharedSecret := bytes.Repeat([]byte{0xAA}, 32)
	hs, err := DeriveHandshakeSecret(ctx, newSHA256(), algo.Version12, sharedSecret)
	require.NoError(t, err)
	ms, err := DeriveMasterSecret(ctx, newSHA256(), algo.Version12, hs)
	require.NoError(t, err)
	th2 := bytes.Repeat([]byte{0xFF}, 32)
	dataKeys, err := DeriveDataKeys(ctx, newSHA256(), algo.Version12, algo.AEADAES256GCM, ms, th2)
	require.NoError(t, err)

	// Error in DeriveUpdatedDataSecret:
	// DeriveUpdatedDataSecret calls newHash().Size() (call 1) to get hashSize,
	// then HKDFExpand internally calls newHash().Size() (call 2).
	// With normalCalls=1: call 1 returns big (512), call 2 returns small (1).
	// HKDFExpand sees length=512 > 255*1=255, returns error.
	s1 := NewSession(1, algo.Version12, algo.HashSHA256, algo.AEADAES256GCM, true)
	s1.DataKeys = &DataKeys{
		RequestSecret:  dataKeys.RequestSecret,
		ResponseSecret: dataKeys.ResponseSecret,
		RequestKey:     dataKeys.RequestKey,
		ResponseKey:    dataKeys.ResponseKey,
		RequestIV:      dataKeys.RequestIV,
		ResponseIV:     dataKeys.ResponseIV,
	}
	h1 := newFailAfterNHash(512, 1, 1)
	err = s1.UpdateRequestKeys(h1)
	require.Error(t, err, "expected error from DeriveUpdatedDataSecret")

	// Verify that successful key update produces different keys
	s2 := NewSession(2, algo.Version12, algo.HashSHA256, algo.AEADAES256GCM, true)
	s2.DataKeys = &DataKeys{
		RequestSecret:  make([]byte, len(dataKeys.RequestSecret)),
		ResponseSecret: make([]byte, len(dataKeys.ResponseSecret)),
		RequestKey:     make([]byte, len(dataKeys.RequestKey)),
		ResponseKey:    make([]byte, len(dataKeys.ResponseKey)),
		RequestIV:      make([]byte, len(dataKeys.RequestIV)),
		ResponseIV:     make([]byte, len(dataKeys.ResponseIV)),
	}
	copy(s2.DataKeys.RequestSecret, dataKeys.RequestSecret)
	copy(s2.DataKeys.ResponseSecret, dataKeys.ResponseSecret)
	copy(s2.DataKeys.RequestKey, dataKeys.RequestKey)
	copy(s2.DataKeys.ResponseKey, dataKeys.ResponseKey)
	copy(s2.DataKeys.RequestIV, dataKeys.RequestIV)
	copy(s2.DataKeys.ResponseIV, dataKeys.ResponseIV)

	origSecret := make([]byte, len(s2.DataKeys.RequestSecret))
	copy(origSecret, s2.DataKeys.RequestSecret)
	origIV := make([]byte, len(s2.DataKeys.RequestIV))
	copy(origIV, s2.DataKeys.RequestIV)

	err = s2.UpdateRequestKeys(newSHA256())
	require.NoError(t, err)
	assert.NotEqual(t, origSecret, s2.DataKeys.RequestSecret, "secret should change")
	assert.NotEqual(t, origIV, s2.DataKeys.RequestIV, "IV should change")
}

func TestUpdateResponseKeysErrorPaths(t *testing.T) {
	ctx := context.Background()

	sharedSecret := bytes.Repeat([]byte{0xBB}, 32)
	hs, err := DeriveHandshakeSecret(ctx, newSHA256(), algo.Version12, sharedSecret)
	require.NoError(t, err)
	ms, err := DeriveMasterSecret(ctx, newSHA256(), algo.Version12, hs)
	require.NoError(t, err)
	th2 := bytes.Repeat([]byte{0xEE}, 32)
	dataKeys, err := DeriveDataKeys(ctx, newSHA256(), algo.Version12, algo.AEADAES256GCM, ms, th2)
	require.NoError(t, err)

	// Error in DeriveUpdatedDataSecret (same logic as UpdateRequestKeys)
	s1 := NewSession(1, algo.Version12, algo.HashSHA256, algo.AEADAES256GCM, true)
	s1.DataKeys = &DataKeys{
		RequestSecret:  dataKeys.RequestSecret,
		ResponseSecret: dataKeys.ResponseSecret,
		RequestKey:     dataKeys.RequestKey,
		ResponseKey:    dataKeys.ResponseKey,
		RequestIV:      dataKeys.RequestIV,
		ResponseIV:     dataKeys.ResponseIV,
	}
	h1 := newFailAfterNHash(512, 1, 1)
	err = s1.UpdateResponseKeys(h1)
	require.Error(t, err, "expected error from DeriveUpdatedDataSecret")

	// Verify successful response key update
	s2 := NewSession(2, algo.Version12, algo.HashSHA256, algo.AEADAES256GCM, true)
	s2.DataKeys = &DataKeys{
		RequestSecret:  make([]byte, len(dataKeys.RequestSecret)),
		ResponseSecret: make([]byte, len(dataKeys.ResponseSecret)),
		RequestKey:     make([]byte, len(dataKeys.RequestKey)),
		ResponseKey:    make([]byte, len(dataKeys.ResponseKey)),
		RequestIV:      make([]byte, len(dataKeys.RequestIV)),
		ResponseIV:     make([]byte, len(dataKeys.ResponseIV)),
	}
	copy(s2.DataKeys.RequestSecret, dataKeys.RequestSecret)
	copy(s2.DataKeys.ResponseSecret, dataKeys.ResponseSecret)
	copy(s2.DataKeys.RequestKey, dataKeys.RequestKey)
	copy(s2.DataKeys.ResponseKey, dataKeys.ResponseKey)
	copy(s2.DataKeys.RequestIV, dataKeys.RequestIV)
	copy(s2.DataKeys.ResponseIV, dataKeys.ResponseIV)

	origRspSecret := make([]byte, len(s2.DataKeys.ResponseSecret))
	copy(origRspSecret, s2.DataKeys.ResponseSecret)
	origRspIV := make([]byte, len(s2.DataKeys.ResponseIV))
	copy(origRspIV, s2.DataKeys.ResponseIV)

	err = s2.UpdateResponseKeys(newSHA256())
	require.NoError(t, err)
	assert.NotEqual(t, origRspSecret, s2.DataKeys.ResponseSecret, "response secret should change")
	assert.NotEqual(t, origRspIV, s2.DataKeys.ResponseIV, "response IV should change")
}
