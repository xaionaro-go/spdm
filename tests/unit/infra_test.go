package unit

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"math/big"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/spdm/pkg/crypto/stdlib"
	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/caps"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/session"
	"github.com/xaionaro-go/spdm/pkg/spdm"
	"github.com/xaionaro-go/spdm/pkg/transport/mctp"
	"github.com/xaionaro-go/spdm/pkg/transport/pcidoe"
	"github.com/xaionaro-go/spdm/pkg/transport/storage"
	"github.com/xaionaro-go/spdm/pkg/transport/tcp"
)

// ---------------------------------------------------------------------------
// Transport tests
// ---------------------------------------------------------------------------

func TestMCTPTransportRoundTrip(t *testing.T) {
	payloads := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"small", []byte{0x10, 0x11, 0x05, 0x00}},
		{"large", bytes.Repeat([]byte{0xAB}, 4096)},
	}

	for _, tc := range payloads {
		t.Run(tc.name, func(t *testing.T) {
			c1, c2 := net.Pipe()
			defer c1.Close()
			defer c2.Close()

			sender := mctp.New(c1)
			receiver := mctp.New(c2)

			errCh := make(chan error, 1)
			go func() {
				errCh <- sender.SendMessage(context.Background(), nil, tc.data)
			}()

			_, got, err := receiver.ReceiveMessage(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tc.data, got)

			require.NoError(t, <-errCh)
		})
	}
}

func TestMCTPHeaderSize(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	tr := mctp.New(c1)
	assert.Equal(t, 1, tr.HeaderSize())
}

func TestPCIDOETransportRoundTrip(t *testing.T) {
	payloads := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"small", []byte{0x10, 0x11, 0x05, 0x00}},
		{"large", bytes.Repeat([]byte{0xCD}, 4096)},
	}

	for _, tc := range payloads {
		t.Run(tc.name, func(t *testing.T) {
			c1, c2 := net.Pipe()
			defer c1.Close()
			defer c2.Close()

			sender := pcidoe.New(c1)
			receiver := pcidoe.New(c2)

			errCh := make(chan error, 1)
			go func() {
				errCh <- sender.SendMessage(context.Background(), nil, tc.data)
			}()

			_, got, err := receiver.ReceiveMessage(context.Background())
			require.NoError(t, err)
			// PCIe DOE pads to DWORD boundary; received payload may include
			// trailing zero padding bytes beyond the original payload.
			require.GreaterOrEqual(t, len(got), len(tc.data))
			assert.Equal(t, tc.data, got[:len(tc.data)])

			require.NoError(t, <-errCh)
		})
	}
}

func TestPCIDOEHeaderSize(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	tr := pcidoe.New(c1)
	assert.Equal(t, 8, tr.HeaderSize())
}

func TestPCIDOEHeaderFields(t *testing.T) {
	// Verify the DOE header written by SendMessage contains the correct
	// VendorID and DataObjectType.
	var buf bytes.Buffer
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	sender := pcidoe.New(c1)
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	errCh := make(chan error, 1)
	go func() {
		errCh <- sender.SendMessage(context.Background(), nil, payload)
	}()

	// Read the raw frame from the other end of the pipe.
	raw := make([]byte, 256)
	n, err := c2.Read(raw)
	require.NoError(t, err)
	raw = raw[:n]

	// Parse header fields.
	require.True(t, len(raw) >= 8, "frame must be at least 8 bytes")
	vendorID := binary.LittleEndian.Uint16(raw[0:2])
	dataObjType := raw[2]
	assert.Equal(t, uint16(pcidoe.DOEVendorIDPCISIG), vendorID)
	assert.Equal(t, uint8(pcidoe.DOEDataObjectTypeSPDM), dataObjType)

	_ = buf // keep import
	require.NoError(t, <-errCh)
}

func TestStorageTransportRoundTrip(t *testing.T) {
	payloads := []struct {
		name string
		data []byte
	}{
		// Empty payload is skipped: storage does two Write calls and
		// net.Pipe blocks on zero-length Write.
		{"small", []byte{0x01, 0x02, 0x03}},
		{"medium", []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80}},
		{"large", bytes.Repeat([]byte{0xEF}, 4096)},
	}

	for _, tc := range payloads {
		t.Run(tc.name, func(t *testing.T) {
			c1, c2 := net.Pipe()
			defer c1.Close()
			defer c2.Close()

			sender := storage.New(c1)
			receiver := storage.New(c2)

			errCh := make(chan error, 1)
			go func() {
				errCh <- sender.SendMessage(context.Background(), nil, tc.data)
			}()

			_, got, err := receiver.ReceiveMessage(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tc.data, got)

			require.NoError(t, <-errCh)
		})
	}
}

func TestStorageHeaderSize(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	tr := storage.New(c1)
	assert.Equal(t, 2, tr.HeaderSize())
}

func TestTCPTransportRoundTrip(t *testing.T) {
	payloads := []struct {
		name string
		data []byte
	}{
		// Empty payload is skipped: tcp does two Write calls and
		// net.Pipe blocks on zero-length Write.
		{"small", []byte{0xAA, 0xBB}},
		{"medium", bytes.Repeat([]byte{0x42}, 256)},
		{"large", bytes.Repeat([]byte{0x42}, 8192)},
	}

	for _, tc := range payloads {
		t.Run(tc.name, func(t *testing.T) {
			c1, c2 := net.Pipe()
			defer c1.Close()
			defer c2.Close()

			sender := tcp.New(c1)
			receiver := tcp.New(c2)

			errCh := make(chan error, 1)
			go func() {
				errCh <- sender.SendMessage(context.Background(), nil, tc.data)
			}()

			_, got, err := receiver.ReceiveMessage(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tc.data, got)

			require.NoError(t, <-errCh)
		})
	}
}

func TestTCPHeaderSize(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	tr := tcp.New(c1)
	assert.Equal(t, 4, tr.HeaderSize())
}

// ---------------------------------------------------------------------------
// Transport wire-format constants
// ---------------------------------------------------------------------------

func TestTransportConstants(t *testing.T) {
	// MCTP message types (untyped int constants).
	assert.Equal(t, 0x05, mctp.MCTPMessageTypeSPDM)
	assert.Equal(t, 0x06, mctp.MCTPMessageTypeSecuredSPDM)

	// PCIe DOE constants (untyped int constants).
	assert.Equal(t, 0x0001, pcidoe.DOEVendorIDPCISIG)
	assert.Equal(t, 0x01, pcidoe.DOEDataObjectTypeSPDM)
	assert.Equal(t, 0x02, pcidoe.DOEDataObjectTypeSecured)
}

// ---------------------------------------------------------------------------
// Session state tests
// ---------------------------------------------------------------------------

func TestNewSession(t *testing.T) {
	s := session.NewSession(42, algo.Version12, algo.HashSHA256, algo.AEADAES256GCM, true)

	assert.Equal(t, session.SessionID(42), s.ID)
	assert.Equal(t, session.StateHandshake, s.State)
	assert.Equal(t, algo.Version12, s.Version)
	assert.Equal(t, algo.AEADAES256GCM, s.AEAD)
	assert.True(t, s.EncryptionRequired)
}

func TestSessionStateString(t *testing.T) {
	tests := []struct {
		state session.State
		want  string
	}{
		{session.StateNone, "none"},
		{session.StateHandshake, "handshake"},
		{session.StateEstablished, "established"},
		{session.StateEnded, "ended"},
		{session.State(99), "unknown"},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, tc.state.String())
	}
}

func TestNextReqSeqNum(t *testing.T) {
	s := session.NewSession(1, algo.Version12, algo.HashSHA256, algo.AEADAES256GCM, true)

	seq0, err := s.NextReqSeqNum()
	require.NoError(t, err)
	assert.Equal(t, uint64(0), seq0)

	seq1, err := s.NextReqSeqNum()
	require.NoError(t, err)
	assert.Equal(t, uint64(1), seq1)

	seq2, err := s.NextReqSeqNum()
	require.NoError(t, err)
	assert.Equal(t, uint64(2), seq2)
}

func TestNextRspSeqNum(t *testing.T) {
	s := session.NewSession(1, algo.Version12, algo.HashSHA256, algo.AEADAES256GCM, true)

	seq0, err := s.NextRspSeqNum()
	require.NoError(t, err)
	assert.Equal(t, uint64(0), seq0)

	seq1, err := s.NextRspSeqNum()
	require.NoError(t, err)
	assert.Equal(t, uint64(1), seq1)
}

func TestSequenceOverflow(t *testing.T) {
	s := session.NewSession(1, algo.Version12, algo.HashSHA256, algo.AEADAES256GCM, true)
	s.ReqSeqNum = ^uint64(0)

	_, err := s.NextReqSeqNum()
	require.ErrorIs(t, err, session.ErrSequenceOverflow)
}

func TestRspSequenceOverflow(t *testing.T) {
	s := session.NewSession(1, algo.Version12, algo.HashSHA256, algo.AEADAES256GCM, true)
	s.RspSeqNum = ^uint64(0)

	_, err := s.NextRspSeqNum()
	require.ErrorIs(t, err, session.ErrSequenceOverflow)
}

// ---------------------------------------------------------------------------
// Key derivation (pkg/session/derive.go)
// ---------------------------------------------------------------------------

func TestHKDFExpand(t *testing.T) {
	prk := make([]byte, 32)
	for i := range prk {
		prk[i] = byte(i)
	}
	info := []byte("test info")

	out, err := session.HKDFExpand(sha256.New, prk, info, 42)
	require.NoError(t, err)
	assert.Equal(t, 42, len(out))

	// Same inputs produce same output (deterministic).
	out2, err := session.HKDFExpand(sha256.New, prk, info, 42)
	require.NoError(t, err)
	assert.Equal(t, out, out2)
}

func TestHKDFExpandDifferentLengths(t *testing.T) {
	prk := bytes.Repeat([]byte{0x07}, 32)

	out16, err := session.HKDFExpand(sha256.New, prk, nil, 16)
	require.NoError(t, err)
	assert.Equal(t, 16, len(out16))

	out64, err := session.HKDFExpand(sha256.New, prk, nil, 64)
	require.NoError(t, err)
	assert.Equal(t, 64, len(out64))

	// The first 16 bytes should NOT match when lengths differ due to
	// how HKDF counter works; but the first 32 bytes of 64 should
	// equal the 32-length output.
	out32, err := session.HKDFExpand(sha256.New, prk, nil, 32)
	require.NoError(t, err)
	assert.Equal(t, out32, out64[:32])
}

func TestHKDFExtract(t *testing.T) {
	salt := []byte("salt value")
	ikm := []byte("input keying material")

	out := session.HKDFExtract(sha256.New, salt, ikm)
	require.NotNil(t, out)
	assert.Equal(t, 32, len(out)) // SHA-256 output

	// Deterministic
	out2 := session.HKDFExtract(sha256.New, salt, ikm)
	assert.Equal(t, out, out2)
}

func TestHKDFExtractZeroSalt(t *testing.T) {
	ikm := []byte("input keying material")

	out := session.HKDFExtract(sha256.New, nil, ikm)
	require.NotNil(t, out)
	assert.Equal(t, 32, len(out))

	// Passing explicit zero-length slice should behave the same as nil.
	out2 := session.HKDFExtract(sha256.New, []byte{}, ikm)
	assert.Equal(t, out, out2)
}

func TestBinConcat(t *testing.T) {
	// binConcat is unexported, but we can test it indirectly through
	// DeriveHandshakeKeys which uses it. Instead, we'll verify the
	// VersionLabel function and use the key derivation functions.
}

func TestVersionLabel(t *testing.T) {
	assert.Equal(t, "spdm1.2 ", session.VersionLabel(algo.Version12))
	assert.Equal(t, "spdm1.3 ", session.VersionLabel(algo.Version13))

	// Unknown version uses generic format.
	label := session.VersionLabel(algo.Version10)
	assert.Equal(t, "spdm1.0 ", label)
}

func TestDeriveHandshakeSecret(t *testing.T) {
	ctx := context.Background()
	sharedSecret := bytes.Repeat([]byte{0xAA}, 32)

	hs, err := session.DeriveHandshakeSecret(ctx, sha256.New, algo.Version12, sharedSecret)
	require.NoError(t, err)
	require.NotNil(t, hs)
	assert.Equal(t, 32, len(hs)) // SHA-256 hash size
}

func TestDeriveMasterSecret(t *testing.T) {
	ctx := context.Background()
	handshakeSecret := bytes.Repeat([]byte{0xBB}, 32)

	ms, err := session.DeriveMasterSecret(ctx, sha256.New, algo.Version12, handshakeSecret)
	require.NoError(t, err)
	require.NotNil(t, ms)
	assert.Equal(t, 32, len(ms))
}

func TestDeriveHandshakeKeys(t *testing.T) {
	ctx := context.Background()
	handshakeSecret := bytes.Repeat([]byte{0xCC}, 32)
	th1Hash := make([]byte, 32) // SHA-256 hash output
	copy(th1Hash, bytes.Repeat([]byte{0xDD}, 32))

	keys, err := session.DeriveHandshakeKeys(ctx, sha256.New, algo.Version12, algo.AEADAES256GCM, handshakeSecret, th1Hash)
	require.NoError(t, err)
	require.NotNil(t, keys)

	// AES-256-GCM: key=32, iv=12, finished=hash_size=32
	assert.Equal(t, 32, len(keys.RequestKey))
	assert.Equal(t, 32, len(keys.ResponseKey))
	assert.Equal(t, 12, len(keys.RequestIV))
	assert.Equal(t, 12, len(keys.ResponseIV))
	assert.Equal(t, 32, len(keys.RequestFinished))
	assert.Equal(t, 32, len(keys.ResponseFinished))
}

func TestDeriveHandshakeKeysAES128(t *testing.T) {
	ctx := context.Background()
	handshakeSecret := bytes.Repeat([]byte{0x11}, 32)
	th1Hash := bytes.Repeat([]byte{0x22}, 32)

	keys, err := session.DeriveHandshakeKeys(ctx, sha256.New, algo.Version12, algo.AEADAES128GCM, handshakeSecret, th1Hash)
	require.NoError(t, err)

	// AES-128-GCM: key=16
	assert.Equal(t, 16, len(keys.RequestKey))
	assert.Equal(t, 16, len(keys.ResponseKey))
	assert.Equal(t, 12, len(keys.RequestIV))
	assert.Equal(t, 12, len(keys.ResponseIV))
}

func TestDeriveDataKeys(t *testing.T) {
	ctx := context.Background()
	masterSecret := bytes.Repeat([]byte{0xEE}, 32)
	th2Hash := bytes.Repeat([]byte{0xFF}, 32)

	keys, err := session.DeriveDataKeys(ctx, sha256.New, algo.Version12, algo.AEADAES256GCM, masterSecret, th2Hash)
	require.NoError(t, err)
	require.NotNil(t, keys)

	assert.Equal(t, 32, len(keys.RequestKey))
	assert.Equal(t, 32, len(keys.ResponseKey))
	assert.Equal(t, 12, len(keys.RequestIV))
	assert.Equal(t, 12, len(keys.ResponseIV))
	assert.Equal(t, 32, len(keys.ExportMasterSecret))
}

func TestGenerateFinishedKey(t *testing.T) {
	ctx := context.Background()
	finishedKey := bytes.Repeat([]byte{0x44}, 32)
	thHash := bytes.Repeat([]byte{0x55}, 32)

	result := session.GenerateFinishedKey(ctx, sha256.New, finishedKey, thHash)
	require.NotNil(t, result)
	assert.Equal(t, 32, len(result)) // HMAC-SHA256 output

	// Deterministic
	result2 := session.GenerateFinishedKey(ctx, sha256.New, finishedKey, thHash)
	assert.Equal(t, result, result2)
}

// ---------------------------------------------------------------------------
// Encode/Decode secured messages (pkg/session/encode.go)
// ---------------------------------------------------------------------------

func TestEncodeDecodeSecuredMessageEncAuth(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32) // AES-256-GCM key
	iv := bytes.Repeat([]byte{0x02}, 12)
	plaintext := []byte("hello SPDM secured message")
	sessionID := uint32(0x12345678)

	encoded, err := session.EncodeSecuredMessage(
		algo.AEADAES256GCM, key, iv, 0, sessionID, plaintext, true, 0,
	)
	require.NoError(t, err)
	require.NotNil(t, encoded)

	gotSessionID, got, err := session.DecodeSecuredMessage(
		algo.AEADAES256GCM, key, iv, 0, true, encoded, 0,
	)
	require.NoError(t, err)
	assert.Equal(t, sessionID, gotSessionID)
	assert.Equal(t, plaintext, got)
}

func TestEncodeDecodeSecuredMessageAuthOnly(t *testing.T) {
	key := bytes.Repeat([]byte{0x03}, 32) // AES-256-GCM key
	iv := bytes.Repeat([]byte{0x04}, 12)
	plaintext := []byte("auth-only message")
	sessionID := uint32(0xAABBCCDD)

	encoded, err := session.EncodeSecuredMessage(
		algo.AEADAES256GCM, key, iv, 0, sessionID, plaintext, false, 0,
	)
	require.NoError(t, err)

	gotSessionID, got, err := session.DecodeSecuredMessage(
		algo.AEADAES256GCM, key, iv, 0, false, encoded, 0,
	)
	require.NoError(t, err)
	assert.Equal(t, sessionID, gotSessionID)
	assert.Equal(t, plaintext, got)
}

func TestEncodeDecodeSecuredMessageAES128(t *testing.T) {
	key := bytes.Repeat([]byte{0x05}, 16) // AES-128-GCM key
	iv := bytes.Repeat([]byte{0x06}, 12)
	plaintext := []byte("AES-128 test")
	sessionID := uint32(0x00000001)

	encoded, err := session.EncodeSecuredMessage(
		algo.AEADAES128GCM, key, iv, 0, sessionID, plaintext, true, 0,
	)
	require.NoError(t, err)

	gotSessionID, got, err := session.DecodeSecuredMessage(
		algo.AEADAES128GCM, key, iv, 0, true, encoded, 0,
	)
	require.NoError(t, err)
	assert.Equal(t, sessionID, gotSessionID)
	assert.Equal(t, plaintext, got)
}

func TestEncodeDecodeSecuredMessageChaCha20(t *testing.T) {
	key := bytes.Repeat([]byte{0x07}, 32) // ChaCha20-Poly1305 key
	iv := bytes.Repeat([]byte{0x08}, 12)
	plaintext := []byte("ChaCha20 test payload")
	sessionID := uint32(0xFEDCBA98)

	encoded, err := session.EncodeSecuredMessage(
		algo.AEADChaCha20Poly1305, key, iv, 0, sessionID, plaintext, true, 0,
	)
	require.NoError(t, err)

	gotSessionID, got, err := session.DecodeSecuredMessage(
		algo.AEADChaCha20Poly1305, key, iv, 0, true, encoded, 0,
	)
	require.NoError(t, err)
	assert.Equal(t, sessionID, gotSessionID)
	assert.Equal(t, plaintext, got)
}

func TestDecodeSecuredMessageTooShort(t *testing.T) {
	_, _, err := session.DecodeSecuredMessage(
		algo.AEADAES256GCM, nil, nil, 0, true, []byte{0x01, 0x02}, 0,
	)
	require.ErrorIs(t, err, session.ErrDecryptFailed)
}

func TestDecodeSecuredMessageCorrupted(t *testing.T) {
	key := bytes.Repeat([]byte{0x09}, 32)
	iv := bytes.Repeat([]byte{0x0A}, 12)
	plaintext := []byte("will be corrupted")
	sessionID := uint32(0x11111111)

	encoded, err := session.EncodeSecuredMessage(
		algo.AEADAES256GCM, key, iv, 0, sessionID, plaintext, true, 0,
	)
	require.NoError(t, err)

	// Corrupt a byte in the ciphertext portion (after the 6-byte header).
	if len(encoded) > 10 {
		encoded[10] ^= 0xFF
	}

	_, _, err = session.DecodeSecuredMessage(
		algo.AEADAES256GCM, key, iv, 0, true, encoded, 0,
	)
	require.ErrorIs(t, err, session.ErrDecryptFailed)
}

func TestBuildNonceXOR(t *testing.T) {
	// Verify that encoding with different sequence numbers produces different
	// ciphertexts (proving the nonce changes).
	key := bytes.Repeat([]byte{0x0B}, 32)
	iv := bytes.Repeat([]byte{0x0C}, 12)
	plaintext := []byte("nonce test")
	sessionID := uint32(1)

	// Use seqNumSize=8 so sequence numbers affect nonce/AAD
	enc0, err := session.EncodeSecuredMessage(
		algo.AEADAES256GCM, key, iv, 0, sessionID, plaintext, true, 8,
	)
	require.NoError(t, err)

	enc1, err := session.EncodeSecuredMessage(
		algo.AEADAES256GCM, key, iv, 1, sessionID, plaintext, true, 8,
	)
	require.NoError(t, err)

	// Different sequence numbers must produce different ciphertexts.
	assert.NotEqual(t, enc0, enc1)

	// Each should decrypt with its own sequence number.
	_, got0, err := session.DecodeSecuredMessage(
		algo.AEADAES256GCM, key, iv, 0, true, enc0, 8,
	)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got0)

	_, got1, err := session.DecodeSecuredMessage(
		algo.AEADAES256GCM, key, iv, 1, true, enc1, 8,
	)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got1)

	// Decoding with the wrong sequence number should fail.
	_, _, err = session.DecodeSecuredMessage(
		algo.AEADAES256GCM, key, iv, 1, true, enc0, 8,
	)
	require.ErrorIs(t, err, session.ErrDecryptFailed)
}

func TestSessionErrors(t *testing.T) {
	assert.NotNil(t, session.ErrDecryptFailed)
	assert.NotNil(t, session.ErrSequenceOverflow)
	assert.Contains(t, session.ErrDecryptFailed.Error(), "decryption")
	assert.Contains(t, session.ErrSequenceOverflow.Error(), "sequence")
	assert.Contains(t, session.ErrUnsupportedAEADSuite{}.Error(), "AEAD")
}

// ---------------------------------------------------------------------------
// Crypto tests (pkg/crypto/stdlib/)
// ---------------------------------------------------------------------------

func TestStdHashProviderAllAlgorithms(t *testing.T) {
	hp := &stdlib.StdHashProvider{}

	tests := []struct {
		algo algo.BaseHashAlgo
		size int
	}{
		{algo.HashSHA256, 32},
		{algo.HashSHA384, 48},
		{algo.HashSHA512, 64},
		{algo.HashSHA3_256, 32},
		{algo.HashSHA3_384, 48},
		{algo.HashSHA3_512, 64},
	}

	for _, tc := range tests {
		t.Run(tc.algo.String(), func(t *testing.T) {
			h, err := hp.NewHash(tc.algo)
			require.NoError(t, err)
			require.NotNil(t, h)

			h.Write([]byte("test data"))
			digest := h.Sum(nil)
			assert.Equal(t, tc.size, len(digest))
		})
	}
}

func TestStdHashProviderSM3(t *testing.T) {
	hp := &stdlib.StdHashProvider{}
	h, err := hp.NewHash(algo.HashSM3_256)
	require.NoError(t, err)
	h.Write([]byte("test data"))
	digest := h.Sum(nil)
	assert.Len(t, digest, 32)
}

func TestStdHashProviderUnsupported(t *testing.T) {
	hp := &stdlib.StdHashProvider{}
	_, err := hp.NewHash(algo.BaseHashAlgo(0x80000000))
	require.Error(t, err)
}

func TestStdAEADSealOpen(t *testing.T) {
	a := &stdlib.StdAEAD{}

	tests := []struct {
		name  string
		suite algo.AEADCipherSuite
		key   []byte
	}{
		{"AES-128-GCM", algo.AEADAES128GCM, bytes.Repeat([]byte{0x01}, 16)},
		{"AES-256-GCM", algo.AEADAES256GCM, bytes.Repeat([]byte{0x02}, 32)},
		{"ChaCha20-Poly1305", algo.AEADChaCha20Poly1305, bytes.Repeat([]byte{0x03}, 32)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nonce := bytes.Repeat([]byte{0x04}, 12)
			plaintext := []byte("AEAD round-trip test")
			aad := []byte("additional data")

			ciphertext, err := a.Seal(tc.suite, tc.key, nonce, plaintext, aad)
			require.NoError(t, err)
			require.NotNil(t, ciphertext)

			got, err := a.Open(tc.suite, tc.key, nonce, ciphertext, aad)
			require.NoError(t, err)
			assert.Equal(t, plaintext, got)
		})
	}
}

func TestStdAEADOpenCorrupted(t *testing.T) {
	a := &stdlib.StdAEAD{}
	key := bytes.Repeat([]byte{0x05}, 32)
	nonce := bytes.Repeat([]byte{0x06}, 12)

	ciphertext, err := a.Seal(algo.AEADAES256GCM, key, nonce, []byte("data"), nil)
	require.NoError(t, err)

	// Corrupt ciphertext
	ciphertext[0] ^= 0xFF

	_, err = a.Open(algo.AEADAES256GCM, key, nonce, ciphertext, nil)
	require.Error(t, err)
}

func TestStdAEADUnsupportedSuite(t *testing.T) {
	a := &stdlib.StdAEAD{}
	nonce := bytes.Repeat([]byte{0x00}, 12)

	_, err := a.Seal(algo.AEADSM4GCM, nil, nonce, []byte("test"), nil)
	require.Error(t, err)
}

func TestStdKeyAgreementGenerateDHE(t *testing.T) {
	ka := &stdlib.StdKeyAgreement{}

	groups := []algo.DHENamedGroup{
		algo.DHESECP256R1,
		algo.DHESECP384R1,
		algo.DHESECP521R1,
	}

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			priv, pub, err := ka.GenerateDHE(g)
			require.NoError(t, err)
			require.NotNil(t, priv)
			require.NotEmpty(t, pub)
		})
	}
}

func TestStdKeyAgreementComputeDHE(t *testing.T) {
	ka := &stdlib.StdKeyAgreement{}

	groups := []algo.DHENamedGroup{
		algo.DHESECP256R1,
		algo.DHESECP384R1,
		algo.DHESECP521R1,
	}

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			// Generate two key pairs.
			priv1, pub1, err := ka.GenerateDHE(g)
			require.NoError(t, err)
			priv2, pub2, err := ka.GenerateDHE(g)
			require.NoError(t, err)

			// Compute shared secret from both sides.
			secret1, err := ka.ComputeDHE(g, priv1, pub2)
			require.NoError(t, err)
			secret2, err := ka.ComputeDHE(g, priv2, pub1)
			require.NoError(t, err)

			assert.Equal(t, secret1, secret2, "shared secrets must match")
			assert.NotEmpty(t, secret1)
		})
	}
}

func TestStdKeyAgreementFFDHESupported(t *testing.T) {
	ka := &stdlib.StdKeyAgreement{}
	priv, pub, err := ka.GenerateDHE(algo.DHEFFDHE2048)
	require.NoError(t, err)
	assert.NotNil(t, priv)
	assert.Len(t, pub, algo.DHEFFDHE2048.DHEPublicKeySize())
}

func TestStdVerifierECDSA(t *testing.T) {
	v := &stdlib.StdVerifier{}

	// Generate a P-256 key pair.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create a digest.
	digest := sha256.Sum256([]byte("test message for ECDSA"))

	// Sign: produce SPDM-format raw r||s signature.
	r, s, err := ecdsa.Sign(rand.Reader, privKey, digest[:])
	require.NoError(t, err)

	componentLen := algo.AsymECDSAP256.SignatureSize() / 2
	sig := make([]byte, algo.AsymECDSAP256.SignatureSize())
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[componentLen-len(rBytes):componentLen], rBytes)
	copy(sig[2*componentLen-len(sBytes):], sBytes)

	err = v.Verify(algo.AsymECDSAP256, &privKey.PublicKey, digest[:], sig)
	require.NoError(t, err)
}

func TestStdVerifierWrongKeyType(t *testing.T) {
	v := &stdlib.StdVerifier{}
	digest := sha256.Sum256([]byte("test"))

	// Pass a string instead of a proper public key.
	err := v.Verify(algo.AsymECDSAP256, "not-a-key", digest[:], make([]byte, 64))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected")
}

func TestStdVerifierWrongSigLength(t *testing.T) {
	v := &stdlib.StdVerifier{}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("test"))

	// Wrong signature length (should be 64 for P-256).
	err = v.Verify(algo.AsymECDSAP256, &privKey.PublicKey, digest[:], make([]byte, 32))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature length")
}

func TestNewSuite(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	suite := stdlib.NewSuite(privKey, pool)
	require.NotNil(t, suite)

	assert.NotNil(t, suite.Hash)
	assert.NotNil(t, suite.Signer)
	assert.NotNil(t, suite.Verifier)
	assert.NotNil(t, suite.KeyAgreement)
	assert.NotNil(t, suite.AEAD)
	assert.NotNil(t, suite.Random)
}

// ---------------------------------------------------------------------------
// pkg/spdm/ high-level API types
// ---------------------------------------------------------------------------

func TestNewRequester(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	suite := stdlib.NewSuite(privKey, nil)

	cfg := spdm.RequesterConfig{
		Versions:         []algo.Version{algo.Version12},
		Transport:        tcp.New(c1),
		Crypto:           *suite,
		Caps:             caps.RequesterCaps(0),
		BaseAsymAlgo:     algo.AsymECDSAP256,
		BaseHashAlgo:     algo.HashSHA256,
		DHEGroups:        algo.DHESECP256R1,
		AEADSuites:       algo.AEADAES256GCM,
		DataTransferSize: 1024,
		MaxSPDMmsgSize:   1024,
	}
	req := spdm.NewRequester(cfg)
	require.NotNil(t, req)
}

func TestNewResponder(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	suite := stdlib.NewSuite(privKey, nil)

	cfg := spdm.ResponderConfig{
		Versions:         []algo.Version{algo.Version12},
		Transport:        tcp.New(c1),
		Crypto:           *suite,
		Caps:             caps.ResponderCaps(0),
		BaseAsymAlgo:     algo.AsymECDSAP256,
		BaseHashAlgo:     algo.HashSHA256,
		DHEGroups:        algo.DHESECP256R1,
		AEADSuites:       algo.AEADAES256GCM,
		DataTransferSize: 1024,
		MaxSPDMmsgSize:   1024,
	}

	// Without CertProvider/MeasProvider.
	rsp := spdm.NewResponder(cfg)
	require.NotNil(t, rsp)
}

func TestNewResponderWithProviders(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	suite := stdlib.NewSuite(privKey, nil)

	cfg := spdm.ResponderConfig{
		Versions:         []algo.Version{algo.Version12},
		Transport:        tcp.New(c1),
		Crypto:           *suite,
		Caps:             caps.ResponderCaps(0),
		BaseAsymAlgo:     algo.AsymECDSAP256,
		BaseHashAlgo:     algo.HashSHA256,
		DataTransferSize: 1024,
		MaxSPDMmsgSize:   1024,
		CertProvider:     &mockCertProvider{},
		MeasProvider:     &mockMeasProvider{},
	}

	rsp := spdm.NewResponder(cfg)
	require.NotNil(t, rsp)
}

func TestConnectionInfoType(t *testing.T) {
	ci := spdm.ConnectionInfo{
		Version:   algo.Version12,
		HashAlgo:  algo.HashSHA256,
		AsymAlgo:  algo.AsymECDSAP256,
		DHEGroup:  algo.DHESECP256R1,
		AEADSuite: algo.AEADAES256GCM,
	}
	assert.Equal(t, algo.Version12, ci.Version)
	assert.Equal(t, algo.HashSHA256, ci.HashAlgo)
	assert.Equal(t, algo.AsymECDSAP256, ci.AsymAlgo)
}

func TestDigestsType(t *testing.T) {
	d := spdm.Digests{
		SlotMask: 0x01,
		Digests:  [][]byte{{0x01, 0x02}, {0x03, 0x04}},
	}
	assert.Equal(t, uint8(0x01), d.SlotMask)
	assert.Len(t, d.Digests, 2)
}

func TestCertificateChainType(t *testing.T) {
	cc := spdm.CertificateChain{
		SlotID: 0,
		Chain:  []byte{0xDE, 0xAD},
	}
	assert.Equal(t, uint8(0), cc.SlotID)
	assert.Equal(t, []byte{0xDE, 0xAD}, cc.Chain)
}

func TestChallengeResultType(t *testing.T) {
	cr := spdm.ChallengeResult{
		SlotID:                 1,
		CertChainHash:          []byte{0x01},
		MeasurementSummaryHash: []byte{0x02},
	}
	assert.Equal(t, uint8(1), cr.SlotID)
	assert.NotNil(t, cr.CertChainHash)
	assert.NotNil(t, cr.MeasurementSummaryHash)
}

func TestMeasurementOptsType(t *testing.T) {
	mo := spdm.MeasurementOpts{
		Index:            0xFF,
		RequestSignature: true,
		SlotID:           0,
		RawBitStream:     false,
	}
	assert.Equal(t, uint8(0xFF), mo.Index)
	assert.True(t, mo.RequestSignature)
}

func TestMeasurementsType(t *testing.T) {
	m := spdm.Measurements{
		NumberOfBlocks: 3,
		Signature:      []byte{0xAA},
	}
	assert.Equal(t, uint8(3), m.NumberOfBlocks)
}

func TestKeyUpdateOpConstants(t *testing.T) {
	assert.Equal(t, spdm.KeyUpdateOp(1), spdm.KeyUpdateUpdateKey)
	assert.Equal(t, spdm.KeyUpdateOp(2), spdm.KeyUpdateUpdateAllKeys)
	assert.Equal(t, spdm.KeyUpdateOp(3), spdm.KeyUpdateVerifyNewKey)
}

func TestVendorRequestType(t *testing.T) {
	vr := spdm.VendorRequest{
		StandardID: 0x0001,
		VendorID:   []byte{0x01, 0x02},
		Payload:    []byte{0xDE, 0xAD},
	}
	assert.Equal(t, uint16(0x0001), vr.StandardID)
	assert.Equal(t, []byte{0x01, 0x02}, vr.VendorID)
	assert.Equal(t, []byte{0xDE, 0xAD}, vr.Payload)
}

func TestVendorResponseType(t *testing.T) {
	vr := spdm.VendorResponse{
		StandardID: 0x0002,
		VendorID:   []byte{0x03},
		Payload:    []byte{0xBE, 0xEF},
	}
	assert.Equal(t, uint16(0x0002), vr.StandardID)
	assert.Equal(t, []byte{0x03}, vr.VendorID)
	assert.Equal(t, []byte{0xBE, 0xEF}, vr.Payload)
}

// ---------------------------------------------------------------------------
// Mock providers for responder tests
// ---------------------------------------------------------------------------

type mockCertProvider struct{}

func (m *mockCertProvider) CertChain(_ context.Context, _ uint8) ([]byte, error) {
	return []byte{0x00}, nil
}

func (m *mockCertProvider) DigestForSlot(_ context.Context, _ uint8) ([]byte, error) {
	return bytes.Repeat([]byte{0x01}, 32), nil
}

type mockMeasProvider struct{}

func (m *mockMeasProvider) Collect(_ context.Context, _ uint8) ([]msgs.MeasurementBlock, error) {
	return nil, nil
}

func (m *mockMeasProvider) SummaryHash(_ context.Context, _ uint8) ([]byte, error) {
	return bytes.Repeat([]byte{0x02}, 32), nil
}

// Ensure unused imports are referenced.
var _ = binary.LittleEndian
var _ = big.NewInt
