package requester

import (
	"context"
	gocrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"hash"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
	"github.com/xaionaro-go/spdm/pkg/gen/status"
	"github.com/xaionaro-go/spdm/pkg/session"
)

// --- RespondIfReady tests ---

func TestRespondIfReady(t *testing.T) {
	// Build a DIGESTS response as the deferred response.
	digest := make([]byte, 32)
	respData := buildDigestResponse(0x12, 0x01, [][]byte{digest})

	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	resp, err := r.RespondIfReady(context.Background(), codes.RequestGetDigests, 0x42)
	require.NoError(t, err)
	assert.Equal(t, uint8(codes.ResponseDigests), resp[1])
}

func TestRespondIfReadyError(t *testing.T) {
	errResp := buildErrorResponse(uint8(codes.ErrorBusy), 0)
	r := newNegotiatedRequesterFromResponses([][]byte{errResp})
	_, err := r.RespondIfReady(context.Background(), codes.RequestGetDigests, 0x01)
	require.Error(t, err)
}

func TestRespondIfReadyTransportError(t *testing.T) {
	r := newNegotiatedRequester(&mockTransport{recvErr: assert.AnError})
	_, err := r.RespondIfReady(context.Background(), codes.RequestGetDigests, 0x01)
	require.Error(t, err)
}

// --- GetEncapsulatedRequest tests ---

func TestGetEncapsulatedRequest(t *testing.T) {
	resp := &msgs.EncapsulatedRequestResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseEncapsulatedRequest),
			Param1:              0x01, // requestID
		}},
		EncapsulatedData: []byte("encapsulated-request"),
	}
	respData, _ := resp.Marshal()

	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	er, err := r.GetEncapsulatedRequest(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []byte("encapsulated-request"), er.EncapsulatedData)
}

func TestGetEncapsulatedRequestError(t *testing.T) {
	errResp := buildErrorResponse(uint8(codes.ErrorUnsupportedRequest), 0)
	r := newNegotiatedRequesterFromResponses([][]byte{errResp})
	_, err := r.GetEncapsulatedRequest(context.Background())
	require.Error(t, err)
}

func TestGetEncapsulatedRequestWrongCode(t *testing.T) {
	// Return a DIGESTS response instead of ENCAPSULATED_REQUEST.
	digest := make([]byte, 32)
	respData := buildDigestResponse(0x12, 0x01, [][]byte{digest})
	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	_, err := r.GetEncapsulatedRequest(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected response code")
}

// --- DeliverEncapsulatedResponse tests ---

func TestDeliverEncapsulatedResponse(t *testing.T) {
	ack := &msgs.EncapsulatedResponseAck{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseEncapsulatedResponseAck),
			Param1:              0x01,
		}},
		EncapsulatedData: []byte("ack-data"),
	}
	ackData, _ := ack.Marshal()

	r := newNegotiatedRequesterFromResponses([][]byte{ackData})
	result, err := r.DeliverEncapsulatedResponse(context.Background(), 0x01, []byte("response-data"))
	require.NoError(t, err)
	assert.Equal(t, []byte("ack-data"), result.EncapsulatedData)
}

func TestDeliverEncapsulatedResponseError(t *testing.T) {
	errResp := buildErrorResponse(uint8(codes.ErrorUnsupportedRequest), 0)
	r := newNegotiatedRequesterFromResponses([][]byte{errResp})
	_, err := r.DeliverEncapsulatedResponse(context.Background(), 0x01, nil)
	require.Error(t, err)
}

func TestDeliverEncapsulatedResponseWrongCode(t *testing.T) {
	digest := make([]byte, 32)
	respData := buildDigestResponse(0x12, 0x01, [][]byte{digest})
	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	_, err := r.DeliverEncapsulatedResponse(context.Background(), 0x01, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected response code")
}

// --- GetSupportedEventTypes tests ---

func TestGetSupportedEventTypes(t *testing.T) {
	resp := &msgs.SupportedEventTypesResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseSupportedEventTypes),
		}},
		SupportedEventCount: 2,
		EventGroupData:      []byte{0x01, 0x02, 0x03, 0x04},
	}
	respData, _ := resp.Marshal()

	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	data, err := r.GetSupportedEventTypes(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, data)
}

func TestGetSupportedEventTypesError(t *testing.T) {
	errResp := buildErrorResponse(uint8(codes.ErrorUnsupportedRequest), 0)
	r := newNegotiatedRequesterFromResponses([][]byte{errResp})
	_, err := r.GetSupportedEventTypes(context.Background())
	require.Error(t, err)
}

func TestGetSupportedEventTypesWrongCode(t *testing.T) {
	digest := make([]byte, 32)
	respData := buildDigestResponse(0x12, 0x01, [][]byte{digest})
	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	_, err := r.GetSupportedEventTypes(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected response code")
}

// --- SubscribeEventTypes tests ---

func TestSubscribeEventTypes(t *testing.T) {
	resp := &msgs.SubscribeEventTypesAckResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseSubscribeEventTypesAck),
		}},
	}
	respData, _ := resp.Marshal()

	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	err := r.SubscribeEventTypes(context.Background(), []byte{0x01, 0x02})
	require.NoError(t, err)
}

func TestSubscribeEventTypesError(t *testing.T) {
	errResp := buildErrorResponse(uint8(codes.ErrorUnsupportedRequest), 0)
	r := newNegotiatedRequesterFromResponses([][]byte{errResp})
	err := r.SubscribeEventTypes(context.Background(), nil)
	require.Error(t, err)
}

func TestSubscribeEventTypesWrongCode(t *testing.T) {
	digest := make([]byte, 32)
	respData := buildDigestResponse(0x12, 0x01, [][]byte{digest})
	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	err := r.SubscribeEventTypes(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected response code")
}

// --- SendEvent tests ---

func TestSendEvent(t *testing.T) {
	resp := &msgs.EventAckResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseEventAck),
		}},
	}
	respData, _ := resp.Marshal()

	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	err := r.SendEvent(context.Background(), []byte("event-data"))
	require.NoError(t, err)
}

func TestSendEventError(t *testing.T) {
	errResp := buildErrorResponse(uint8(codes.ErrorUnsupportedRequest), 0)
	r := newNegotiatedRequesterFromResponses([][]byte{errResp})
	err := r.SendEvent(context.Background(), nil)
	require.Error(t, err)
}

func TestSendEventWrongCode(t *testing.T) {
	digest := make([]byte, 32)
	respData := buildDigestResponse(0x12, 0x01, [][]byte{digest})
	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	err := r.SendEvent(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected response code")
}

// --- SetKeyPairInfo tests ---

func TestSetKeyPairInfo(t *testing.T) {
	resp := &msgs.SetKeyPairInfoAck{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseSetKeyPairInfoAck),
		}},
	}
	respData, _ := resp.Marshal()

	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	err := r.SetKeyPairInfo(context.Background(), 1, 0x01, 0x0001, 0x00000010, 0x01, nil)
	require.NoError(t, err)
}

func TestSetKeyPairInfoError(t *testing.T) {
	errResp := buildErrorResponse(uint8(codes.ErrorUnsupportedRequest), 0)
	r := newNegotiatedRequesterFromResponses([][]byte{errResp})
	err := r.SetKeyPairInfo(context.Background(), 1, 0x01, 0, 0, 0, nil)
	require.Error(t, err)
}

func TestSetKeyPairInfoWrongCode(t *testing.T) {
	digest := make([]byte, 32)
	respData := buildDigestResponse(0x12, 0x01, [][]byte{digest})
	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	err := r.SetKeyPairInfo(context.Background(), 1, 0x01, 0, 0, 0, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected response code")
}

// --- GetEndpointInfo additional tests ---

func TestGetEndpointInfoError(t *testing.T) {
	errResp := buildErrorResponse(uint8(codes.ErrorUnsupportedRequest), 0)
	r := newNegotiatedRequesterFromResponses([][]byte{errResp})
	_, err := r.GetEndpointInfo(context.Background(), 0x01)
	require.Error(t, err)
}

func TestGetEndpointInfoWrongCode(t *testing.T) {
	digest := make([]byte, 32)
	respData := buildDigestResponse(0x12, 0x01, [][]byte{digest})
	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	_, err := r.GetEndpointInfo(context.Background(), 0x01)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected response code")
}

// --- GetMeasurementExtensionLog additional tests ---

func TestGetMeasurementExtensionLogError(t *testing.T) {
	errResp := buildErrorResponse(uint8(codes.ErrorUnsupportedRequest), 0)
	r := newNegotiatedRequesterFromResponses([][]byte{errResp})
	_, err := r.GetMeasurementExtensionLog(context.Background(), 0, 1024)
	require.Error(t, err)
}

func TestGetMeasurementExtensionLogWrongCode(t *testing.T) {
	digest := make([]byte, 32)
	respData := buildDigestResponse(0x12, 0x01, [][]byte{digest})
	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	_, err := r.GetMeasurementExtensionLog(context.Background(), 0, 1024)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected response code")
}

// --- GetKeyPairInfo additional tests ---

func TestGetKeyPairInfoError(t *testing.T) {
	errResp := buildErrorResponse(uint8(codes.ErrorUnsupportedRequest), 0)
	r := newNegotiatedRequesterFromResponses([][]byte{errResp})
	_, err := r.GetKeyPairInfo(context.Background(), 1)
	require.Error(t, err)
}

func TestGetKeyPairInfoWrongCode(t *testing.T) {
	digest := make([]byte, 32)
	respData := buildDigestResponse(0x12, 0x01, [][]byte{digest})
	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	_, err := r.GetKeyPairInfo(context.Background(), 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected response code")
}

// --- GetCSR additional tests ---

func TestGetCSRWrongCode(t *testing.T) {
	digest := make([]byte, 32)
	respData := buildDigestResponse(0x12, 0x01, [][]byte{digest})
	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	_, err := r.GetCSR(context.Background(), nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected response code")
}

// --- SetCertificate additional tests ---

func TestSetCertificateWrongCode(t *testing.T) {
	digest := make([]byte, 32)
	respData := buildDigestResponse(0x12, 0x01, [][]byte{digest})
	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	err := r.SetCertificate(context.Background(), 0, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected response code")
}

// --- VendorDefinedRequest additional tests ---

func TestVendorDefinedRequestWrongCode(t *testing.T) {
	digest := make([]byte, 32)
	respData := buildDigestResponse(0x12, 0x01, [][]byte{digest})
	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	_, err := r.VendorDefinedRequest(context.Background(), 0x42, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected response code")
}

// --- ChunkSend additional tests ---

func TestChunkSendError(t *testing.T) {
	errResp := buildErrorResponse(uint8(codes.ErrorBusy), 0)
	r := New(Config{
		Versions:         []algo.Version{algo.Version12},
		Transport:        &mockTransport{responses: [][]byte{errResp}},
		DataTransferSize: 4096,
	})
	r.conn.PeerVersion = algo.Version12

	err := r.ChunkSend(context.Background(), 1, []byte("msg"))
	require.Error(t, err)
}

func TestChunkSendDataTransferSizeTooSmall(t *testing.T) {
	r := New(Config{
		Versions:         []algo.Version{algo.Version12},
		Transport:        &mockTransport{},
		DataTransferSize: 10, // too small for any chunk overhead
	})
	r.conn.PeerVersion = algo.Version12

	err := r.ChunkSend(context.Background(), 1, []byte("msg"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DataTransferSize too small")
}

func TestChunkSendWrongResponseCode(t *testing.T) {
	digest := make([]byte, 32)
	respData := buildDigestResponse(0x12, 0x01, [][]byte{digest})
	r := New(Config{
		Versions:         []algo.Version{algo.Version12},
		Transport:        &mockTransport{responses: [][]byte{respData}},
		DataTransferSize: 4096,
	})
	r.conn.PeerVersion = algo.Version12

	err := r.ChunkSend(context.Background(), 1, []byte("msg"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected response code")
}

func TestChunkSendEarlyError(t *testing.T) {
	ack := &msgs.ChunkSendAck{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseChunkSendAck),
			Param1:              msgs.ChunkSendAckAttrEarlyError,
		}},
		ChunkSeqNo: 0,
	}
	ackData, _ := ack.Marshal()

	r := New(Config{
		Versions:         []algo.Version{algo.Version12},
		Transport:        &mockTransport{responses: [][]byte{ackData}},
		DataTransferSize: 4096,
	})
	r.conn.PeerVersion = algo.Version12

	err := r.ChunkSend(context.Background(), 1, []byte("msg"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "early error")
}

// --- ChunkGet additional tests ---

func TestChunkGetError(t *testing.T) {
	errResp := buildErrorResponse(uint8(codes.ErrorBusy), 0)
	r := newNegotiatedRequesterFromResponses([][]byte{errResp})
	_, err := r.ChunkGet(context.Background(), 1)
	require.Error(t, err)
}

func TestChunkGetWrongResponseCode(t *testing.T) {
	digest := make([]byte, 32)
	respData := buildDigestResponse(0x12, 0x01, [][]byte{digest})
	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	_, err := r.ChunkGet(context.Background(), 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected response code")
}

// --- DER parsing and certificate chain tests ---

func TestDerObjectLengthShortForm(t *testing.T) {
	data := []byte{0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}
	length, err := derObjectLength(data)
	require.NoError(t, err)
	assert.Equal(t, 7, length) // 2 (tag+len) + 5 (value)
}

func TestDerObjectLengthLongForm(t *testing.T) {
	// Tag=0x30, length byte=0x82 (2 subsequent length bytes), length=0x0100 (256 bytes)
	data := make([]byte, 260)
	data[0] = 0x30
	data[1] = 0x82
	data[2] = 0x01
	data[3] = 0x00
	length, err := derObjectLength(data)
	require.NoError(t, err)
	assert.Equal(t, 260, length) // 2 + 2 + 256
}

func TestDerObjectLengthTooShort(t *testing.T) {
	data := []byte{0x30}
	_, err := derObjectLength(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestDerObjectLengthInvalidEncoding(t *testing.T) {
	// numLenBytes == 0 is invalid.
	data := []byte{0x30, 0x80, 0x01, 0x02}
	_, err := derObjectLength(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid DER length encoding")
}

func TestDerObjectLengthTooManyLengthBytes(t *testing.T) {
	// numLenBytes == 5 is invalid (max 4).
	data := []byte{0x30, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	_, err := derObjectLength(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid DER length encoding")
}

func TestDerObjectLengthExceedsData(t *testing.T) {
	// Long form: claims 1000 bytes of value, but only have 6 bytes total.
	data := []byte{0x30, 0x82, 0x03, 0xE8, 0x01, 0x02}
	_, err := derObjectLength(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds data length")
}

func TestDerObjectLengthShortLengthEncoding(t *testing.T) {
	// Long form header claims 2 length bytes but data is too short.
	data := []byte{0x30, 0x82, 0x01}
	_, err := derObjectLength(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too short for length encoding")
}

func TestParseDERCertificates(t *testing.T) {
	// Generate a real X.509 certificate for testing.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certs, err := parseDERCertificates(certDER)
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, "Test", certs[0].Subject.CommonName)
}

func TestParseDERCertificatesMultiple(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Cert1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	cert1DER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	template2 := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Cert2"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	rootCert, err := x509.ParseCertificate(cert1DER)
	require.NoError(t, err)
	cert2DER, err := x509.CreateCertificate(rand.Reader, template2, rootCert, &key.PublicKey, key)
	require.NoError(t, err)

	concat := append(cert1DER, cert2DER...)
	certs, err := parseDERCertificates(concat)
	require.NoError(t, err)
	require.Len(t, certs, 2)
	assert.Equal(t, "Cert1", certs[0].Subject.CommonName)
	assert.Equal(t, "Cert2", certs[1].Subject.CommonName)
}

func TestParseDERCertificatesInvalid(t *testing.T) {
	// Invalid DER data.
	_, err := parseDERCertificates([]byte{0x30, 0x03, 0x01, 0x02, 0x03})
	require.Error(t, err)
}

func TestParseDERCertificatesEmpty(t *testing.T) {
	certs, err := parseDERCertificates(nil)
	require.NoError(t, err)
	assert.Empty(t, certs)
}

// --- extractPeerPublicKey tests ---

func TestExtractPeerPublicKeyNoCertChain(t *testing.T) {
	r := newNegotiatedRequester(&mockTransport{})
	_, err := r.extractPeerPublicKey()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no peer certificate chain")
}

func TestExtractPeerPublicKeyTooShort(t *testing.T) {
	r := newNegotiatedRequester(&mockTransport{})
	r.peerCertChain = []byte{0x01, 0x02}
	_, err := r.extractPeerPublicKey()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestExtractPeerPublicKeyValid(t *testing.T) {
	r := newNegotiatedRequester(&mockTransport{})

	// Build a minimal SPDM cert chain with a real certificate.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	hashSize := algo.HashSHA256.Size()
	headerSize := msgs.CertChainHeaderSize
	rootHash := make([]byte, hashSize)
	chain := make([]byte, headerSize+hashSize+len(certDER))
	binary.LittleEndian.PutUint16(chain[0:2], uint16(len(chain)))
	copy(chain[headerSize:], rootHash)
	copy(chain[headerSize+hashSize:], certDER)

	r.peerCertChain = chain
	pubKey, err := r.extractPeerPublicKey()
	require.NoError(t, err)
	assert.NotNil(t, pubKey)
}

func TestExtractPeerPublicKeyNoCerts(t *testing.T) {
	r := newNegotiatedRequester(&mockTransport{})

	hashSize := algo.HashSHA256.Size()
	headerSize := msgs.CertChainHeaderSize
	// Chain with header + root hash but no certificate data.
	chain := make([]byte, headerSize+hashSize)
	binary.LittleEndian.PutUint16(chain[0:2], uint16(len(chain)))
	r.peerCertChain = chain

	_, err := r.extractPeerPublicKey()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no certificates")
}

// --- validateCertChain tests ---

func TestValidateCertChainTooShort(t *testing.T) {
	rootPool := x509.NewCertPool()

	r := newNegotiatedRequester(&mockTransport{})
	r.cfg.Crypto.CertPool = rootPool

	err := r.validateCertChain(context.Background(), []byte{0x01, 0x02})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "chain too short")
}

func TestValidateCertChainNoCerts(t *testing.T) {
	rootPool := x509.NewCertPool()

	r := newNegotiatedRequester(&mockTransport{})
	r.cfg.Crypto.CertPool = rootPool

	hashSize := algo.HashSHA256.Size()
	headerSize := msgs.CertChainHeaderSize
	chain := make([]byte, headerSize+hashSize)

	err := r.validateCertChain(context.Background(), chain)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no certificates")
}

func TestValidateCertChainSuccess(t *testing.T) {
	// Generate a real CA and leaf certificate.
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	r := newNegotiatedRequester(&mockTransport{})
	r.cfg.Crypto.CertPool = rootPool

	hashSize := algo.HashSHA256.Size()
	headerSize := msgs.CertChainHeaderSize
	rootHash := sha256.Sum256(rootDER)

	certData := append(rootDER, leafDER...)
	chain := make([]byte, headerSize+hashSize+len(certData))
	binary.LittleEndian.PutUint16(chain[0:2], uint16(len(chain)))
	copy(chain[headerSize:], rootHash[:])
	copy(chain[headerSize+hashSize:], certData)

	err = r.validateCertChain(context.Background(), chain)
	require.NoError(t, err)
}

func TestValidateCertChainInvalidDER(t *testing.T) {
	rootPool := x509.NewCertPool()

	r := newNegotiatedRequester(&mockTransport{})
	r.cfg.Crypto.CertPool = rootPool

	hashSize := algo.HashSHA256.Size()
	headerSize := msgs.CertChainHeaderSize
	// Invalid cert data after header+hash.
	invalidCert := []byte{0x30, 0x03, 0x01, 0x02, 0x03}
	chain := make([]byte, headerSize+hashSize+len(invalidCert))
	copy(chain[headerSize+hashSize:], invalidCert)

	err := r.validateCertChain(context.Background(), chain)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse certificates")
}

// --- buildSigningData tests ---

func TestBuildSigningData(t *testing.T) {
	message := []byte("test message for signing")
	context := msgs.ChallengeAuthSignContext

	result := buildSigningData(algo.HashSHA256.CryptoHash(), message, context)
	// Result should be SigningContextSize + hashSize bytes.
	assert.Equal(t, msgs.SigningContextSize+algo.HashSHA256.Size(), len(result))
}

// --- newHash tests ---

func TestNewHash(t *testing.T) {
	r := newNegotiatedRequester(&mockTransport{})
	hashFactory := r.newHash()
	h := hashFactory()
	require.NotNil(t, h)
	h.Write([]byte("test"))
	assert.Equal(t, 32, h.Size())
}

// --- checkResponse additional tests ---

func TestCheckResponseTooShort(t *testing.T) {
	r := New(Config{})
	_, err := r.checkResponse([]byte{0x12})
	require.Error(t, err)
	assert.ErrorIs(t, err, status.ErrInvalidMsgSize)
}

func TestCheckResponseNormal(t *testing.T) {
	r := New(Config{})
	resp := []byte{0x12, uint8(codes.ResponseDigests), 0x00, 0x01}
	data, err := r.checkResponse(resp)
	require.NoError(t, err)
	assert.Equal(t, resp, data)
}

func TestCheckResponseError(t *testing.T) {
	r := New(Config{})
	resp := buildErrorResponse(uint8(codes.ErrorBusy), 0)
	_, err := r.checkResponse(resp)
	require.Error(t, err)
	var pe *status.ProtocolError
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, uint8(codes.ErrorBusy), pe.ErrorCode)
}

// --- sendReceiveVCA error paths ---

func TestSendReceiveVCASendError(t *testing.T) {
	mt := &mockTransport{sendErr: assert.AnError}
	r := New(Config{Transport: mt, Versions: []algo.Version{algo.Version12}})
	r.conn.PeerVersion = algo.Version12
	_, err := r.InitConnection(context.Background())
	require.Error(t, err)
}

// --- securedSessionTransport is a mock transport that handles AEAD encryption/decryption ---

// securedSessionTransport wraps a session to simulate the responder side for secured messaging.
type securedSessionTransport struct {
	sess         *session.Session
	sent         [][]byte
	responseCode uint8 // response code byte[1]
	sendErr      error
	recvErr      error
}

func (s *securedSessionTransport) SendMessage(_ context.Context, _ *uint32, msg []byte) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	cp := make([]byte, len(msg))
	copy(cp, msg)
	s.sent = append(s.sent, cp)
	return nil
}

func (s *securedSessionTransport) ReceiveMessage(_ context.Context) (*uint32, []byte, error) {
	if s.recvErr != nil {
		return nil, nil, s.recvErr
	}

	// Build a response with the given response code.
	resp := []byte{0x12, s.responseCode, 0x00, 0x00}

	// Encrypt it using the session's data keys (response direction).
	rspSeq := s.sess.RspSeqNum

	sid := uint32(s.sess.ID)
	secured, err := session.EncodeSecuredMessage(
		s.sess.AEAD,
		s.sess.DataKeys.ResponseKey,
		s.sess.DataKeys.ResponseIV,
		rspSeq,
		sid,
		resp,
		s.sess.EncryptionRequired,
		s.sess.SeqNumSize,
	)
	if err != nil {
		return nil, nil, err
	}

	return nil, secured, nil
}

func (s *securedSessionTransport) HeaderSize() int { return 0 }

// newEstablishedSession creates a fully established session with real AES-128-GCM keys
// and the matching requester configured to use it.
func newEstablishedSession(t *testing.T, responseCode uint8) (*Requester, session.SessionID, *securedSessionTransport) {
	t.Helper()

	sid := session.SessionID(0x12340001)
	hashAlgo := algo.HashSHA256
	aeadSuite := algo.AEADAES128GCM

	// Create a session in established state.
	sess := session.NewSession(sid, algo.Version12, hashAlgo, aeadSuite, true)
	sess.State = session.StateEstablished

	// Generate real AES-128-GCM keys (16 bytes key, 12 bytes IV).
	reqKey := make([]byte, 16)
	rspKey := make([]byte, 16)
	reqIV := make([]byte, 12)
	rspIV := make([]byte, 12)
	reqSecret := make([]byte, 32)
	rspSecret := make([]byte, 32)
	_, _ = rand.Read(reqKey)
	_, _ = rand.Read(rspKey)
	_, _ = rand.Read(reqIV)
	_, _ = rand.Read(rspIV)
	_, _ = rand.Read(reqSecret)
	_, _ = rand.Read(rspSecret)

	sess.DataKeys = &session.DataKeys{
		RequestKey:     reqKey,
		ResponseKey:    rspKey,
		RequestIV:      reqIV,
		ResponseIV:     rspIV,
		RequestSecret:  reqSecret,
		ResponseSecret: rspSecret,
	}

	st := &securedSessionTransport{
		sess:         sess,
		responseCode: responseCode,
	}

	r := New(Config{
		Versions:     []algo.Version{algo.Version12},
		Transport:    st,
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
		AEADSuites:   algo.AEADAES128GCM,
	})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256
	r.conn.AsymAlgo = algo.AsymECDSAP256
	r.conn.AEADSuite = algo.AEADAES128GCM
	r.sessions[sid] = sess

	return r, sid, st
}

// --- SendReceiveSecured tests ---

func TestSendReceiveSecured(t *testing.T) {
	r, sid, _ := newEstablishedSession(t, uint8(codes.ResponseHeartbeatAck))
	sess := r.sessions[sid]

	plaintext := []byte{0x12, uint8(codes.RequestHeartbeat), 0x00, 0x00}
	resp, err := r.SendReceiveSecured(context.Background(), sess, plaintext)
	require.NoError(t, err)
	assert.Equal(t, uint8(codes.ResponseHeartbeatAck), resp[1])
}

func TestSendReceiveSecuredSendError(t *testing.T) {
	r, sid, st := newEstablishedSession(t, uint8(codes.ResponseHeartbeatAck))
	sess := r.sessions[sid]
	st.sendErr = assert.AnError

	plaintext := []byte{0x12, uint8(codes.RequestHeartbeat), 0x00, 0x00}
	_, err := r.SendReceiveSecured(context.Background(), sess, plaintext)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "send secured")
}

func TestSendReceiveSecuredRecvError(t *testing.T) {
	r, sid, st := newEstablishedSession(t, uint8(codes.ResponseHeartbeatAck))
	sess := r.sessions[sid]
	st.recvErr = assert.AnError

	plaintext := []byte{0x12, uint8(codes.RequestHeartbeat), 0x00, 0x00}
	_, err := r.SendReceiveSecured(context.Background(), sess, plaintext)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "receive secured")
}

func TestSendReceiveSecuredErrorResponse(t *testing.T) {
	r, sid, _ := newEstablishedSession(t, uint8(codes.ResponseError))

	// Override the transport to return an encrypted ERROR response.
	sess := r.sessions[sid]
	plaintext := []byte{0x12, uint8(codes.RequestHeartbeat), 0x00, 0x00}
	_, err := r.SendReceiveSecured(context.Background(), sess, plaintext)
	require.Error(t, err)
	var pe *status.ProtocolError
	require.ErrorAs(t, err, &pe)
}

// --- Heartbeat with established session tests ---

func TestHeartbeatEstablishedSession(t *testing.T) {
	r, sid, _ := newEstablishedSession(t, uint8(codes.ResponseHeartbeatAck))
	err := r.Heartbeat(context.Background(), sid)
	require.NoError(t, err)
}

func TestHeartbeatWrongResponseCode(t *testing.T) {
	r, sid, _ := newEstablishedSession(t, uint8(codes.ResponseDigests))
	err := r.Heartbeat(context.Background(), sid)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected response code")
}

func TestHeartbeatSendError(t *testing.T) {
	r, sid, st := newEstablishedSession(t, uint8(codes.ResponseHeartbeatAck))
	st.sendErr = assert.AnError
	err := r.Heartbeat(context.Background(), sid)
	require.Error(t, err)
}

// --- KeyUpdate with established session tests ---

func TestKeyUpdateEstablishedSession(t *testing.T) {
	r, sid, _ := newEstablishedSession(t, uint8(codes.ResponseKeyUpdateAck))
	err := r.KeyUpdate(context.Background(), sid, msgs.KeyUpdateOpUpdateKey)
	require.NoError(t, err)
}

func TestKeyUpdateAllKeysEstablished(t *testing.T) {
	r, sid, _ := newEstablishedSession(t, uint8(codes.ResponseKeyUpdateAck))
	err := r.KeyUpdate(context.Background(), sid, msgs.KeyUpdateOpUpdateAllKeys)
	require.NoError(t, err)
}

func TestKeyUpdateWrongResponseCode(t *testing.T) {
	r, sid, _ := newEstablishedSession(t, uint8(codes.ResponseDigests))
	err := r.KeyUpdate(context.Background(), sid, msgs.KeyUpdateOpUpdateKey)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected response code")
}

func TestKeyUpdateSendError(t *testing.T) {
	r, sid, st := newEstablishedSession(t, uint8(codes.ResponseKeyUpdateAck))
	st.sendErr = assert.AnError
	err := r.KeyUpdate(context.Background(), sid, msgs.KeyUpdateOpUpdateKey)
	require.Error(t, err)
}

// --- EndSession with established session tests ---

func TestEndSessionEstablished(t *testing.T) {
	r, sid, _ := newEstablishedSession(t, uint8(codes.ResponseEndSessionAck))
	err := r.EndSession(context.Background(), sid)
	require.NoError(t, err)
	// Session should be removed.
	_, ok := r.sessions[sid]
	assert.False(t, ok)
}

func TestEndSessionWrongResponseCode(t *testing.T) {
	r, sid, _ := newEstablishedSession(t, uint8(codes.ResponseDigests))
	err := r.EndSession(context.Background(), sid)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected response code")
}

func TestEndSessionSendError(t *testing.T) {
	r, sid, st := newEstablishedSession(t, uint8(codes.ResponseEndSessionAck))
	st.sendErr = assert.AnError
	err := r.EndSession(context.Background(), sid)
	require.Error(t, err)
}

// --- PSKExchange full flow test ---

// pskResponderTransport simulates a PSK responder that computes proper HMAC verify data.
type pskResponderTransport struct {
	sent          [][]byte
	psk           []byte
	hashAlgo      algo.BaseHashAlgo
	aeadSuite     algo.AEADCipherSuite
	version       algo.Version
	vcaTranscript []byte
	phase         int // 0 = PSK_EXCHANGE, 1 = PSK_FINISH
}

func (p *pskResponderTransport) SendMessage(_ context.Context, _ *uint32, msg []byte) error {
	cp := make([]byte, len(msg))
	copy(cp, msg)
	p.sent = append(p.sent, cp)
	return nil
}

func (p *pskResponderTransport) ReceiveMessage(_ context.Context) (*uint32, []byte, error) {
	if p.phase == 0 {
		return p.handlePSKExchange()
	}
	return p.handlePSKFinish()
}

func (p *pskResponderTransport) handlePSKExchange() (*uint32, []byte, error) {
	p.phase = 1
	reqBytes := p.sent[len(p.sent)-1]

	// Parse PSK_EXCHANGE request.
	var pskReq msgs.PSKExchange
	if err := pskReq.Unmarshal(reqBytes); err != nil {
		return nil, nil, err
	}

	hashSize := p.hashAlgo.Size()
	newHash := p.newHash()

	rspSessionID := uint16(0xBBBB)

	// Build context (same size as request context).
	rspContext := make([]byte, hashSize)

	// Build PSK_EXCHANGE_RSP header + fields (without VerifyData initially).
	pskResp := &msgs.PSKExchangeResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(p.version),
			RequestResponseCode: uint8(codes.ResponsePSKExchangeRsp),
			Param1:              msgs.NoMeasurementSummaryHash,
		}},
		RspSessionID: rspSessionID,
		Context:      rspContext,
		OpaqueData:   nil, // no opaque data
	}

	// Marshal without verify data.
	respNoVerify, _ := pskResp.Marshal()

	// Derive handshake keys.
	hsSecret, err := session.DeriveHandshakeSecret(context.Background(), newHash, p.version, p.psk)
	if err != nil {
		return nil, nil, err
	}

	// TH1 = hash(VCA || PSK_EXCHANGE_req || PSK_EXCHANGE_RSP_without_verify_data)
	th1Hasher := newHash()
	th1Hasher.Write(p.vcaTranscript)
	th1Hasher.Write(reqBytes)
	th1Hasher.Write(respNoVerify)
	th1Hash := th1Hasher.Sum(nil)

	hsKeys, err := session.DeriveHandshakeKeys(context.Background(), newHash, p.version, p.aeadSuite, hsSecret, th1Hash)
	if err != nil {
		return nil, nil, err
	}

	// Generate responder verify data.
	verifyData := session.GenerateFinishedKey(context.Background(), newHash, hsKeys.ResponseFinished, th1Hash)

	// Append verify data to response.
	pskResp.VerifyData = verifyData
	fullResp, _ := pskResp.Marshal()

	return nil, fullResp, nil
}

func (p *pskResponderTransport) handlePSKFinish() (*uint32, []byte, error) {
	// Return PSK_FINISH_RSP.
	resp := &msgs.PSKFinishResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(p.version),
			RequestResponseCode: uint8(codes.ResponsePSKFinishRsp),
		}},
	}
	data, _ := resp.Marshal()
	return nil, data, nil
}

func (p *pskResponderTransport) HeaderSize() int { return 0 }

func (p *pskResponderTransport) newHash() func() hash.Hash {
	return func() hash.Hash { return p.hashAlgo.CryptoHash().New() }
}

func TestPSKExchangeFullFlow(t *testing.T) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(i)
	}

	pt := &pskResponderTransport{
		psk:       psk,
		hashAlgo:  algo.HashSHA256,
		aeadSuite: algo.AEADAES128GCM,
		version:   algo.Version12,
	}

	r := New(Config{
		Versions:     []algo.Version{algo.Version12},
		Transport:    pt,
		BaseHashAlgo: algo.HashSHA256,
		AEADSuites:   algo.AEADAES128GCM,
		PSKProvider:  &mockPSKProvider{psk: psk},
	})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256
	r.conn.AEADSuite = algo.AEADAES128GCM

	// Copy the VCA transcript to the responder transport.
	pt.vcaTranscript = r.vcaTranscript

	sess, err := r.PSKExchange(context.Background(), []byte("hint"))
	require.NoError(t, err)
	require.NotNil(t, sess)
	assert.Equal(t, session.StateEstablished, sess.State)
	assert.NotNil(t, sess.DataKeys)
}

// --- verifyChallengeSignature and verifyMeasurementsSignature tests ---

// mockVerifier implements crypto.Verifier for testing.
type mockVerifier struct {
	err error
}

func (m *mockVerifier) Verify(_ algo.BaseAsymAlgo, _ gocrypto.PublicKey, _, _ []byte) error {
	return m.err
}

func TestVerifyChallengeSignatureSuccess(t *testing.T) {
	r := newNegotiatedRequester(&mockTransport{})
	r.cfg.Crypto.Verifier = &mockVerifier{}

	// Build a cert chain with a real certificate.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	hashSize := algo.HashSHA256.Size()
	headerSize := msgs.CertChainHeaderSize
	h := sha256.Sum256(certDER)
	chain := make([]byte, headerSize+hashSize+len(certDER))
	binary.LittleEndian.PutUint16(chain[0:2], uint16(len(chain)))
	copy(chain[headerSize:], h[:])
	copy(chain[headerSize+hashSize:], certDER)
	r.peerCertChain = chain

	reqBytes := []byte{0x12, 0x83, 0x00, 0x00}
	car := &msgs.ChallengeAuthResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseChallengeAuth),
		}},
		CertChainHash: make([]byte, hashSize),
		Signature:     make([]byte, 64),
	}
	respBytes, _ := car.Marshal()

	err = r.verifyChallengeSignature(context.Background(), reqBytes, respBytes, car)
	require.NoError(t, err)
}

func TestVerifyChallengeSignatureVerifyFails(t *testing.T) {
	r := newNegotiatedRequester(&mockTransport{})
	r.cfg.Crypto.Verifier = &mockVerifier{err: assert.AnError}

	// Build cert chain.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	hashSize := algo.HashSHA256.Size()
	headerSize := msgs.CertChainHeaderSize
	h := sha256.Sum256(certDER)
	chain := make([]byte, headerSize+hashSize+len(certDER))
	binary.LittleEndian.PutUint16(chain[0:2], uint16(len(chain)))
	copy(chain[headerSize:], h[:])
	copy(chain[headerSize+hashSize:], certDER)
	r.peerCertChain = chain

	reqBytes := []byte{0x12, 0x83, 0x00, 0x00}
	car := &msgs.ChallengeAuthResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseChallengeAuth),
		}},
		CertChainHash: make([]byte, hashSize),
		Signature:     make([]byte, 64),
	}
	respBytes, _ := car.Marshal()

	err = r.verifyChallengeSignature(context.Background(), reqBytes, respBytes, car)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verify")
}

func TestVerifyChallengeSignatureNoPeerCert(t *testing.T) {
	r := newNegotiatedRequester(&mockTransport{})
	r.cfg.Crypto.Verifier = &mockVerifier{}
	// No peer cert chain set.

	reqBytes := []byte{0x12, 0x83, 0x00, 0x00}
	car := &msgs.ChallengeAuthResponse{
		Signature: make([]byte, 64),
	}
	respBytes := []byte{0x12, uint8(codes.ResponseChallengeAuth), 0x00, 0x00}

	err := r.verifyChallengeSignature(context.Background(), reqBytes, respBytes, car)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "extract peer public key")
}

func TestVerifyMeasurementsSignatureSuccess(t *testing.T) {
	r := newNegotiatedRequester(&mockTransport{})
	r.cfg.Crypto.Verifier = &mockVerifier{}

	// Build cert chain.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	hashSize := algo.HashSHA256.Size()
	headerSize := msgs.CertChainHeaderSize
	h := sha256.Sum256(certDER)
	chain := make([]byte, headerSize+hashSize+len(certDER))
	binary.LittleEndian.PutUint16(chain[0:2], uint16(len(chain)))
	copy(chain[headerSize:], h[:])
	copy(chain[headerSize+hashSize:], certDER)
	r.peerCertChain = chain

	mr := &msgs.MeasurementsResponse{
		Signature: make([]byte, 64),
	}

	err = r.verifyMeasurementsSignature(context.Background(), mr)
	require.NoError(t, err)
}

func TestVerifyMeasurementsSignatureFailure(t *testing.T) {
	r := newNegotiatedRequester(&mockTransport{})
	r.cfg.Crypto.Verifier = &mockVerifier{err: assert.AnError}

	// Build cert chain.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	hashSize := algo.HashSHA256.Size()
	headerSize := msgs.CertChainHeaderSize
	h := sha256.Sum256(certDER)
	chain := make([]byte, headerSize+hashSize+len(certDER))
	binary.LittleEndian.PutUint16(chain[0:2], uint16(len(chain)))
	copy(chain[headerSize:], h[:])
	copy(chain[headerSize+hashSize:], certDER)
	r.peerCertChain = chain

	mr := &msgs.MeasurementsResponse{
		Signature: make([]byte, 64),
	}

	err = r.verifyMeasurementsSignature(context.Background(), mr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verify")
}

func TestVerifyMeasurementsSignatureNoPeerCert(t *testing.T) {
	r := newNegotiatedRequester(&mockTransport{})
	r.cfg.Crypto.Verifier = &mockVerifier{}

	mr := &msgs.MeasurementsResponse{
		Signature: make([]byte, 64),
	}

	err := r.verifyMeasurementsSignature(context.Background(), mr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "extract peer public key")
}

// --- GetMeasurements with signature verification ---

func TestGetMeasurementsWithSignatureVerification(t *testing.T) {
	// Build a measurements response with signature.
	sigSize := algo.AsymECDSAP256.SignatureSize()
	record := []byte{0xAA, 0xBB}
	sig := make([]byte, sigSize)

	resp := &msgs.MeasurementsResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseMeasurements),
			Param1:              1,
		}},
		NumberOfBlocks:       1,
		MeasurementRecordLen: uint32(len(record)),
		MeasurementRecord:    record,
		Signature:            sig,
	}
	respData, _ := resp.Marshal()

	mt := &mockTransport{responses: [][]byte{respData}}
	r := newNegotiatedRequester(mt)

	// Set up verifier and peer cert chain.
	r.cfg.Crypto.Verifier = &mockVerifier{}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	hashSize := algo.HashSHA256.Size()
	headerSize := msgs.CertChainHeaderSize
	h := sha256.Sum256(certDER)
	chain := make([]byte, headerSize+hashSize+len(certDER))
	binary.LittleEndian.PutUint16(chain[0:2], uint16(len(chain)))
	copy(chain[headerSize:], h[:])
	copy(chain[headerSize+hashSize:], certDER)
	r.peerCertChain = chain

	mr, err := r.GetMeasurements(context.Background(), 1, true)
	require.NoError(t, err)
	assert.Equal(t, uint8(1), mr.NumberOfBlocks)
	// measTranscript should be reset after verified signature.
	assert.Nil(t, r.measTranscript)
}

func TestGetMeasurementsWithSignatureVerificationFailure(t *testing.T) {
	sigSize := algo.AsymECDSAP256.SignatureSize()
	record := []byte{0xAA}
	sig := make([]byte, sigSize)

	resp := &msgs.MeasurementsResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseMeasurements),
			Param1:              1,
		}},
		NumberOfBlocks:       1,
		MeasurementRecordLen: uint32(len(record)),
		MeasurementRecord:    record,
		Signature:            sig,
	}
	respData, _ := resp.Marshal()

	mt := &mockTransport{responses: [][]byte{respData}}
	r := newNegotiatedRequester(mt)

	// Verifier returns error.
	r.cfg.Crypto.Verifier = &mockVerifier{err: assert.AnError}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	hashSize := algo.HashSHA256.Size()
	headerSize := msgs.CertChainHeaderSize
	h := sha256.Sum256(certDER)
	chain := make([]byte, headerSize+hashSize+len(certDER))
	binary.LittleEndian.PutUint16(chain[0:2], uint16(len(chain)))
	copy(chain[headerSize:], h[:])
	copy(chain[headerSize+hashSize:], certDER)
	r.peerCertChain = chain

	_, err = r.GetMeasurements(context.Background(), 1, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification")
	// measTranscript should be reset on verification failure.
	assert.Nil(t, r.measTranscript)
}

// --- Challenge with signature verification ---

func TestChallengeWithSignatureVerification(t *testing.T) {
	digestSize := algo.HashSHA256.Size()
	sigSize := algo.AsymECDSAP256.SignatureSize()

	mt := &mockTransport{
		responses: [][]byte{
			buildChallengeAuthResponse(0x12, 0, digestSize, 0, sigSize),
		},
	}

	r := newNegotiatedRequester(mt)
	r.cfg.Crypto.Verifier = &mockVerifier{}

	// Build cert chain.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	hashSize := algo.HashSHA256.Size()
	headerSize := msgs.CertChainHeaderSize
	h := sha256.Sum256(certDER)
	chain := make([]byte, headerSize+hashSize+len(certDER))
	binary.LittleEndian.PutUint16(chain[0:2], uint16(len(chain)))
	copy(chain[headerSize:], h[:])
	copy(chain[headerSize+hashSize:], certDER)
	r.peerCertChain = chain

	err = r.Challenge(context.Background(), 0, msgs.NoMeasurementSummaryHash)
	require.NoError(t, err)
	assert.Equal(t, StateAuthenticated, r.State())
}

// --- GetCertificate with validation ---

func TestGetCertificateWithValidation(t *testing.T) {
	// Generate a real CA and leaf certificate.
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	// Build SPDM cert chain.
	hashSize := algo.HashSHA256.Size()
	headerSize := msgs.CertChainHeaderSize
	rootHash := sha256.Sum256(rootDER)
	certData := append(rootDER, leafDER...)
	chain := make([]byte, headerSize+hashSize+len(certData))
	binary.LittleEndian.PutUint16(chain[0:2], uint16(len(chain)))
	copy(chain[headerSize:], rootHash[:])
	copy(chain[headerSize+hashSize:], certData)

	mt := &mockTransport{
		responses: [][]byte{
			buildCertificateResponse(0x12, 0, chain, 0),
		},
	}

	r := newNegotiatedRequester(mt)
	r.cfg.Crypto.CertPool = rootPool

	result, err := r.GetCertificate(context.Background(), 0)
	require.NoError(t, err)
	assert.Equal(t, chain, result)
}
