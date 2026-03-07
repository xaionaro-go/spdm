package responder

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

// --- Mock providers ---

type mockCSRProvider struct {
	csr []byte
	err error
}

func (m *mockCSRProvider) GenerateCSR(_ context.Context, _, _ []byte) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.csr, nil
}

type mockProvisioningProvider struct {
	setCertErr    error
	keyPairInfo   *msgs.KeyPairInfoResponse
	keyPairErr    error
	setKeyPairErr error
}

func (m *mockProvisioningProvider) SetCertificate(_ context.Context, _ uint8, _ []byte) error {
	return m.setCertErr
}

func (m *mockProvisioningProvider) GetKeyPairInfo(_ context.Context, _ uint8) (*msgs.KeyPairInfoResponse, error) {
	if m.keyPairErr != nil {
		return nil, m.keyPairErr
	}
	return m.keyPairInfo, nil
}

func (m *mockProvisioningProvider) SetKeyPairInfo(_ context.Context, _ uint8, _ uint8, _ uint16, _ uint32, _ []byte) error {
	return m.setKeyPairErr
}

type mockEndpointInfoProvider struct {
	info []byte
	err  error
}

func (m *mockEndpointInfoProvider) GetEndpointInfo(_ context.Context, _ uint8) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.info, nil
}

type mockMELProvider struct {
	portion   []byte
	remainder uint32
	err       error
}

func (m *mockMELProvider) GetMEL(_ context.Context, _, _ uint32) ([]byte, uint32, error) {
	if m.err != nil {
		return nil, 0, m.err
	}
	return m.portion, m.remainder, nil
}

// --- CSR handler tests ---

func TestGetCSRNilProvider(t *testing.T) {
	r := newTestResponder()
	negotiateResponder(t, r)

	req := &msgs.GetCSR{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetCSR),
		}},
	}
	reqData, _ := req.Marshal()
	resp, _ := r.ProcessMessage(context.Background(), reqData)
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnsupportedRequest, errResp.ErrorCode())
}

func TestGetCSRNotNegotiated(t *testing.T) {
	r := newTestResponder()
	r.cfg.CSRProvider = &mockCSRProvider{csr: []byte("csr")}
	r.version = 0x12

	req := &msgs.GetCSR{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetCSR),
		}},
	}
	reqData, _ := req.Marshal()
	resp, _ := r.ProcessMessage(context.Background(), reqData)
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnexpectedRequest, errResp.ErrorCode())
}

func TestGetCSRSuccess(t *testing.T) {
	r := newTestResponder()
	r.cfg.CSRProvider = &mockCSRProvider{csr: []byte("test-csr")}
	negotiateResponder(t, r)

	req := &msgs.GetCSR{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetCSR),
		}},
		RequesterInfo: []byte("info"),
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var cr msgs.CSRResponse
	require.NoError(t, cr.Unmarshal(resp))
	assert.Equal(t, uint8(codes.ResponseCSR), cr.Header.RequestResponseCode)
	assert.Equal(t, []byte("test-csr"), cr.CSR)
}

func TestGetCSRProviderError(t *testing.T) {
	r := newTestResponder()
	r.cfg.CSRProvider = &mockCSRProvider{err: fmt.Errorf("gen failed")}
	negotiateResponder(t, r)

	req := &msgs.GetCSR{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetCSR),
		}},
	}
	reqData, _ := req.Marshal()
	resp, _ := r.ProcessMessage(context.Background(), reqData)
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnspecified, errResp.ErrorCode())
}

// --- SetCertificate handler tests ---

func TestSetCertificateNilProvider(t *testing.T) {
	r := newTestResponder()
	negotiateResponder(t, r)

	req := &msgs.SetCertificate{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestSetCertificate),
		}},
	}
	reqData, _ := req.Marshal()
	resp, _ := r.ProcessMessage(context.Background(), reqData)
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnsupportedRequest, errResp.ErrorCode())
}

func TestSetCertificateSuccess(t *testing.T) {
	r := newTestResponder()
	r.cfg.ProvisioningProvider = &mockProvisioningProvider{}
	negotiateResponder(t, r)

	req := &msgs.SetCertificate{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestSetCertificate),
			Param1:              0x02, // slotID=2
		}},
		CertChain: []byte("cert-chain"),
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var scr msgs.SetCertificateResponse
	require.NoError(t, scr.Unmarshal(resp))
	assert.Equal(t, uint8(codes.ResponseSetCertificateRsp), scr.Header.RequestResponseCode)
}

// --- GetKeyPairInfo handler tests ---

func TestGetKeyPairInfoNilProvider(t *testing.T) {
	r := newTestResponder()
	negotiateResponder(t, r)

	req := &msgs.GetKeyPairInfo{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetKeyPairInfo),
		}},
		KeyPairID: 1,
	}
	reqData, _ := req.Marshal()
	resp, _ := r.ProcessMessage(context.Background(), reqData)
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnsupportedRequest, errResp.ErrorCode())
}

func TestGetKeyPairInfoSuccess(t *testing.T) {
	r := newTestResponder()
	r.cfg.ProvisioningProvider = &mockProvisioningProvider{
		keyPairInfo: &msgs.KeyPairInfoResponse{
			TotalKeyPairs: 3,
			KeyPairID:     1,
		},
	}
	negotiateResponder(t, r)

	req := &msgs.GetKeyPairInfo{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetKeyPairInfo),
		}},
		KeyPairID: 1,
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var kpr msgs.KeyPairInfoResponse
	require.NoError(t, kpr.Unmarshal(resp))
	assert.Equal(t, uint8(codes.ResponseKeyPairInfo), kpr.Header.RequestResponseCode)
	assert.Equal(t, uint8(3), kpr.TotalKeyPairs)
}

// --- EndpointInfo handler tests ---

func TestGetEndpointInfoNilProvider(t *testing.T) {
	r := newTestResponder()
	negotiateResponder(t, r)

	req := &msgs.GetEndpointInfo{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetEndpointInfo),
		}},
	}
	reqData, _ := req.Marshal()
	resp, _ := r.ProcessMessage(context.Background(), reqData)
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnsupportedRequest, errResp.ErrorCode())
}

func TestGetEndpointInfoSuccess(t *testing.T) {
	r := newTestResponder()
	r.cfg.EndpointInfoProvider = &mockEndpointInfoProvider{info: []byte("endpoint-data")}
	negotiateResponder(t, r)

	req := &msgs.GetEndpointInfo{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetEndpointInfo),
			Param1:              0x01,
		}},
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var eir msgs.EndpointInfoResponse
	require.NoError(t, eir.Unmarshal(resp))
	assert.Equal(t, uint8(codes.ResponseEndpointInfo), eir.Header.RequestResponseCode)
	assert.Equal(t, []byte("endpoint-data"), eir.EndpointInfo)
}

// --- MEL handler tests ---

func TestGetMELNilProvider(t *testing.T) {
	r := newTestResponder()
	negotiateResponder(t, r)

	req := &msgs.GetMeasurementExtensionLog{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetMeasurementExtensionLog),
		}},
		Offset: 0,
		Length: 1024,
	}
	reqData, _ := req.Marshal()
	resp, _ := r.ProcessMessage(context.Background(), reqData)
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnsupportedRequest, errResp.ErrorCode())
}

func TestGetMELSuccess(t *testing.T) {
	r := newTestResponder()
	r.cfg.MELProvider = &mockMELProvider{portion: []byte("mel-data"), remainder: 100}
	negotiateResponder(t, r)

	req := &msgs.GetMeasurementExtensionLog{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetMeasurementExtensionLog),
		}},
		Offset: 0,
		Length: 1024,
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var mr msgs.MeasurementExtensionLogResponse
	require.NoError(t, mr.Unmarshal(resp))
	assert.Equal(t, uint8(codes.ResponseMeasurementExtensionLog), mr.Header.RequestResponseCode)
	assert.Equal(t, []byte("mel-data"), mr.MEL)
	assert.Equal(t, uint32(100), mr.RemainderLength)
}

// --- Chunk handler tests ---

func TestChunkSendNoState(t *testing.T) {
	r := newTestResponder()
	r.version = 0x12

	// Send a non-first chunk without prior chunk 0 -> error.
	req := &msgs.ChunkSend{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestChunkSend),
			Param2:              1,
		}},
		ChunkSeqNo: 1,
		ChunkSize:  4,
		Chunk:      []byte("data"),
	}
	reqData, _ := req.Marshal()
	resp, _ := r.ProcessMessage(context.Background(), reqData)
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorInvalidRequest, errResp.ErrorCode())
}

func TestChunkGetNoState(t *testing.T) {
	r := newTestResponder()
	r.version = 0x12

	req := &msgs.ChunkGet{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestChunkGet),
		}},
		ChunkSeqNo: 0,
	}
	reqData, _ := req.Marshal()
	resp, _ := r.ProcessMessage(context.Background(), reqData)
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnsupportedRequest, errResp.ErrorCode())
}

func TestChunkSendReassemble(t *testing.T) {
	r := newTestResponder()
	r.version = 0x12
	ctx := context.Background()

	// Build a valid GET_VERSION as the "large message" to reassemble.
	getVer := &msgs.GetVersion{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x10,
			RequestResponseCode: uint8(codes.RequestGetVersion),
		}},
	}
	getVerData, _ := getVer.Marshal()

	// First chunk with seq=0 starts reassembly.
	req0 := &msgs.ChunkSend{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestChunkSend),
			Param1:              msgs.ChunkSendAttrLastChunk, // single chunk
			Param2:              1,
		}},
		ChunkSeqNo:       0,
		LargeMessageSize: uint32(len(getVerData)),
		ChunkSize:        uint32(len(getVerData)),
		Chunk:            getVerData,
	}
	reqData, _ := req0.Marshal()
	resp, err := r.ProcessMessage(ctx, reqData)
	require.NoError(t, err)

	// The ACK should contain the inner response.
	var ack msgs.ChunkSendAck
	require.NoError(t, ack.Unmarshal(resp))
	assert.Equal(t, uint8(codes.ResponseChunkSendAck), ack.Header.RequestResponseCode)
	// The response embedded in ACK should be an error (no versions configured)
	// or a VERSION response. Either way, it should be valid.
	require.True(t, len(ack.Response) >= msgs.HeaderSize)
}

// --- Unmarshal error tests for new handlers ---

func TestCSRUnmarshalError(t *testing.T) {
	r := newTestResponder()
	r.cfg.CSRProvider = &mockCSRProvider{csr: []byte("csr")}
	negotiateResponder(t, r)

	// Too-short data for GET_CSR (needs HeaderSize+4=8 bytes).
	resp, _ := r.ProcessMessage(context.Background(), []byte{0x12, uint8(codes.RequestGetCSR), 0, 0})
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorInvalidRequest, errResp.ErrorCode())
}

func TestGetKeyPairInfoUnmarshalError(t *testing.T) {
	r := newTestResponder()
	r.cfg.ProvisioningProvider = &mockProvisioningProvider{
		keyPairInfo: &msgs.KeyPairInfoResponse{TotalKeyPairs: 1},
	}
	negotiateResponder(t, r)

	// Too-short data for GET_KEY_PAIR_INFO (needs HeaderSize+1=5 bytes).
	resp, _ := r.ProcessMessage(context.Background(), []byte{0x12, uint8(codes.RequestGetKeyPairInfo), 0, 0})
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorInvalidRequest, errResp.ErrorCode())
}

func TestGetMELUnmarshalError(t *testing.T) {
	r := newTestResponder()
	r.cfg.MELProvider = &mockMELProvider{portion: []byte("mel")}
	negotiateResponder(t, r)

	// Too-short data for GET_MEL (needs HeaderSize+8=12 bytes).
	resp, _ := r.ProcessMessage(context.Background(), []byte{0x12, uint8(codes.RequestGetMeasurementExtensionLog), 0, 0})
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorInvalidRequest, errResp.ErrorCode())
}
