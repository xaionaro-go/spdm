package requester

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

func newNegotiatedRequesterFromResponses(responses [][]byte) *Requester {
	return newNegotiatedRequester(&mockTransport{responses: responses})
}

// --- VendorDefinedRequest tests ---

func TestVendorDefinedRequest(t *testing.T) {
	resp := &msgs.VendorDefinedResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseVendorDefined),
		}},
		StandardID: 0x42,
		VendorID:   []byte{0xAA},
		Payload:    []byte("hello"),
	}
	respData, _ := resp.Marshal()

	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	vr, err := r.VendorDefinedRequest(context.Background(), 0x42, []byte{0xAA}, []byte("test"))
	require.NoError(t, err)
	assert.Equal(t, uint16(0x42), vr.StandardID)
	assert.Equal(t, []byte("hello"), vr.Payload)
}

func TestVendorDefinedRequestError(t *testing.T) {
	errResp := &msgs.ErrorResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseError),
			Param1:              uint8(codes.ErrorUnsupportedRequest),
		}},
	}
	respData, _ := errResp.Marshal()

	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	_, err := r.VendorDefinedRequest(context.Background(), 0x42, nil, nil)
	require.Error(t, err)
}

// --- GetCSR tests ---

func TestGetCSR(t *testing.T) {
	csrBytes := []byte("fake-csr-data")
	resp := &msgs.CSRResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseCSR),
		}},
		CSR: csrBytes,
	}
	respData, _ := resp.Marshal()

	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	csr, err := r.GetCSR(context.Background(), []byte("info"), []byte("opaque"))
	require.NoError(t, err)
	assert.Equal(t, csrBytes, csr)
}

func TestGetCSRError(t *testing.T) {
	errResp := &msgs.ErrorResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseError),
			Param1:              uint8(codes.ErrorUnsupportedRequest),
		}},
	}
	respData, _ := errResp.Marshal()

	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	_, err := r.GetCSR(context.Background(), nil, nil)
	require.Error(t, err)
}

// --- SetCertificate tests ---

func TestSetCertificate(t *testing.T) {
	resp := &msgs.SetCertificateResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseSetCertificateRsp),
		}},
	}
	respData, _ := resp.Marshal()

	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	err := r.SetCertificate(context.Background(), 0, []byte("cert-chain"))
	require.NoError(t, err)
}

func TestSetCertificateError(t *testing.T) {
	errResp := &msgs.ErrorResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseError),
			Param1:              uint8(codes.ErrorUnsupportedRequest),
		}},
	}
	respData, _ := errResp.Marshal()

	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	err := r.SetCertificate(context.Background(), 0, nil)
	require.Error(t, err)
}

// --- GetKeyPairInfo tests ---

func TestGetKeyPairInfo(t *testing.T) {
	resp := &msgs.KeyPairInfoResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseKeyPairInfo),
		}},
		TotalKeyPairs: 2,
		KeyPairID:     1,
	}
	respData, _ := resp.Marshal()

	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	kpr, err := r.GetKeyPairInfo(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, uint8(2), kpr.TotalKeyPairs)
	assert.Equal(t, uint8(1), kpr.KeyPairID)
}

// --- GetEndpointInfo tests ---

func TestGetEndpointInfo(t *testing.T) {
	resp := &msgs.EndpointInfoResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseEndpointInfo),
		}},
		EndpointInfo: []byte("endpoint-data"),
	}
	respData, _ := resp.Marshal()

	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	info, err := r.GetEndpointInfo(context.Background(), 0x01)
	require.NoError(t, err)
	assert.Equal(t, []byte("endpoint-data"), info)
}

// --- GetMeasurementExtensionLog tests ---

func TestGetMeasurementExtensionLog(t *testing.T) {
	resp := &msgs.MeasurementExtensionLogResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseMeasurementExtensionLog),
		}},
		MEL:             []byte("mel-data"),
		RemainderLength: 0,
	}
	respData, _ := resp.Marshal()

	r := newNegotiatedRequesterFromResponses([][]byte{respData})
	mr, err := r.GetMeasurementExtensionLog(context.Background(), 0, 1024)
	require.NoError(t, err)
	assert.Equal(t, []byte("mel-data"), mr.MEL)
	assert.Equal(t, uint32(0), mr.RemainderLength)
}

// --- ChunkSend tests ---

func TestChunkSendSingleChunk(t *testing.T) {
	ack := &msgs.ChunkSendAck{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseChunkSendAck),
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

	err := r.ChunkSend(context.Background(), 1, []byte("small message"))
	require.NoError(t, err)
}

func TestChunkSendMultipleChunks(t *testing.T) {
	// DataTransferSize=32, overhead for first=16, rest=12, so first chunk=16 bytes, rest=20 bytes.
	ack0 := &msgs.ChunkSendAck{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseChunkSendAck),
		}},
		ChunkSeqNo: 0,
	}
	ack1 := &msgs.ChunkSendAck{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseChunkSendAck),
		}},
		ChunkSeqNo: 1,
	}
	ack0Data, _ := ack0.Marshal()
	ack1Data, _ := ack1.Marshal()

	r := New(Config{
		Versions:         []algo.Version{algo.Version12},
		Transport:        &mockTransport{responses: [][]byte{ack0Data, ack1Data}},
		DataTransferSize: 32,
	})
	r.conn.PeerVersion = algo.Version12

	// 30 bytes: first chunk=16, second chunk=14
	err := r.ChunkSend(context.Background(), 1, make([]byte, 30))
	require.NoError(t, err)
}

// --- ChunkGet tests ---

func TestChunkGetSingleChunk(t *testing.T) {
	cr := &msgs.ChunkResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseChunkResponse),
			Param1:              msgs.ChunkResponseAttrLastChunk,
		}},
		ChunkSeqNo:       0,
		LargeMessageSize: 10,
		Chunk:            []byte("0123456789"),
	}
	crData, _ := cr.Marshal()

	r := newNegotiatedRequesterFromResponses([][]byte{crData})
	result, err := r.ChunkGet(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, []byte("0123456789"), result)
}

func TestChunkGetMultipleChunks(t *testing.T) {
	cr0 := &msgs.ChunkResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseChunkResponse),
		}},
		ChunkSeqNo:       0,
		LargeMessageSize: 8,
		Chunk:            []byte("ABCD"),
	}
	cr1 := &msgs.ChunkResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseChunkResponse),
			Param1:              msgs.ChunkResponseAttrLastChunk,
		}},
		ChunkSeqNo: 1,
		Chunk:      []byte("EFGH"),
	}
	cr0Data, _ := cr0.Marshal()
	cr1Data, _ := cr1.Marshal()

	r := newNegotiatedRequesterFromResponses([][]byte{cr0Data, cr1Data})
	result, err := r.ChunkGet(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, []byte("ABCDEFGH"), result)
}
