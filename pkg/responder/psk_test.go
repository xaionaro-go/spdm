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

// mockPSKProvider implements crypto.PSKProvider for testing.
type mockPSKProvider struct {
	psk []byte
	err error
}

func (m *mockPSKProvider) Lookup(_ context.Context, _ []byte) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.psk, nil
}

func TestHandlePSKExchange_NoPSKProvider(t *testing.T) {
	r := newTestResponder()
	negotiateResponder(t, r)

	req := &msgs.PSKExchange{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestPSKExchange),
		}},
		ReqSessionID: 0x1234,
		PSKHint:      []byte("test-hint"),
		Context:      make([]byte, 32),
		OpaqueData:   []byte{},
	}
	reqData, _ := req.Marshal()

	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnsupportedRequest, errResp.ErrorCode())
}

func TestHandlePSKExchange_NotNegotiated(t *testing.T) {
	r := newTestResponder()
	// Don't call negotiateResponder — state is not negotiated.

	req := &msgs.PSKExchange{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestPSKExchange),
		}},
		ReqSessionID: 0x1234,
	}
	reqData, _ := req.Marshal()

	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnexpectedRequest, errResp.ErrorCode())
}

func TestHandlePSKExchange_PSKLookupFails(t *testing.T) {
	r := newTestResponder()
	r.cfg.PSKProvider = &mockPSKProvider{err: fmt.Errorf("no such key")}
	negotiateResponder(t, r)

	req := &msgs.PSKExchange{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestPSKExchange),
		}},
		ReqSessionID: 0x1234,
		PSKHint:      []byte("unknown"),
		Context:      make([]byte, 32),
		OpaqueData:   []byte{},
	}
	reqData, _ := req.Marshal()

	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnspecified, errResp.ErrorCode())
}

func TestHandlePSKFinish_NoPending(t *testing.T) {
	r := newTestResponder()
	r.cfg.PSKProvider = &mockPSKProvider{psk: make([]byte, 32)}
	negotiateResponder(t, r)

	req := &msgs.PSKFinish{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestPSKFinish),
		}},
		VerifyData: make([]byte, 32),
	}
	reqData, _ := req.Marshal()

	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnexpectedRequest, errResp.ErrorCode())
}

func TestHandlePSKExchange_Success(t *testing.T) {
	r := newTestResponder()
	r.cfg.PSKProvider = &mockPSKProvider{psk: make([]byte, 32)}
	negotiateResponder(t, r)

	req := &msgs.PSKExchange{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestPSKExchange),
			Param1:              msgs.NoMeasurementSummaryHash,
		}},
		ReqSessionID: 0x1234,
		PSKHint:      []byte("test"),
		Context:      make([]byte, 32),
		OpaqueData:   buildKeyExchangeOpaqueData(),
	}
	reqData, _ := req.Marshal()

	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), msgs.HeaderSize)
	assert.Equal(t, uint8(codes.ResponsePSKExchangeRsp), resp[1])

	// After PSK_EXCHANGE, there should be a pending PSK session.
	require.NotNil(t, r.pendingPSK)
}
