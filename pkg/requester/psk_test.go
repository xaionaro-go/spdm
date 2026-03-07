package requester

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/caps"
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

func TestPSKExchange_NoPSKProvider(t *testing.T) {
	r := New(Config{
		Versions:     []algo.Version{algo.Version12},
		Caps:         caps.ReqPSKCapRequester,
		BaseHashAlgo: algo.HashSHA256,
		AEADSuites:   algo.AEADAES128GCM,
	})
	// Set connection state as if negotiation happened.
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256
	r.conn.AEADSuite = algo.AEADAES128GCM

	_, err := r.PSKExchange(context.Background(), []byte("hint"))
	require.Error(t, err, "should fail without PSKProvider")
	assert.Contains(t, err.Error(), "PSKProvider not configured")
}

func TestPSKExchange_PSKLookupError(t *testing.T) {
	r := New(Config{
		Versions:     []algo.Version{algo.Version12},
		Caps:         caps.ReqPSKCapRequester,
		BaseHashAlgo: algo.HashSHA256,
		AEADSuites:   algo.AEADAES128GCM,
		PSKProvider:  &mockPSKProvider{err: assert.AnError},
	})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256
	r.conn.AEADSuite = algo.AEADAES128GCM

	_, err := r.PSKExchange(context.Background(), []byte("hint"))
	require.Error(t, err, "should fail on PSK lookup error")
	assert.Contains(t, err.Error(), "PSK lookup")
}

func TestPSKExchange_TransportError(t *testing.T) {
	mt := &mockTransport{recvErr: assert.AnError}
	r := New(Config{
		Versions:     []algo.Version{algo.Version12},
		Caps:         caps.ReqPSKCapRequester,
		BaseHashAlgo: algo.HashSHA256,
		AEADSuites:   algo.AEADAES128GCM,
		PSKProvider:  &mockPSKProvider{psk: make([]byte, 32)},
		Transport:    mt,
	})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256
	r.conn.AEADSuite = algo.AEADAES128GCM

	_, err := r.PSKExchange(context.Background(), []byte("hint"))
	require.Error(t, err, "should fail on transport error")
}

func TestPSKExchange_ErrorResponse(t *testing.T) {
	// Build an error response.
	errResp := &msgs.ErrorResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.ResponseError),
			Param1:              uint8(codes.ErrorUnsupportedRequest),
		}},
	}
	errRespBytes, _ := errResp.Marshal()

	mt := &mockTransport{responses: [][]byte{errRespBytes}}
	r := New(Config{
		Versions:     []algo.Version{algo.Version12},
		Caps:         caps.ReqPSKCapRequester,
		BaseHashAlgo: algo.HashSHA256,
		AEADSuites:   algo.AEADAES128GCM,
		PSKProvider:  &mockPSKProvider{psk: make([]byte, 32)},
		Transport:    mt,
	})
	r.conn.PeerVersion = algo.Version12
	r.conn.HashAlgo = algo.HashSHA256
	r.conn.AEADSuite = algo.AEADAES128GCM

	_, err := r.PSKExchange(context.Background(), []byte("hint"))
	require.Error(t, err, "should fail on error response")
}
