package spdm

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/spdm/internal/testutil"
	"github.com/xaionaro-go/spdm/pkg/crypto/stdlib"
	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/caps"
	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
)

// --- Mock providers ---

type mockCertProv struct{}

func (m *mockCertProv) CertChain(_ context.Context, _ uint8) ([]byte, error) {
	return []byte{0x01}, nil
}
func (m *mockCertProv) DigestForSlot(_ context.Context, _ uint8) ([]byte, error) {
	return make([]byte, 32), nil
}

// realCertProv provides a proper SPDM-formatted certificate chain for tests that verify signatures.
type realCertProv struct {
	chain  []byte
	digest []byte
}

func (m *realCertProv) CertChain(_ context.Context, _ uint8) ([]byte, error) {
	return m.chain, nil
}
func (m *realCertProv) DigestForSlot(_ context.Context, _ uint8) ([]byte, error) {
	return m.digest, nil
}

type mockMeasProv struct{}

func (m *mockMeasProv) Collect(_ context.Context, _ uint8) ([]msgs.MeasurementBlock, error) {
	return nil, nil
}
func (m *mockMeasProv) SummaryHash(_ context.Context, _ uint8) ([]byte, error) {
	return make([]byte, 32), nil
}

type mockCSRProv struct{}

func (m *mockCSRProv) GenerateCSR(_ context.Context, _, _ []byte) ([]byte, error) {
	return []byte("csr"), nil
}

type mockProvProv struct{}

func (m *mockProvProv) SetCertificate(_ context.Context, _ uint8, _ []byte) error {
	return nil
}
func (m *mockProvProv) GetKeyPairInfo(_ context.Context, _ uint8) (*msgs.KeyPairInfoResponse, error) {
	return &msgs.KeyPairInfoResponse{}, nil
}
func (m *mockProvProv) SetKeyPairInfo(_ context.Context, _ uint8, _ uint8, _ uint16, _ uint32, _ []byte) error {
	return nil
}

type mockEIProv struct{}

func (m *mockEIProv) GetEndpointInfo(_ context.Context, _ uint8) ([]byte, error) {
	return []byte("info"), nil
}

type mockMELProv struct{}

func (m *mockMELProv) GetMEL(_ context.Context, _, _ uint32) ([]byte, uint32, error) {
	return []byte("mel"), 0, nil
}

type mockPSKProv struct{}

func (m *mockPSKProv) Lookup(_ context.Context, _ []byte) ([]byte, error) {
	return []byte("psk"), nil
}

// --- NewRequester ---

func TestNewRequester(t *testing.T) {
	reqSide, _ := testutil.NewLoopbackPair()
	r := NewRequester(RequesterConfig{
		Versions:     []algo.Version{algo.Version12},
		Transport:    reqSide,
		Crypto:       *stdlib.NewSuite(nil, nil),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})
	require.NotNil(t, r)
	require.NotNil(t, r.inner)
}

func TestNewRequesterWithPSK(t *testing.T) {
	reqSide, _ := testutil.NewLoopbackPair()
	r := NewRequester(RequesterConfig{
		Versions:     []algo.Version{algo.Version12},
		Transport:    reqSide,
		Crypto:       *stdlib.NewSuite(nil, nil),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
		PSKProvider:  &mockPSKProv{},
	})
	require.NotNil(t, r)
}

// --- NewResponder ---

func TestNewResponder(t *testing.T) {
	_, rspSide := testutil.NewLoopbackPair()
	r := NewResponder(ResponderConfig{
		Versions:     []algo.Version{algo.Version12},
		Transport:    rspSide,
		Crypto:       *stdlib.NewSuite(nil, nil),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})
	require.NotNil(t, r)
	require.NotNil(t, r.inner)
}

func TestNewResponderWithProviders(t *testing.T) {
	_, rspSide := testutil.NewLoopbackPair()
	r := NewResponder(ResponderConfig{
		Versions:     []algo.Version{algo.Version12},
		Transport:    rspSide,
		Crypto:       *stdlib.NewSuite(nil, nil),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
		CertProvider: &mockCertProv{},
		MeasProvider: &mockMeasProv{},
	})
	require.NotNil(t, r)
}

func TestNewResponderAllProviders(t *testing.T) {
	_, rspSide := testutil.NewLoopbackPair()
	r := NewResponder(ResponderConfig{
		Versions:             []algo.Version{algo.Version12},
		Transport:            rspSide,
		Crypto:               *stdlib.NewSuite(nil, nil),
		BaseAsymAlgo:         algo.AsymECDSAP256,
		BaseHashAlgo:         algo.HashSHA256,
		CertProvider:         &mockCertProv{},
		MeasProvider:         &mockMeasProv{},
		PSKProvider:          &mockPSKProv{},
		CSRProvider:          &mockCSRProv{},
		ProvisioningProvider: &mockProvProv{},
		EndpointInfoProvider: &mockEIProv{},
		MELProvider:          &mockMELProv{},
	})
	require.NotNil(t, r)
}

func TestNewResponderNilProviders(t *testing.T) {
	_, rspSide := testutil.NewLoopbackPair()
	r := NewResponder(ResponderConfig{
		Versions:     []algo.Version{algo.Version12},
		Transport:    rspSide,
		Crypto:       *stdlib.NewSuite(nil, nil),
		CertProvider: nil,
		MeasProvider: nil,
	})
	require.NotNil(t, r)
}

// --- Integration test: InitConnection via loopback ---

func TestInitConnectionLoopback(t *testing.T) {
	reqSide, rspSide := testutil.NewLoopbackPair()

	rootPool, rootCert, leafCert, leafKey := testutil.TestCertsWithRoot(t, "ecdsa-p256")
	certChain := testutil.BuildSPDMCertChain(sha256.New, rootCert, leafCert)
	digest := sha256.Sum256(certChain)

	reqCfg := RequesterConfig{
		Versions:         []algo.Version{algo.Version12},
		Transport:        reqSide,
		Crypto:           *stdlib.NewSuite(leafKey, rootPool),
		Caps:             caps.ReqCertCap | caps.ReqChalCap,
		BaseAsymAlgo:     algo.AsymECDSAP256,
		BaseHashAlgo:     algo.HashSHA256,
		DHEGroups:        algo.DHESECP256R1,
		AEADSuites:       algo.AEADAES256GCM,
		DataTransferSize: 4096,
		MaxSPDMmsgSize:   65536,
	}

	rspCfg := ResponderConfig{
		Versions:         []algo.Version{algo.Version12},
		Transport:        rspSide,
		Crypto:           *stdlib.NewSuite(leafKey, nil),
		Caps:             caps.RspCertCap | caps.RspChalCap,
		BaseAsymAlgo:     algo.AsymECDSAP256,
		BaseHashAlgo:     algo.HashSHA256,
		DHEGroups:        algo.DHESECP256R1,
		AEADSuites:       algo.AEADAES256GCM,
		DataTransferSize: 4096,
		MaxSPDMmsgSize:   65536,
		CertProvider: &realCertProv{
			chain:  certChain,
			digest: digest[:],
		},
		MeasProvider: &mockMeasProv{},
	}

	req := NewRequester(reqCfg)
	rsp := NewResponder(rspCfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Run responder Serve in the background.
	errCh := make(chan error, 1)
	go func() {
		errCh <- rsp.Serve(ctx)
	}()

	ci, err := req.InitConnection(ctx)
	require.NoError(t, err)
	require.NotNil(t, ci)
	assert.Equal(t, algo.Version12, ci.Version)
	assert.Equal(t, algo.HashSHA256, ci.HashAlgo)
	assert.Equal(t, algo.AsymECDSAP256, ci.AsymAlgo)

	// After InitConnection, test GetDigests.
	digests, err := req.GetDigests(ctx)
	require.NoError(t, err)
	require.NotNil(t, digests)

	// Test GetCertificate.
	cert, err := req.GetCertificate(ctx, 0)
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.Equal(t, uint8(0), cert.SlotID)

	// Test Challenge.
	cr, err := req.Challenge(ctx, 0)
	require.NoError(t, err)
	require.NotNil(t, cr)
	assert.Equal(t, uint8(0), cr.SlotID)

	// Test GetMeasurements.
	meas, err := req.GetMeasurements(ctx, MeasurementOpts{Index: 0})
	require.NoError(t, err)
	require.NotNil(t, meas)

	cancel()
}

// --- ProcessMessage test ---

func TestProcessMessageGetVersion(t *testing.T) {
	_, rspSide := testutil.NewLoopbackPair()
	rsp := NewResponder(ResponderConfig{
		Versions:     []algo.Version{algo.Version12},
		Transport:    rspSide,
		Crypto:       *stdlib.NewSuite(nil, nil),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	// Build a GET_VERSION request manually.
	reqMsg := []byte{0x10, 0x84, 0x00, 0x00} // version=1.0, code=GET_VERSION
	resp, err := rsp.ProcessMessage(context.Background(), reqMsg)
	require.NoError(t, err)
	require.True(t, len(resp) >= 4, "response too short")
	// Response code should be VERSION (0x04).
	assert.Equal(t, byte(0x04), resp[1])
}

func TestProcessMessageTooShort(t *testing.T) {
	_, rspSide := testutil.NewLoopbackPair()
	rsp := NewResponder(ResponderConfig{
		Versions:  []algo.Version{algo.Version12},
		Transport: rspSide,
		Crypto:    *stdlib.NewSuite(nil, nil),
	})

	// Too short to contain a header.
	resp, err := rsp.ProcessMessage(context.Background(), []byte{0x10})
	require.NoError(t, err)
	// Should return an ERROR response.
	require.True(t, len(resp) >= 4, "response too short")
	assert.Equal(t, byte(0x7F), resp[1]) // ResponseError = 0x7F
}

func TestProcessMessageUnsupportedRequest(t *testing.T) {
	_, rspSide := testutil.NewLoopbackPair()
	rsp := NewResponder(ResponderConfig{
		Versions:  []algo.Version{algo.Version12},
		Transport: rspSide,
		Crypto:    *stdlib.NewSuite(nil, nil),
	})

	// Unknown request code.
	reqMsg := []byte{0x12, 0xFF, 0x00, 0x00}
	resp, err := rsp.ProcessMessage(context.Background(), reqMsg)
	require.NoError(t, err)
	assert.Equal(t, byte(0x7F), resp[1])
}

// --- Facade error path tests ---

func TestInitConnectionError(t *testing.T) {
	reqSide, _ := testutil.NewLoopbackPair()
	req := NewRequester(RequesterConfig{
		Versions:     []algo.Version{algo.Version12},
		Transport:    reqSide,
		Crypto:       *stdlib.NewSuite(nil, nil),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := req.InitConnection(ctx)
	require.Error(t, err)
}

func TestGetDigestsError(t *testing.T) {
	reqSide, rspSide := testutil.NewLoopbackPair()

	req := NewRequester(RequesterConfig{
		Versions:     []algo.Version{algo.Version12},
		Transport:    reqSide,
		Crypto:       *stdlib.NewSuite(nil, nil),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	// Cancel context so sendReceive fails.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_ = rspSide // keep reference

	_, err := req.GetDigests(ctx)
	require.Error(t, err)
}

func TestGetCertificateError(t *testing.T) {
	reqSide, _ := testutil.NewLoopbackPair()
	req := NewRequester(RequesterConfig{
		Versions:     []algo.Version{algo.Version12},
		Transport:    reqSide,
		Crypto:       *stdlib.NewSuite(nil, nil),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := req.GetCertificate(ctx, 0)
	require.Error(t, err)
}

func TestChallengeError(t *testing.T) {
	reqSide, _ := testutil.NewLoopbackPair()
	req := NewRequester(RequesterConfig{
		Versions:     []algo.Version{algo.Version12},
		Transport:    reqSide,
		Crypto:       *stdlib.NewSuite(nil, nil),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := req.Challenge(ctx, 0)
	require.Error(t, err)
}

func TestGetMeasurementsError(t *testing.T) {
	reqSide, _ := testutil.NewLoopbackPair()
	req := NewRequester(RequesterConfig{
		Versions:     []algo.Version{algo.Version12},
		Transport:    reqSide,
		Crypto:       *stdlib.NewSuite(nil, nil),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := req.GetMeasurements(ctx, MeasurementOpts{Index: 1})
	require.Error(t, err)
}

// --- Facade error path tests for remaining wrapper methods ---

func TestKeyExchangeError(t *testing.T) {
	reqSide, _ := testutil.NewLoopbackPair()
	req := NewRequester(RequesterConfig{
		Versions:     []algo.Version{algo.Version12},
		Transport:    reqSide,
		Crypto:       *stdlib.NewSuite(nil, nil),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := req.KeyExchange(ctx, KeyExchangeOpts{SlotID: 0, HashType: 0xFF})
	require.Error(t, err)
}

func TestPSKExchangeError(t *testing.T) {
	reqSide, _ := testutil.NewLoopbackPair()
	req := NewRequester(RequesterConfig{
		Versions:     []algo.Version{algo.Version12},
		Transport:    reqSide,
		Crypto:       *stdlib.NewSuite(nil, nil),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := req.PSKExchange(ctx, []byte("hint"))
	require.Error(t, err)
}

func TestGetCSRError(t *testing.T) {
	reqSide, _ := testutil.NewLoopbackPair()
	req := NewRequester(RequesterConfig{
		Versions:     []algo.Version{algo.Version12},
		Transport:    reqSide,
		Crypto:       *stdlib.NewSuite(nil, nil),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := req.GetCSR(ctx, nil, nil)
	require.Error(t, err)
}

func TestSetCertificateError(t *testing.T) {
	reqSide, _ := testutil.NewLoopbackPair()
	req := NewRequester(RequesterConfig{
		Versions:     []algo.Version{algo.Version12},
		Transport:    reqSide,
		Crypto:       *stdlib.NewSuite(nil, nil),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := req.SetCertificate(ctx, 0, []byte("cert"))
	require.Error(t, err)
}

func TestGetKeyPairInfoError(t *testing.T) {
	reqSide, _ := testutil.NewLoopbackPair()
	req := NewRequester(RequesterConfig{
		Versions:     []algo.Version{algo.Version12},
		Transport:    reqSide,
		Crypto:       *stdlib.NewSuite(nil, nil),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := req.GetKeyPairInfo(ctx, 0)
	require.Error(t, err)
}

func TestGetEndpointInfoError(t *testing.T) {
	reqSide, _ := testutil.NewLoopbackPair()
	req := NewRequester(RequesterConfig{
		Versions:     []algo.Version{algo.Version12},
		Transport:    reqSide,
		Crypto:       *stdlib.NewSuite(nil, nil),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := req.GetEndpointInfo(ctx, 0)
	require.Error(t, err)
}

func TestVendorDefinedRequestError(t *testing.T) {
	reqSide, _ := testutil.NewLoopbackPair()
	req := NewRequester(RequesterConfig{
		Versions:     []algo.Version{algo.Version12},
		Transport:    reqSide,
		Crypto:       *stdlib.NewSuite(nil, nil),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := req.VendorDefinedRequest(ctx, 1, []byte{0x01}, []byte{0x02})
	require.Error(t, err)
}

func TestGetMeasurementExtensionLogError(t *testing.T) {
	reqSide, _ := testutil.NewLoopbackPair()
	req := NewRequester(RequesterConfig{
		Versions:     []algo.Version{algo.Version12},
		Transport:    reqSide,
		Crypto:       *stdlib.NewSuite(nil, nil),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := req.GetMeasurementExtensionLog(ctx, 0, 100)
	require.Error(t, err)
}

func TestSetKeyPairInfoError(t *testing.T) {
	reqSide, _ := testutil.NewLoopbackPair()
	req := NewRequester(RequesterConfig{
		Versions:     []algo.Version{algo.Version12},
		Transport:    reqSide,
		Crypto:       *stdlib.NewSuite(nil, nil),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := req.SetKeyPairInfo(ctx, 1, 0, 0, 0, 0, nil)
	require.Error(t, err)
}

func TestGetEncapsulatedRequestError(t *testing.T) {
	reqSide, _ := testutil.NewLoopbackPair()
	req := NewRequester(RequesterConfig{
		Versions:     []algo.Version{algo.Version12},
		Transport:    reqSide,
		Crypto:       *stdlib.NewSuite(nil, nil),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := req.GetEncapsulatedRequest(ctx)
	require.Error(t, err)
}

func TestDeliverEncapsulatedResponseError(t *testing.T) {
	reqSide, _ := testutil.NewLoopbackPair()
	req := NewRequester(RequesterConfig{
		Versions:     []algo.Version{algo.Version12},
		Transport:    reqSide,
		Crypto:       *stdlib.NewSuite(nil, nil),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := req.DeliverEncapsulatedResponse(ctx, 1, []byte("data"))
	require.Error(t, err)
}

func TestGetSupportedEventTypesError(t *testing.T) {
	reqSide, _ := testutil.NewLoopbackPair()
	req := NewRequester(RequesterConfig{
		Versions:     []algo.Version{algo.Version12},
		Transport:    reqSide,
		Crypto:       *stdlib.NewSuite(nil, nil),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := req.GetSupportedEventTypes(ctx)
	require.Error(t, err)
}

func TestSubscribeEventTypesError(t *testing.T) {
	reqSide, _ := testutil.NewLoopbackPair()
	req := NewRequester(RequesterConfig{
		Versions:     []algo.Version{algo.Version12},
		Transport:    reqSide,
		Crypto:       *stdlib.NewSuite(nil, nil),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := req.SubscribeEventTypes(ctx, []byte("groups"))
	require.Error(t, err)
}

func TestSendEventError(t *testing.T) {
	reqSide, _ := testutil.NewLoopbackPair()
	req := NewRequester(RequesterConfig{
		Versions:     []algo.Version{algo.Version12},
		Transport:    reqSide,
		Crypto:       *stdlib.NewSuite(nil, nil),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := req.SendEvent(ctx, []byte("event"))
	require.Error(t, err)
}

func TestRespondIfReadyError(t *testing.T) {
	reqSide, _ := testutil.NewLoopbackPair()
	req := NewRequester(RequesterConfig{
		Versions:     []algo.Version{algo.Version12},
		Transport:    reqSide,
		Crypto:       *stdlib.NewSuite(nil, nil),
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA256,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := req.RespondIfReady(ctx, codes.RequestCode(0x84), 42)
	require.Error(t, err)
}

// --- Session nil-check tests ---

func TestSessionSendReceiveNilSession(t *testing.T) {
	s := &Session{}
	_, err := s.SendReceive(context.Background(), []byte("data"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session not initialized")
}

func TestSessionHeartbeatNilSession(t *testing.T) {
	s := &Session{}
	err := s.Heartbeat(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session not initialized")
}

func TestSessionKeyUpdateNilSession(t *testing.T) {
	s := &Session{}
	err := s.KeyUpdate(context.Background(), KeyUpdateUpdateKey)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session not initialized")
}

func TestSessionCloseNilSession(t *testing.T) {
	s := &Session{}
	err := s.Close(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session not initialized")
}
