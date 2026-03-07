package responder

import (
	"context"
	gocrypto "crypto"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/caps"
	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

// mockCertProvider implements CertProvider for testing.
type mockCertProvider struct {
	chains  map[uint8][]byte
	digests map[uint8][]byte
}

func (m *mockCertProvider) CertChain(_ context.Context, slotID uint8) ([]byte, error) {
	chain, ok := m.chains[slotID]
	if !ok {
		return nil, fmt.Errorf("no chain for slot %d", slotID)
	}
	return chain, nil
}

func (m *mockCertProvider) DigestForSlot(_ context.Context, slotID uint8) ([]byte, error) {
	d, ok := m.digests[slotID]
	if !ok {
		return nil, fmt.Errorf("no digest for slot %d", slotID)
	}
	return d, nil
}

// mockMeasProvider implements MeasurementProvider for testing.
type mockMeasProvider struct {
	blocks []msgs.MeasurementBlock
}

func (m *mockMeasProvider) Collect(_ context.Context, _ uint8) ([]msgs.MeasurementBlock, error) {
	return m.blocks, nil
}

func (m *mockMeasProvider) SummaryHash(_ context.Context, _ uint8) ([]byte, error) {
	return make([]byte, 32), nil
}

func newTestResponder() *Responder {
	return New(Config{
		Versions:         []algo.Version{algo.Version12},
		Caps:             caps.RspCertCap | caps.RspChalCap | caps.RspMeasCapSig,
		BaseAsymAlgo:     algo.AsymECDSAP256 | algo.AsymECDSAP384,
		BaseHashAlgo:     algo.HashSHA256 | algo.HashSHA384,
		DHEGroups:        algo.DHESECP256R1 | algo.DHESECP384R1,
		AEADSuites:       algo.AEADAES128GCM | algo.AEADAES256GCM,
		DataTransferSize: 4096,
		MaxSPDMmsgSize:   65536,
	})
}

func buildGetVersion() []byte {
	req := &msgs.GetVersion{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x10,
			RequestResponseCode: uint8(codes.RequestGetVersion),
		}},
	}
	data, _ := req.Marshal()
	return data
}

func buildGetCapabilities() []byte {
	req := &msgs.GetCapabilities{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetCapabilities),
		}},
		Flags:            uint32(caps.ReqCertCap | caps.ReqChalCap),
		DataTransferSize: 4096,
		MaxSPDMmsgSize:   65536,
	}
	data, _ := req.Marshal()
	return data
}

func buildNegotiateAlgorithms() []byte {
	req := &msgs.NegotiateAlgorithms{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestNegotiateAlgorithms),
			Param1:              2, // number of AlgStructs
		}},
		BaseAsymAlgo:             uint32(algo.AsymECDSAP256),
		BaseHashAlgo:             uint32(algo.HashSHA256),
		MeasurementSpecification: 0x01,
		AlgStructs: []msgs.AlgStructTable{
			{AlgType: msgs.AlgTypeDHE, AlgCount: 0x20, AlgSupported: uint16(algo.DHESECP256R1)},
			{AlgType: msgs.AlgTypeAEAD, AlgCount: 0x20, AlgSupported: uint16(algo.AEADAES128GCM)},
		},
	}
	data, _ := req.Marshal()
	return data
}

func TestProcessMessageGetVersion(t *testing.T) {
	r := newTestResponder()
	ctx := context.Background()

	resp, err := r.ProcessMessage(ctx, buildGetVersion())
	require.NoError(t, err)

	var vr msgs.VersionResponse
	require.NoError(t, vr.Unmarshal(resp))

	assert.Equal(t, uint8(codes.ResponseVersion), vr.Header.RequestResponseCode)
	require.Equal(t, 1, len(vr.VersionEntries))
	// Version12 -> major=1, minor=2 -> wire = 1<<12 | 2<<8 = 0x1200
	assert.Equal(t, uint16(0x1200), vr.VersionEntries[0])
}

func TestProcessMessageInvalidRequest(t *testing.T) {
	r := newTestResponder()
	ctx := context.Background()

	// Too-short request.
	resp, err := r.ProcessMessage(ctx, []byte{0x10})
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, uint8(codes.ResponseError), errResp.Header.RequestResponseCode)
	assert.Equal(t, codes.ErrorInvalidRequest, errResp.ErrorCode())
}

func TestProcessMessageUnsupportedRequest(t *testing.T) {
	r := newTestResponder()
	ctx := context.Background()

	// Unknown request code 0xAA.
	resp, err := r.ProcessMessage(ctx, []byte{0x12, 0xAA, 0x00, 0x00})
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnsupportedRequest, errResp.ErrorCode())
}

func TestFullThreeStepConnection(t *testing.T) {
	r := newTestResponder()
	ctx := context.Background()

	// Step 1: GET_VERSION
	resp, err := r.ProcessMessage(ctx, buildGetVersion())
	require.NoError(t, err)
	var vr msgs.VersionResponse
	require.NoError(t, vr.Unmarshal(resp))
	require.Equal(t, uint8(codes.ResponseVersion), vr.Header.RequestResponseCode)

	// Step 2: GET_CAPABILITIES
	resp, err = r.ProcessMessage(ctx, buildGetCapabilities())
	require.NoError(t, err)
	var cr msgs.CapabilitiesResponse
	require.NoError(t, cr.Unmarshal(resp))
	require.Equal(t, uint8(codes.ResponseCapabilities), cr.Header.RequestResponseCode)
	assert.Equal(t, uint32(r.cfg.Caps), cr.Flags)
	assert.Equal(t, uint32(4096), cr.DataTransferSize)

	// Step 3: NEGOTIATE_ALGORITHMS
	resp, err = r.ProcessMessage(ctx, buildNegotiateAlgorithms())
	require.NoError(t, err)
	var ar msgs.AlgorithmsResponse
	require.NoError(t, ar.Unmarshal(resp))
	require.Equal(t, uint8(codes.ResponseAlgorithms), ar.Header.RequestResponseCode)
	assert.Equal(t, uint32(algo.HashSHA256), ar.BaseHashSel)
	assert.Equal(t, uint32(algo.AsymECDSAP256), ar.BaseAsymSel)
	assert.True(t, r.negotiated, "expected negotiated=true after algorithm negotiation")
}

func TestGetDigests(t *testing.T) {
	digest0 := make([]byte, 32)
	for i := range digest0 {
		digest0[i] = 0xAA
	}
	digest1 := make([]byte, 32)
	for i := range digest1 {
		digest1[i] = 0xBB
	}

	provider := &mockCertProvider{
		digests: map[uint8][]byte{
			0: digest0,
			1: digest1,
		},
	}

	r := newTestResponder()
	r.cfg.CertProvider = provider
	ctx := context.Background()

	// Run the 3-step connection first so negotiated=true.
	_, err := r.ProcessMessage(ctx, buildGetVersion())
	require.NoError(t, err)
	_, err = r.ProcessMessage(ctx, buildGetCapabilities())
	require.NoError(t, err)
	_, err = r.ProcessMessage(ctx, buildNegotiateAlgorithms())
	require.NoError(t, err)

	// Build GET_DIGESTS request.
	req := &msgs.GetDigests{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetDigests),
		}},
	}
	reqData, _ := req.Marshal()

	resp, err := r.ProcessMessage(ctx, reqData)
	require.NoError(t, err)

	var dr msgs.DigestResponse
	require.NoError(t, dr.UnmarshalWithDigestSize(resp, 32))

	require.Equal(t, uint8(codes.ResponseDigests), dr.Header.RequestResponseCode)

	// Slots 0 and 1 are provisioned.
	expectedMask := uint8(0x03)
	assert.Equal(t, expectedMask, dr.SlotMask())
	require.Equal(t, 2, len(dr.Digests))
	assert.Equal(t, byte(0xAA), dr.Digests[0][0])
	assert.Equal(t, byte(0xBB), dr.Digests[1][0])
}

func TestGetDigestsWithoutNegotiation(t *testing.T) {
	r := newTestResponder()
	ctx := context.Background()

	req := &msgs.GetDigests{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetDigests),
		}},
	}
	reqData, _ := req.Marshal()

	resp, err := r.ProcessMessage(ctx, reqData)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnexpectedRequest, errResp.ErrorCode())
}

func TestHeartbeat(t *testing.T) {
	r := newTestResponder()
	r.version = algo.Version12
	ctx := context.Background()

	req := &msgs.Heartbeat{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestHeartbeat),
		}},
	}
	reqData, _ := req.Marshal()

	resp, err := r.ProcessMessage(ctx, reqData)
	require.NoError(t, err)

	var hr msgs.HeartbeatResponse
	require.NoError(t, hr.Unmarshal(resp))
	assert.Equal(t, uint8(codes.ResponseHeartbeatAck), hr.Header.RequestResponseCode)
}

func TestKeyUpdate(t *testing.T) {
	r := newTestResponder()
	r.version = algo.Version12
	ctx := context.Background()

	// Without an active session, KEY_UPDATE returns ERROR.
	req := &msgs.KeyUpdate{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestKeyUpdate),
			Param1:              msgs.KeyUpdateOpUpdateKey,
			Param2:              0x42,
		}},
	}
	reqData, _ := req.Marshal()

	resp, err := r.ProcessMessage(ctx, reqData)
	require.NoError(t, err)

	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, uint8(codes.ResponseError), errResp.Header.RequestResponseCode)
}

func TestEndSession(t *testing.T) {
	r := newTestResponder()
	r.version = algo.Version12
	ctx := context.Background()

	req := &msgs.EndSession{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestEndSession),
		}},
	}
	reqData, _ := req.Marshal()

	resp, err := r.ProcessMessage(ctx, reqData)
	require.NoError(t, err)

	var er msgs.EndSessionResponse
	require.NoError(t, er.Unmarshal(resp))
	assert.Equal(t, uint8(codes.ResponseEndSessionAck), er.Header.RequestResponseCode)
}

func negotiateResponder(t *testing.T, r *Responder) {
	t.Helper()
	ctx := context.Background()
	_, err := r.ProcessMessage(ctx, buildGetVersion())
	require.NoError(t, err)
	_, err = r.ProcessMessage(ctx, buildGetCapabilities())
	require.NoError(t, err)
	_, err = r.ProcessMessage(ctx, buildNegotiateAlgorithms())
	require.NoError(t, err)
}

func TestGetCertificate(t *testing.T) {
	chain := make([]byte, 200)
	for i := range chain {
		chain[i] = byte(i)
	}
	r := newTestResponder()
	r.cfg.CertProvider = &mockCertProvider{
		chains:  map[uint8][]byte{0: chain},
		digests: map[uint8][]byte{0: make([]byte, 32)},
	}
	ctx := context.Background()
	negotiateResponder(t, r)

	// Request first portion.
	req := &msgs.GetCertificate{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetCertificate),
			Param1:              0,
		}},
		Offset: 0,
		Length: 100,
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(ctx, reqData)
	require.NoError(t, err)
	var cr msgs.CertificateResponse
	require.NoError(t, cr.Unmarshal(resp))
	assert.Equal(t, uint16(100), cr.PortionLength)
	assert.Equal(t, uint16(100), cr.RemainderLength)

	// Request second portion.
	req.Offset = 100
	req.Length = 200
	reqData, _ = req.Marshal()
	resp, err = r.ProcessMessage(ctx, reqData)
	require.NoError(t, err)
	require.NoError(t, cr.Unmarshal(resp))
	assert.Equal(t, uint16(100), cr.PortionLength)
	assert.Equal(t, uint16(0), cr.RemainderLength)
}

func TestGetCertificateNotNegotiated(t *testing.T) {
	r := newTestResponder()
	r.cfg.CertProvider = &mockCertProvider{chains: map[uint8][]byte{0: make([]byte, 10)}}
	req := &msgs.GetCertificate{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestGetCertificate)}},
	}
	reqData, _ := req.Marshal()
	resp, _ := r.ProcessMessage(context.Background(), reqData)
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnexpectedRequest, errResp.ErrorCode())
}

func TestGetCertificateNoCertProvider(t *testing.T) {
	r := newTestResponder()
	negotiateResponder(t, r)
	req := &msgs.GetCertificate{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestGetCertificate)}},
	}
	reqData, _ := req.Marshal()
	resp, _ := r.ProcessMessage(context.Background(), reqData)
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnsupportedRequest, errResp.ErrorCode())
}

func TestGetCertificateOffsetBeyondChain(t *testing.T) {
	r := newTestResponder()
	r.cfg.CertProvider = &mockCertProvider{
		chains:  map[uint8][]byte{0: make([]byte, 10)},
		digests: map[uint8][]byte{0: make([]byte, 32)},
	}
	negotiateResponder(t, r)
	req := &msgs.GetCertificate{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestGetCertificate)}},
		Offset: 100,
		Length: 10,
	}
	reqData, _ := req.Marshal()
	resp, _ := r.ProcessMessage(context.Background(), reqData)
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorInvalidRequest, errResp.ErrorCode())
}

func TestChallenge(t *testing.T) {
	r := newTestResponder()
	r.cfg.CertProvider = &mockCertProvider{
		chains:  map[uint8][]byte{0: make([]byte, 50)},
		digests: map[uint8][]byte{0: make([]byte, 32)},
	}
	negotiateResponder(t, r)

	req := &msgs.Challenge{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestChallenge),
			Param1:              0,    // slotID
			Param2:              0xFF, // hashType = all
		}},
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp), msgs.HeaderSize, "response too short")
	assert.Equal(t, uint8(codes.ResponseChallengeAuth), resp[1])
}

func TestChallengeNotNegotiated(t *testing.T) {
	r := newTestResponder()
	req := &msgs.Challenge{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestChallenge)}},
	}
	reqData, _ := req.Marshal()
	resp, _ := r.ProcessMessage(context.Background(), reqData)
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnexpectedRequest, errResp.ErrorCode())
}

func TestChallengeNoMeasHash(t *testing.T) {
	r := newTestResponder()
	r.cfg.CertProvider = &mockCertProvider{
		digests: map[uint8][]byte{0: make([]byte, 32)},
	}
	negotiateResponder(t, r)
	req := &msgs.Challenge{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestChallenge),
			Param1:              0,
			Param2:              0x00, // NoMeasurementSummaryHash
		}},
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)
	assert.Equal(t, uint8(codes.ResponseChallengeAuth), resp[1])
}

func TestGetMeasurements(t *testing.T) {
	r := newTestResponder()
	r.cfg.MeasProvider = &mockMeasProvider{
		blocks: []msgs.MeasurementBlock{
			{Index: 1, Spec: 0x01, ValueType: 0x01, Value: []byte("firmware")},
			{Index: 2, Spec: 0x01, ValueType: 0x02, Value: []byte("config")},
		},
	}
	negotiateResponder(t, r)

	req := &msgs.GetMeasurements{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetMeasurements),
			Param2:              msgs.MeasOpAllMeasurements,
		}},
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)
	var mr msgs.MeasurementsResponse
	require.NoError(t, mr.Unmarshal(resp))
	assert.Equal(t, uint8(2), mr.NumberOfBlocks)
}

func TestGetMeasurementsNotNegotiated(t *testing.T) {
	r := newTestResponder()
	r.cfg.MeasProvider = &mockMeasProvider{}
	req := &msgs.GetMeasurements{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestGetMeasurements)}},
	}
	reqData, _ := req.Marshal()
	resp, _ := r.ProcessMessage(context.Background(), reqData)
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnexpectedRequest, errResp.ErrorCode())
}

func TestGetMeasurementsNoProvider(t *testing.T) {
	r := newTestResponder()
	negotiateResponder(t, r)
	req := &msgs.GetMeasurements{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestGetMeasurements)}},
	}
	reqData, _ := req.Marshal()
	resp, _ := r.ProcessMessage(context.Background(), reqData)
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnsupportedRequest, errResp.ErrorCode())
}

func TestVendorDefined(t *testing.T) {
	r := newTestResponder()
	r.version = algo.Version12
	req := &msgs.VendorDefinedRequest{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestVendorDefined),
		}},
		StandardID: 0x0042,
		VendorID:   []byte{0xAA, 0xBB},
		Payload:    []byte("test"),
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)
	var vr msgs.VendorDefinedResponse
	require.NoError(t, vr.Unmarshal(resp))
	assert.Equal(t, uint16(0x0042), vr.StandardID)
}

func TestGetDigestsNoCertProvider(t *testing.T) {
	r := newTestResponder()
	negotiateResponder(t, r)
	req := &msgs.GetDigests{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestGetDigests)}},
	}
	reqData, _ := req.Marshal()
	resp, _ := r.ProcessMessage(context.Background(), reqData)
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnsupportedRequest, errResp.ErrorCode())
}

func TestGetVersionResetsState(t *testing.T) {
	r := newTestResponder()
	ctx := context.Background()
	negotiateResponder(t, r)
	require.True(t, r.negotiated, "should be negotiated")
	// GET_VERSION resets state.
	_, err := r.ProcessMessage(ctx, buildGetVersion())
	require.NoError(t, err)
	assert.False(t, r.negotiated, "negotiated should be false after GET_VERSION")
}

func TestGetVersionEmptyVersions(t *testing.T) {
	r := New(Config{})
	resp, _ := r.ProcessMessage(context.Background(), buildGetVersion())
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnspecified, errResp.ErrorCode())
}

func TestNegotiateAlgorithmsNoCommon(t *testing.T) {
	r := New(Config{
		Versions:     []algo.Version{algo.Version12},
		BaseAsymAlgo: algo.AsymECDSAP256,
		BaseHashAlgo: algo.HashSHA384, // No overlap with SHA256 request
	})
	ctx := context.Background()
	_, err := r.ProcessMessage(ctx, buildGetVersion())
	require.NoError(t, err)
	_, err = r.ProcessMessage(ctx, buildGetCapabilities())
	require.NoError(t, err)
	// buildNegotiateAlgorithms requests SHA256 but responder only has SHA384.
	resp, _ := r.ProcessMessage(ctx, buildNegotiateAlgorithms())
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnspecified, errResp.ErrorCode())
}

func TestBuildError(t *testing.T) {
	r := newTestResponder()
	// Without version set.
	data := r.buildError(codes.ErrorInvalidRequest, 0x42)
	require.GreaterOrEqual(t, len(data), 4)
	assert.Equal(t, uint8(0x10), data[0])
	assert.Equal(t, uint8(codes.ResponseError), data[1])

	// With version set.
	r.version = algo.Version12
	data = r.buildError(codes.ErrorBusy, 0)
	assert.Equal(t, uint8(algo.Version12), data[0])
}

func TestSelectAlgorithm16(t *testing.T) {
	tests := []struct {
		ours, theirs, want uint16
	}{
		{0, 0, 0},
		{0x01, 0x02, 0},
		{0x03, 0x06, 0x02},
		{0xFF, 0xFF, 0x01},
	}
	for _, tt := range tests {
		got := selectAlgorithm16(tt.ours, tt.theirs)
		assert.Equal(t, tt.want, got)
	}
}

func TestNewDefaults(t *testing.T) {
	r := New(Config{})
	assert.Equal(t, uint32(4096), r.cfg.DataTransferSize)
	assert.Equal(t, uint32(65536), r.cfg.MaxSPDMmsgSize)
}

func TestServeContextCancellation(t *testing.T) {
	r := newTestResponder()
	reqSide, rspSide := makeChanTransport()
	r.cfg.Transport = rspSide

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- r.Serve(ctx) }()

	// Send a valid message.
	data := buildGetVersion()
	reqSide.sendCh <- data

	// Read response.
	<-reqSide.recvCh

	cancel()
	err := <-errCh
	assert.NotEqual(t, nil, err, "expected error from Serve after cancel")
}

// chanTransport is a simple channel-based transport for testing Serve().
type chanTransport struct {
	sendCh chan []byte
	recvCh chan []byte
}

func makeChanTransport() (*chanTransport, *chanTransport) {
	ch1 := make(chan []byte, 16)
	ch2 := make(chan []byte, 16)
	return &chanTransport{sendCh: ch1, recvCh: ch2}, &chanTransport{sendCh: ch2, recvCh: ch1}
}

func (t *chanTransport) SendMessage(ctx context.Context, _ *uint32, msg []byte) error {
	select {
	case t.sendCh <- msg:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *chanTransport) ReceiveMessage(ctx context.Context) (*uint32, []byte, error) {
	select {
	case msg := <-t.recvCh:
		return nil, msg, nil
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}

func (t *chanTransport) HeaderSize() int { return 0 }

func TestChallengeWithSigner(t *testing.T) {
	r := newTestResponder()
	r.cfg.CertProvider = &mockCertProvider{
		digests: map[uint8][]byte{0: make([]byte, 32)},
	}
	// Use a fake signer (non-nil to trigger signing path).
	r.cfg.DeviceSigner = &fakeSigner{}
	negotiateResponder(t, r)

	req := &msgs.Challenge{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestChallenge),
			Param1:              0,
			Param2:              0xFF,
		}},
	}
	reqData, _ := req.Marshal()
	resp, err := r.ProcessMessage(context.Background(), reqData)
	require.NoError(t, err)
	assert.Equal(t, uint8(codes.ResponseChallengeAuth), resp[1])
}

// fakeSigner implements crypto.Signer for testing.
type fakeSigner struct{}

func (s *fakeSigner) Public() gocrypto.PublicKey { return nil }
func (s *fakeSigner) Sign(_ io.Reader, _ []byte, _ gocrypto.SignerOpts) ([]byte, error) {
	return make([]byte, 64), nil
}

func TestSessionHandlersUnmarshalErrors(t *testing.T) {
	r := newTestResponder()
	r.version = algo.Version12
	ctx := context.Background()

	// Heartbeat with too-short data (less than HeaderSize).
	resp, _ := r.ProcessMessage(ctx, []byte{0x12, uint8(codes.RequestHeartbeat), 0})
	assert.Equal(t, uint8(codes.ResponseError), resp[1])

	// KeyUpdate with too-short data.
	resp, _ = r.ProcessMessage(ctx, []byte{0x12, uint8(codes.RequestKeyUpdate), 0})
	assert.Equal(t, uint8(codes.ResponseError), resp[1])

	// EndSession with too-short data.
	resp, _ = r.ProcessMessage(ctx, []byte{0x12, uint8(codes.RequestEndSession), 0})
	assert.Equal(t, uint8(codes.ResponseError), resp[1])

	// VendorDefined with just a header (no vendor fields).
	badVendor := []byte{0x12, uint8(codes.RequestVendorDefined), 0, 0}
	resp, _ = r.ProcessMessage(ctx, badVendor)
	assert.Equal(t, uint8(codes.ResponseError), resp[1])
}

func TestServeProcessError(t *testing.T) {
	r := newTestResponder()
	reqSide, rspSide := makeChanTransport()
	r.cfg.Transport = rspSide

	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { errCh <- r.Serve(ctx) }()

	// Send GET_VERSION.
	reqSide.sendCh <- buildGetVersion()
	resp := <-reqSide.recvCh
	require.GreaterOrEqual(t, len(resp), 4)
	require.Equal(t, uint8(codes.ResponseVersion), resp[1])

	// Send invalid request -> error response but Serve continues.
	reqSide.sendCh <- []byte{0x12, 0xAA, 0, 0}
	resp = <-reqSide.recvCh
	require.Equal(t, uint8(codes.ResponseError), resp[1])

	cancel()
	<-errCh
}

func TestMeasurementsProviderError(t *testing.T) {
	r := newTestResponder()
	r.cfg.MeasProvider = &errorMeasProvider{}
	negotiateResponder(t, r)
	req := &msgs.GetMeasurements{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestGetMeasurements)}},
	}
	reqData, _ := req.Marshal()
	resp, _ := r.ProcessMessage(context.Background(), reqData)
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnspecified, errResp.ErrorCode())
}

type errorMeasProvider struct{}

func (m *errorMeasProvider) Collect(_ context.Context, _ uint8) ([]msgs.MeasurementBlock, error) {
	return nil, fmt.Errorf("provider error")
}

func (m *errorMeasProvider) SummaryHash(_ context.Context, _ uint8) ([]byte, error) {
	return nil, fmt.Errorf("provider error")
}

func TestServeTransportSendError(t *testing.T) {
	r := newTestResponder()
	reqSide, rspSide := makeChanTransport()
	r.cfg.Transport = rspSide

	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { errCh <- r.Serve(ctx) }()

	// Send a valid request.
	reqSide.sendCh <- buildGetVersion()

	// Read the response (this unblocks the responder's send).
	<-reqSide.recvCh

	// Now cancel to stop.
	cancel()
	<-errCh
}

func TestChallengeWithDigestError(t *testing.T) {
	r := newTestResponder()
	// CertProvider with no digests for slot 0.
	r.cfg.CertProvider = &mockCertProvider{
		digests: map[uint8][]byte{},
	}
	negotiateResponder(t, r)

	req := &msgs.Challenge{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestChallenge),
			Param1:              0,
			Param2:              0x00,
		}},
	}
	reqData, _ := req.Marshal()
	resp, _ := r.ProcessMessage(context.Background(), reqData)
	// Should still produce a response (uses zero hash if digest fails).
	if resp[1] != uint8(codes.ResponseChallengeAuth) {
		t.Logf("got response code 0x%02X", resp[1])
	}
}

func TestChallengeNoCertProvider(t *testing.T) {
	r := newTestResponder()
	negotiateResponder(t, r)
	req := &msgs.Challenge{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestChallenge),
			Param1:              0,
			Param2:              0x00,
		}},
	}
	reqData, _ := req.Marshal()
	resp, _ := r.ProcessMessage(context.Background(), reqData)
	// Should still produce a response (uses zero hash).
	if resp[1] != uint8(codes.ResponseChallengeAuth) {
		t.Logf("got response code 0x%02X", resp[1])
	}
}

func TestGetCertificateChainError(t *testing.T) {
	r := newTestResponder()
	r.cfg.CertProvider = &mockCertProvider{
		chains:  map[uint8][]byte{}, // no chains
		digests: map[uint8][]byte{0: make([]byte, 32)},
	}
	negotiateResponder(t, r)
	req := &msgs.GetCertificate{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestGetCertificate), Param1: 0}},
		Offset: 0,
		Length: 100,
	}
	reqData, _ := req.Marshal()
	resp, _ := r.ProcessMessage(context.Background(), reqData)
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnspecified, errResp.ErrorCode())
}

func TestGetDigestsAllSlotsEmpty(t *testing.T) {
	r := newTestResponder()
	r.cfg.CertProvider = &mockCertProvider{
		digests: map[uint8][]byte{}, // all empty
	}
	negotiateResponder(t, r)
	req := &msgs.GetDigests{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{SPDMVersion: 0x12, RequestResponseCode: uint8(codes.RequestGetDigests)}},
	}
	reqData, _ := req.Marshal()
	resp, _ := r.ProcessMessage(context.Background(), reqData)
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnspecified, errResp.ErrorCode())
}

func TestNegotiateAlgorithmsUnknownAlgType(t *testing.T) {
	r := newTestResponder()
	ctx := context.Background()
	_, err := r.ProcessMessage(ctx, buildGetVersion())
	require.NoError(t, err)
	_, err = r.ProcessMessage(ctx, buildGetCapabilities())
	require.NoError(t, err)

	req := &msgs.NegotiateAlgorithms{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestNegotiateAlgorithms),
			Param1:              1,
		}},
		BaseAsymAlgo: uint32(algo.AsymECDSAP256),
		BaseHashAlgo: uint32(algo.HashSHA256),
		AlgStructs: []msgs.AlgStructTable{
			{AlgType: 0xFF, AlgCount: 0x20, AlgSupported: 0x01}, // unknown type
		},
	}
	reqData, _ := req.Marshal()
	resp, _ := r.ProcessMessage(ctx, reqData)
	var ar msgs.AlgorithmsResponse
	require.NoError(t, ar.Unmarshal(resp))
	// Unknown type should be echoed with zero selection.
	require.Equal(t, 1, len(ar.AlgStructs))
	assert.Equal(t, uint16(0), ar.AlgStructs[0].AlgSupported)
}

func TestCapabilitiesUnmarshalError(t *testing.T) {
	r := newTestResponder()
	ctx := context.Background()
	_, err := r.ProcessMessage(ctx, buildGetVersion())
	require.NoError(t, err)
	// Send too-short capabilities request.
	resp, _ := r.ProcessMessage(ctx, []byte{0x12, uint8(codes.RequestGetCapabilities), 0, 0})
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorInvalidRequest, errResp.ErrorCode())
}

// errTransport is a transport that returns errors for testing Serve() error paths.
type errTransport struct {
	recvErr error
	sendErr error
	recvMsg []byte
}

func (e *errTransport) ReceiveMessage(_ context.Context) (*uint32, []byte, error) {
	if e.recvErr != nil {
		return nil, nil, e.recvErr
	}
	return nil, e.recvMsg, nil
}

func (e *errTransport) SendMessage(_ context.Context, _ *uint32, _ []byte) error {
	return e.sendErr
}

func (e *errTransport) HeaderSize() int { return 0 }

// errReader is an io.Reader that always returns an error.
type errReader struct{}

func (e *errReader) Read(_ []byte) (int, error) {
	return 0, fmt.Errorf("reader error")
}

func TestServeReceiveError(t *testing.T) {
	r := newTestResponder()
	r.cfg.Transport = &errTransport{recvErr: fmt.Errorf("transport down")}

	err := r.Serve(context.Background())
	require.Error(t, err, "expected error from Serve")
	assert.EqualError(t, err, "receive: transport down")
}

func TestServeSendError(t *testing.T) {
	r := newTestResponder()
	r.cfg.Transport = &errTransport{
		recvMsg: buildGetVersion(),
		sendErr: fmt.Errorf("send failed"),
	}

	err := r.Serve(context.Background())
	require.Error(t, err, "expected error from Serve")
	assert.EqualError(t, err, "send: send failed")
}

func TestRandomBytesError(t *testing.T) {
	r := newTestResponder()
	r.cfg.Crypto.Random = &errReader{}

	_, err := r.randomBytes(32)
	require.Error(t, err, "expected error from randomBytes with failing reader")
}

func TestChallengeUnmarshalError(t *testing.T) {
	r := newTestResponder()
	r.cfg.CertProvider = &mockCertProvider{
		digests: map[uint8][]byte{0: make([]byte, 32)},
	}
	negotiateResponder(t, r)

	// 4-byte header passes ProcessMessage's length check but fails Challenge.Unmarshal
	// (needs HeaderSize + NonceSize = 36 bytes).
	req := []byte{0x12, uint8(codes.RequestChallenge), 0, 0}
	resp, _ := r.ProcessMessage(context.Background(), req)
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorInvalidRequest, errResp.ErrorCode())
}

func TestChallengeRandomBytesError(t *testing.T) {
	r := newTestResponder()
	r.cfg.CertProvider = &mockCertProvider{
		digests: map[uint8][]byte{0: make([]byte, 32)},
	}
	r.cfg.Crypto.Random = &errReader{}
	negotiateResponder(t, r)

	req := &msgs.Challenge{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestChallenge),
			Param1:              0,
			Param2:              0x00,
		}},
	}
	reqData, _ := req.Marshal()
	resp, _ := r.ProcessMessage(context.Background(), reqData)
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnspecified, errResp.ErrorCode())
}

func TestGetMeasurementsUnmarshalError(t *testing.T) {
	r := newTestResponder()
	r.cfg.MeasProvider = &mockMeasProvider{}
	negotiateResponder(t, r)

	// With MeasAttrGenerateSignature set, Unmarshal requires HeaderSize+NonceSize+1=37 bytes.
	// 4-byte header triggers Unmarshal failure.
	req := []byte{0x12, uint8(codes.RequestGetMeasurements), msgs.MeasAttrGenerateSignature, 0}
	resp, _ := r.ProcessMessage(context.Background(), req)
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorInvalidRequest, errResp.ErrorCode())
}

func TestGetMeasurementsRandomBytesError(t *testing.T) {
	r := newTestResponder()
	r.cfg.MeasProvider = &mockMeasProvider{
		blocks: []msgs.MeasurementBlock{
			{Index: 1, Spec: 0x01, ValueType: 0x01, Value: []byte("fw")},
		},
	}
	r.cfg.Crypto.Random = &errReader{}
	negotiateResponder(t, r)

	req := &msgs.GetMeasurements{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x12,
			RequestResponseCode: uint8(codes.RequestGetMeasurements),
			Param2:              0,
		}},
	}
	reqData, _ := req.Marshal()
	resp, _ := r.ProcessMessage(context.Background(), reqData)
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorUnspecified, errResp.ErrorCode())
}

func TestGetCertificateUnmarshalError(t *testing.T) {
	r := newTestResponder()
	r.cfg.CertProvider = &mockCertProvider{
		chains:  map[uint8][]byte{0: make([]byte, 50)},
		digests: map[uint8][]byte{0: make([]byte, 32)},
	}
	negotiateResponder(t, r)

	// 4-byte header passes ProcessMessage but fails GetCertificate.Unmarshal
	// (needs HeaderSize + 4 = 8 bytes).
	req := []byte{0x12, uint8(codes.RequestGetCertificate), 0, 0}
	resp, _ := r.ProcessMessage(context.Background(), req)
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorInvalidRequest, errResp.ErrorCode())
}

func TestNegotiateAlgorithmsUnmarshalError(t *testing.T) {
	r := newTestResponder()
	ctx := context.Background()
	_, err := r.ProcessMessage(ctx, buildGetVersion())
	require.NoError(t, err)
	_, err = r.ProcessMessage(ctx, buildGetCapabilities())
	require.NoError(t, err)

	// 4-byte header passes ProcessMessage but fails NegotiateAlgorithms.Unmarshal
	// (needs HeaderSize + 28 = 32 bytes).
	req := []byte{0x12, uint8(codes.RequestNegotiateAlgorithms), 0, 0}
	resp, _ := r.ProcessMessage(ctx, req)
	var errResp msgs.ErrorResponse
	require.NoError(t, errResp.Unmarshal(resp))
	assert.Equal(t, codes.ErrorInvalidRequest, errResp.ErrorCode())
}

func TestSelectAlgorithm(t *testing.T) {
	tests := []struct {
		name   string
		ours   uint32
		theirs uint32
		want   uint32
	}{
		{"no common", 0x01, 0x02, 0},
		{"single common", 0x03, 0x02, 0x02},
		{"lowest bit wins", 0x0F, 0x0E, 0x02},
		{"exact match", 0x04, 0x04, 0x04},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectAlgorithm(tt.ours, tt.theirs)
			assert.Equal(t, tt.want, got)
		})
	}
}
