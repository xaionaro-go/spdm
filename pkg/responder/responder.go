package responder

import (
	"context"
	gocrypto "crypto"
	"crypto/rand"
	"io"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/crypto"
	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/caps"
	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
	"github.com/xaionaro-go/spdm/pkg/session"
	"github.com/xaionaro-go/spdm/pkg/transport"
)

// CertProvider supplies certificate chains per DSP0274 Section 10.7.
type CertProvider interface {
	CertChain(ctx context.Context, slotID uint8) ([]byte, error)
	DigestForSlot(ctx context.Context, slotID uint8) ([]byte, error)
}

// MeasurementProvider supplies device measurements per DSP0274 Section 10.11.
type MeasurementProvider interface {
	Collect(ctx context.Context, index uint8) ([]msgs.MeasurementBlock, error)
	SummaryHash(ctx context.Context, hashType uint8) ([]byte, error)
}

// Config for responder.
type Config struct {
	Versions             []algo.Version
	Transport            transport.Transport
	Crypto               crypto.Suite
	Caps                 caps.ResponderCaps
	BaseAsymAlgo         algo.BaseAsymAlgo
	BaseHashAlgo         algo.BaseHashAlgo
	DHEGroups            algo.DHENamedGroup
	AEADSuites           algo.AEADCipherSuite
	CTExponent           uint8
	DataTransferSize     uint32
	MaxSPDMmsgSize       uint32
	CertProvider         CertProvider
	MeasProvider         MeasurementProvider
	DeviceSigner         gocrypto.Signer
	PSKProvider          crypto.PSKProvider
	CSRProvider          CSRProvider
	ProvisioningProvider ProvisioningProvider
	EndpointInfoProvider EndpointInfoProvider
	MELProvider          MELProvider
}

// ConnectionState tracks the SPDM connection state machine per DSP0274 Section 9.
type ConnectionState uint8

const (
	// StateNotStarted is the initial state before GET_VERSION.
	StateNotStarted ConnectionState = iota
	// StateAfterVersion is the state after a successful GET_VERSION exchange.
	StateAfterVersion
	// StateAfterCapabilities is the state after a successful GET_CAPABILITIES exchange.
	StateAfterCapabilities
	// StateNegotiated is the state after a successful NEGOTIATE_ALGORITHMS exchange.
	StateNegotiated
)

// Responder implements the SPDM responder protocol state machine per DSP0274.
type Responder struct {
	cfg        Config
	version    algo.Version
	state      ConnectionState
	peerCaps   caps.RequesterCaps
	prevCaps   *msgs.GetCapabilities // tracks previous GET_CAPABILITIES for replay detection per DSP0274 Section 10.4
	hashAlgo   algo.BaseHashAlgo
	asymAlgo   algo.BaseAsymAlgo
	dheGroup   algo.DHENamedGroup
	aeadSuite  algo.AEADCipherSuite
	sessions   map[session.SessionID]*session.Session
	negotiated bool
	// transcript accumulates message bytes for signing per DSP0274 Section 15.
	// M1 = Concatenate(A, B, C) where:
	//   A = VCA messages (GET_VERSION..ALGORITHMS)
	//   B = GET_DIGESTS/DIGESTS + GET_CERTIFICATE/CERTIFICATE
	//   C = CHALLENGE + CHALLENGE_AUTH (without signature)
	transcript []byte
	// vcaTranscript is a snapshot of transcript after NEGOTIATE_ALGORITHMS (message A only).
	// Used by KEY_EXCHANGE TH computation which needs VCA separately from B messages.
	vcaTranscript []byte
	// measTranscript accumulates measurement message bytes (message_m) across
	// multiple GET_MEASUREMENTS exchanges per DSP0274 Section 15.
	// Reset after a signed measurement response.
	measTranscript []byte
	// pending holds state between KEY_EXCHANGE_RSP and FINISH.
	pending *pendingSession
	// pendingPSK holds state between PSK_EXCHANGE_RSP and PSK_FINISH.
	pendingPSK *pendingPSKSession
	// activeSessionID is set by the caller (e.g. transport layer) to indicate
	// which session context the current message belongs to.
	activeSessionID session.SessionID
	// chunkSend tracks the reassembly state for CHUNK_SEND.
	chunkSend *chunkSendState
	// chunkGet tracks the sending state for CHUNK_GET.
	chunkGet *chunkGetState
}

// New creates a new Responder with the given configuration.
func New(cfg Config) *Responder {
	if cfg.DataTransferSize == 0 {
		cfg.DataTransferSize = 4096
	}
	if cfg.MaxSPDMmsgSize == 0 {
		cfg.MaxSPDMmsgSize = 65536
	}
	return &Responder{
		cfg:      cfg,
		sessions: make(map[session.SessionID]*session.Session),
	}
}

// ProcessMessage handles a single SPDM request and returns the response.
func (r *Responder) ProcessMessage(ctx context.Context, request []byte) (_resp []byte, _err error) {
	logger.Tracef(ctx, "ProcessMessage: len=%d", len(request))
	defer func() { logger.Tracef(ctx, "/ProcessMessage: len=%d; err=%v", len(_resp), _err) }()
	if len(request) < msgs.HeaderSize {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}
	var hdr msgs.MessageHeader
	if err := hdr.Unmarshal(request); err != nil {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	reqCode := codes.RequestCode(hdr.RequestResponseCode)

	// State machine enforcement per DSP0274 Section 9.
	// GET_VERSION is always allowed and resets state.
	if reqCode != codes.RequestGetVersion {
		// Version mismatch check per DSP0274 Section 10.3:
		// after version negotiation, all messages must use the negotiated version.
		if r.version != 0 && hdr.SPDMVersion != uint8(r.version) {
			return r.buildError(codes.ErrorVersionMismatch, 0), nil
		}

		switch reqCode {
		case codes.RequestGetCapabilities:
			if r.state < StateAfterVersion {
				return r.buildError(codes.ErrorUnexpectedRequest, 0), nil
			}
		case codes.RequestNegotiateAlgorithms:
			if r.state < StateAfterCapabilities {
				return r.buildError(codes.ErrorUnexpectedRequest, 0), nil
			}
		}
	}

	handler, ok := messageHandlers[reqCode]
	if !ok {
		return r.buildError(codes.ErrorUnsupportedRequest, 0), nil
	}
	return handler(r, ctx, request)
}

// Serve continuously reads requests and writes responses.
func (r *Responder) Serve(ctx context.Context) (_err error) {
	logger.Tracef(ctx, "Serve")
	defer func() { logger.Tracef(ctx, "/Serve: err=%v", _err) }()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_, request, err := r.cfg.Transport.ReceiveMessage(ctx)
		if err != nil {
			return &ErrReceive{Err: err}
		}
		response, err := r.ProcessMessage(ctx, request)
		if err != nil {
			return &ErrProcess{Err: err}
		}
		if err := r.cfg.Transport.SendMessage(ctx, nil, response); err != nil {
			return &ErrSendResponse{Err: err}
		}
	}
}

// buildError constructs a serialized SPDM ERROR response.
func (r *Responder) buildError(errCode codes.SPDMErrorCode, errData uint8) []byte {
	ver := uint8(0x10)
	if r.version != 0 {
		ver = uint8(r.version)
	}
	resp := &msgs.ErrorResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.ResponseError),
			Param1:              uint8(errCode),
			Param2:              errData,
		}},
	}
	data, _ := resp.Marshal()
	return data
}

// randomBytes returns n random bytes using the configured or default random source.
func (r *Responder) randomBytes(n int) ([]byte, error) {
	rng := r.cfg.Crypto.Random
	if rng == nil {
		rng = rand.Reader
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(rng, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// GetSession returns the session with the given ID, or nil if not found.
func (r *Responder) GetSession(id session.SessionID) *session.Session {
	return r.sessions[id]
}

// SetActiveSession sets the active session ID for session message handling.
func (r *Responder) SetActiveSession(id session.SessionID) {
	r.activeSessionID = id
}

// ActiveSession returns the currently active session, or nil.
func (r *Responder) ActiveSession() *session.Session {
	return r.sessions[r.activeSessionID]
}

// selectAlgorithm picks the lowest set bit from the intersection of two bitmasks.
// Returns 0 if no common algorithm exists.
func selectAlgorithm(ours, theirs uint32) uint32 {
	common := ours & theirs
	if common == 0 {
		return 0
	}
	// Return lowest set bit.
	return common & (-common)
}

// selectAlgorithm16 is the 16-bit variant of selectAlgorithm.
func selectAlgorithm16(ours, theirs uint16) uint16 {
	common := ours & theirs
	if common == 0 {
		return 0
	}
	return common & (-common)
}
