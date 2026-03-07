package spdm

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/requester"
	"github.com/xaionaro-go/spdm/pkg/session"
)

// Requester is the consumer-facing SPDM requester.
type Requester struct {
	inner *requester.Requester
}

// NewRequester creates a new SPDM requester.
func NewRequester(cfg RequesterConfig) *Requester {
	return &Requester{
		inner: requester.New(requester.Config{
			Versions:         cfg.Versions,
			Transport:        cfg.Transport,
			Crypto:           cfg.Crypto,
			Caps:             cfg.Caps,
			BaseAsymAlgo:     cfg.BaseAsymAlgo,
			BaseHashAlgo:     cfg.BaseHashAlgo,
			DHEGroups:        cfg.DHEGroups,
			AEADSuites:       cfg.AEADSuites,
			DataTransferSize: cfg.DataTransferSize,
			MaxSPDMmsgSize:   cfg.MaxSPDMmsgSize,
			PSKProvider:      cfg.PSKProvider,
		}),
	}
}

// InitConnection performs version, capabilities, and algorithm negotiation.
func (r *Requester) InitConnection(ctx context.Context) (*ConnectionInfo, error) {
	ci, err := r.inner.InitConnection(ctx)
	if err != nil {
		return nil, err
	}
	return &ConnectionInfo{
		Version:      ci.PeerVersion,
		PeerCaps:     ci.PeerCaps,
		HashAlgo:     ci.HashAlgo,
		AsymAlgo:     ci.AsymAlgo,
		DHEGroup:     ci.DHEGroup,
		AEADSuite:    ci.AEADSuite,
		MeasHashAlgo: ci.MeasHashAlgo,
	}, nil
}

// GetDigests retrieves certificate digests from the responder.
func (r *Requester) GetDigests(ctx context.Context) (*Digests, error) {
	digests, err := r.inner.GetDigests(ctx)
	if err != nil {
		return nil, err
	}
	return &Digests{Digests: digests}, nil
}

// GetCertificate retrieves a full certificate chain.
func (r *Requester) GetCertificate(ctx context.Context, slotID uint8) (*CertificateChain, error) {
	chain, err := r.inner.GetCertificate(ctx, slotID)
	if err != nil {
		return nil, err
	}
	return &CertificateChain{SlotID: slotID, Chain: chain}, nil
}

// Challenge performs SPDM challenge authentication.
func (r *Requester) Challenge(ctx context.Context, slotID uint8) (*ChallengeResult, error) {
	if err := r.inner.Challenge(ctx, slotID, 0xFF); err != nil {
		return nil, err
	}
	return &ChallengeResult{SlotID: slotID}, nil
}

// GetMeasurements retrieves device measurements.
func (r *Requester) GetMeasurements(ctx context.Context, opts MeasurementOpts) (*Measurements, error) {
	resp, err := r.inner.GetMeasurements(ctx, opts.Index, opts.RequestSignature)
	if err != nil {
		return nil, err
	}
	return &Measurements{
		NumberOfBlocks: resp.NumberOfBlocks,
	}, nil
}

// KeyExchange performs an SPDM KEY_EXCHANGE to establish a secure session.
func (r *Requester) KeyExchange(ctx context.Context, opts KeyExchangeOpts) (*Session, error) {
	sess, err := r.inner.KeyExchange(ctx, opts.SlotID, opts.HashType)
	if err != nil {
		return nil, err
	}
	return &Session{inner: sess, req: r}, nil
}

// PSKExchange performs an SPDM PSK_EXCHANGE to establish a session using a pre-shared key.
func (r *Requester) PSKExchange(ctx context.Context, pskHint []byte) (*Session, error) {
	sess, err := r.inner.PSKExchange(ctx, pskHint)
	if err != nil {
		return nil, err
	}
	return &Session{inner: sess, req: r}, nil
}

// GetCSR requests a Certificate Signing Request from the responder per DSP0274 Section 10.22.
func (r *Requester) GetCSR(ctx context.Context, requesterInfo, opaqueData []byte) ([]byte, error) {
	return r.inner.GetCSR(ctx, requesterInfo, opaqueData)
}

// SetCertificate provisions a certificate chain to the responder per DSP0274 Section 10.23.
func (r *Requester) SetCertificate(ctx context.Context, slotID uint8, certChain []byte) error {
	return r.inner.SetCertificate(ctx, slotID, certChain)
}

// GetKeyPairInfo retrieves key pair information from the responder per DSP0274 Section 10.25.
func (r *Requester) GetKeyPairInfo(ctx context.Context, keyPairID uint8) (*msgs.KeyPairInfoResponse, error) {
	return r.inner.GetKeyPairInfo(ctx, keyPairID)
}

// GetEndpointInfo retrieves endpoint information from the responder per DSP0274 Section 10.26.
func (r *Requester) GetEndpointInfo(ctx context.Context, subCode uint8) ([]byte, error) {
	return r.inner.GetEndpointInfo(ctx, subCode)
}

// VendorDefinedRequest sends a vendor-defined request and returns the response.
func (r *Requester) VendorDefinedRequest(ctx context.Context, standardID uint16, vendorID, payload []byte) (*VendorResponse, error) {
	resp, err := r.inner.VendorDefinedRequest(ctx, standardID, vendorID, payload)
	if err != nil {
		return nil, &ErrVendorDefined{Err: err}
	}
	return &VendorResponse{
		StandardID: resp.StandardID,
		VendorID:   resp.VendorID,
		Payload:    resp.Payload,
	}, nil
}

// GetMeasurementExtensionLog retrieves measurement extension log data per DSP0274 Section 10.24.
func (r *Requester) GetMeasurementExtensionLog(ctx context.Context, offset, length uint32) (*msgs.MeasurementExtensionLogResponse, error) {
	return r.inner.GetMeasurementExtensionLog(ctx, offset, length)
}

// SetKeyPairInfo configures a key pair on the responder per DSP0274 Section 10.25.
func (r *Requester) SetKeyPairInfo(
	ctx context.Context,
	keyPairID uint8,
	operation uint8,
	desiredKeyUsage uint16,
	desiredAsymAlgo uint32,
	desiredAssocCertSlotMask uint8,
	publicKeyInfo []byte,
) (_err error) {
	logger.Tracef(ctx, "SetKeyPairInfo")
	defer func() { logger.Tracef(ctx, "/SetKeyPairInfo: %v", _err) }()

	return r.inner.SetKeyPairInfo(ctx, keyPairID, operation, desiredKeyUsage, desiredAsymAlgo, desiredAssocCertSlotMask, publicKeyInfo)
}

// GetEncapsulatedRequest retrieves an encapsulated request from the responder
// for mutual authentication per DSP0274 Section 10.15.
func (r *Requester) GetEncapsulatedRequest(
	ctx context.Context,
) (_result *msgs.EncapsulatedRequestResponse, _err error) {
	logger.Tracef(ctx, "GetEncapsulatedRequest")
	defer func() { logger.Tracef(ctx, "/GetEncapsulatedRequest: %v", _err) }()

	return r.inner.GetEncapsulatedRequest(ctx)
}

// DeliverEncapsulatedResponse delivers the requester's response to the responder's
// encapsulated request per DSP0274 Section 10.15.
func (r *Requester) DeliverEncapsulatedResponse(
	ctx context.Context,
	requestID uint8,
	encapsulatedData []byte,
) (_result *msgs.EncapsulatedResponseAck, _err error) {
	logger.Tracef(ctx, "DeliverEncapsulatedResponse")
	defer func() { logger.Tracef(ctx, "/DeliverEncapsulatedResponse: %v", _err) }()

	return r.inner.DeliverEncapsulatedResponse(ctx, requestID, encapsulatedData)
}

// GetSupportedEventTypes queries the responder for supported event types
// per DSP0274 Section 10.22.
func (r *Requester) GetSupportedEventTypes(
	ctx context.Context,
) (_result []byte, _err error) {
	logger.Tracef(ctx, "GetSupportedEventTypes")
	defer func() { logger.Tracef(ctx, "/GetSupportedEventTypes: %v", _err) }()

	return r.inner.GetSupportedEventTypes(ctx)
}

// SubscribeEventTypes subscribes to event types on the responder
// per DSP0274 Section 10.23.
func (r *Requester) SubscribeEventTypes(
	ctx context.Context,
	eventGroups []byte,
) (_err error) {
	logger.Tracef(ctx, "SubscribeEventTypes")
	defer func() { logger.Tracef(ctx, "/SubscribeEventTypes: %v", _err) }()

	return r.inner.SubscribeEventTypes(ctx, eventGroups)
}

// SendEvent sends an event notification to the responder per DSP0274 Section 10.24.
func (r *Requester) SendEvent(
	ctx context.Context,
	eventData []byte,
) (_err error) {
	logger.Tracef(ctx, "SendEvent")
	defer func() { logger.Tracef(ctx, "/SendEvent: %v", _err) }()

	return r.inner.SendEvent(ctx, eventData)
}

// RespondIfReady sends RESPOND_IF_READY per DSP0274 Section 10.18.
// Used to retry an operation that previously returned ResponseNotReady.
func (r *Requester) RespondIfReady(
	ctx context.Context,
	originalRequestCode codes.RequestCode,
	token uint8,
) (_result []byte, _err error) {
	logger.Tracef(ctx, "RespondIfReady")
	defer func() { logger.Tracef(ctx, "/RespondIfReady: %v", _err) }()

	return r.inner.RespondIfReady(ctx, originalRequestCode, token)
}

// Session wraps a protocol session with consumer-friendly methods.
type Session struct {
	inner *session.Session
	req   *Requester
}

// SendReceive sends data within the secure session and returns the response.
func (s *Session) SendReceive(
	ctx context.Context,
	data []byte,
) (_ret []byte, _err error) {
	logger.Tracef(ctx, "SendReceive")
	defer func() { logger.Tracef(ctx, "/SendReceive: %v", _err) }()

	if s.req == nil || s.inner == nil {
		return nil, &ErrSessionNotInitialized{}
	}
	return s.req.inner.SendReceiveSecured(ctx, s.inner, data)
}

// Heartbeat sends a session heartbeat per DSP0274 Section 10.16.
func (s *Session) Heartbeat(ctx context.Context) (_err error) {
	logger.Tracef(ctx, "Heartbeat")
	defer func() { logger.Tracef(ctx, "/Heartbeat: %v", _err) }()

	if s.req == nil || s.inner == nil {
		return &ErrSessionNotInitialized{}
	}
	return s.req.inner.Heartbeat(ctx, s.inner.ID)
}

// KeyUpdate performs a key update within the session per DSP0274 Section 10.17.
func (s *Session) KeyUpdate(ctx context.Context, op KeyUpdateOp) (_err error) {
	logger.Tracef(ctx, "KeyUpdate")
	defer func() { logger.Tracef(ctx, "/KeyUpdate: %v", _err) }()

	if s.req == nil || s.inner == nil {
		return &ErrSessionNotInitialized{}
	}
	return s.req.inner.KeyUpdate(ctx, s.inner.ID, uint8(op))
}

// Close ends the session per DSP0274 Section 10.19.
func (s *Session) Close(ctx context.Context) (_err error) {
	logger.Tracef(ctx, "Close")
	defer func() { logger.Tracef(ctx, "/Close: %v", _err) }()

	if s.req == nil || s.inner == nil {
		return &ErrSessionNotInitialized{}
	}
	return s.req.inner.EndSession(ctx, s.inner.ID)
}
