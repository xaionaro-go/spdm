package requester

import (
	"context"
	"hash"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/crypto"
	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/caps"
	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/status"
	"github.com/xaionaro-go/spdm/pkg/session"
	"github.com/xaionaro-go/spdm/pkg/transport"
)

// ConnectionState tracks the protocol negotiation state per DSP0274 Section 9.
type ConnectionState int

const (
	StateNotStarted ConnectionState = iota
	StateAfterVersion
	StateAfterCapabilities
	StateAfterAlgorithms
	StateAuthenticated
)

// ConnectionInfo holds the negotiated connection parameters.
type ConnectionInfo struct {
	PeerVersion  algo.Version
	PeerCaps     caps.ResponderCaps
	HashAlgo     algo.BaseHashAlgo
	AsymAlgo     algo.BaseAsymAlgo
	DHEGroup     algo.DHENamedGroup
	AEADSuite    algo.AEADCipherSuite
	MeasHashAlgo algo.MeasurementHashAlgo
}

// Config holds requester configuration.
type Config struct {
	Versions         []algo.Version
	Transport        transport.Transport
	Crypto           crypto.Suite
	Caps             caps.RequesterCaps
	CTExponent       uint8 // timeout exponent per DSP0274 Section 10.4
	BaseAsymAlgo     algo.BaseAsymAlgo
	BaseHashAlgo     algo.BaseHashAlgo
	DHEGroups        algo.DHENamedGroup
	AEADSuites       algo.AEADCipherSuite
	DataTransferSize uint32
	MaxSPDMmsgSize   uint32
	PSKProvider      crypto.PSKProvider
}

// Requester implements the SPDM requester protocol state machine per DSP0274.
type Requester struct {
	cfg      Config
	state    ConnectionState
	conn     ConnectionInfo
	sessions map[session.SessionID]*session.Session
	// vcaTranscript accumulates VCA message bytes (GET_VERSION..ALGORITHMS) per DSP0274 Section 15.
	vcaTranscript []byte
	// transcript accumulates B message bytes (GET_DIGESTS/DIGESTS + GET_CERTIFICATE/CERTIFICATE)
	// per DSP0274 Section 15 for Challenge signature verification.
	transcript []byte
	// measTranscript accumulates measurement message bytes (message_m) across
	// multiple GET_MEASUREMENTS exchanges per DSP0274 Section 15.
	// Reset after a signed measurement response.
	measTranscript []byte
	// peerCertChain stores the responder's certificate chain for TH computation.
	peerCertChain []byte
}

// New creates a new Requester with the given configuration.
func New(cfg Config) *Requester {
	if cfg.DataTransferSize == 0 {
		cfg.DataTransferSize = 4096
	}
	if cfg.MaxSPDMmsgSize == 0 {
		cfg.MaxSPDMmsgSize = 65536
	}
	return &Requester{
		cfg:      cfg,
		sessions: make(map[session.SessionID]*session.Session),
	}
}

// ConnectionInfo returns the current negotiated connection parameters.
func (r *Requester) ConnectionInfo() ConnectionInfo { return r.conn }

// State returns the current connection state.
func (r *Requester) State() ConnectionState { return r.state }

// sendReceive marshals a request, sends it via transport, receives and validates the response.
// It checks for ERROR responses and converts them to ProtocolError.
func (r *Requester) sendReceive(ctx context.Context, req msgs.RequestMessage) ([]byte, error) {
	data, err := req.Marshal()
	if err != nil {
		return nil, &ErrMarshalRequest{Err: err}
	}

	logger.Debugf(ctx, "sendReceive: sending %d bytes", len(data))

	if err := r.cfg.Transport.SendMessage(ctx, nil, data); err != nil {
		return nil, &ErrSend{Err: err}
	}

	_, resp, err := r.cfg.Transport.ReceiveMessage(ctx)
	if err != nil {
		return nil, &ErrReceive{Err: err}
	}

	logger.Debugf(ctx, "sendReceive: received %d bytes", len(resp))

	return r.checkResponse(resp)
}

// checkResponse validates a response payload: checks minimum size and ERROR responses.
func (r *Requester) checkResponse(resp []byte) ([]byte, error) {
	if len(resp) < msgs.HeaderSize {
		return nil, status.ErrInvalidMsgSize
	}
	if resp[1] == uint8(codes.ResponseError) {
		var errResp msgs.ErrorResponse
		if err := errResp.Unmarshal(resp); err != nil {
			return nil, &ErrUnmarshalErrorResponse{Err: err}
		}
		return nil, &status.ProtocolError{
			ErrorCode: uint8(errResp.ErrorCode()),
			ErrorData: errResp.ErrorData(),
			ExtData:   errResp.ExtErrorData,
		}
	}
	return resp, nil
}

// newHash returns a factory function for the negotiated hash algorithm.
func (r *Requester) newHash() func() hash.Hash {
	return func() hash.Hash { return r.conn.HashAlgo.CryptoHash().New() }
}

// getSession looks up a session by ID and verifies it is in the established state.
func (r *Requester) getSession(sessionID session.SessionID) (*session.Session, error) {
	sess, ok := r.sessions[sessionID]
	if !ok {
		return nil, &ErrSessionNotFound{SessionID: uint32(sessionID)}
	}
	if sess.State != session.StateEstablished {
		return nil, &ErrSessionInvalidState{SessionID: uint32(sessionID), State: sess.State.String()}
	}
	return sess, nil
}

// SendReceiveSecured encrypts an SPDM message, sends it within a session, receives
// and decrypts the response. It checks for ERROR responses in the decrypted payload.
func (r *Requester) SendReceiveSecured(ctx context.Context, sess *session.Session, plaintext []byte) ([]byte, error) {
	reqSeq, err := sess.NextReqSeqNum()
	if err != nil {
		return nil, &ErrRequestSequenceNumber{Err: err}
	}

	sid := uint32(sess.ID)
	secured, err := session.EncodeSecuredMessage(
		sess.AEAD,
		sess.DataKeys.RequestKey,
		sess.DataKeys.RequestIV,
		reqSeq,
		sid,
		plaintext,
		sess.EncryptionRequired,
		sess.SeqNumSize,
	)
	if err != nil {
		return nil, &ErrEncodeSecuredMessage{Err: err}
	}

	logger.Debugf(ctx, "sendReceiveSecured: sending %d bytes (session %d)", len(secured), sid)

	if err := r.cfg.Transport.SendMessage(ctx, &sid, secured); err != nil {
		return nil, &ErrSendSecured{Err: err}
	}

	_, respSecured, err := r.cfg.Transport.ReceiveMessage(ctx)
	if err != nil {
		return nil, &ErrReceiveSecured{Err: err}
	}

	rspSeq, err := sess.NextRspSeqNum()
	if err != nil {
		return nil, &ErrResponseSequenceNumber{Err: err}
	}

	_, respPlain, err := session.DecodeSecuredMessage(
		sess.AEAD,
		sess.DataKeys.ResponseKey,
		sess.DataKeys.ResponseIV,
		rspSeq,
		sess.EncryptionRequired,
		respSecured,
		sess.SeqNumSize,
	)
	if err != nil {
		return nil, &ErrDecodeSecuredMessage{Err: err}
	}

	logger.Debugf(ctx, "sendReceiveSecured: decrypted %d bytes", len(respPlain))

	return r.checkResponse(respPlain)
}

// sendReceiveVCA calls sendReceive and records both request and response to vcaTranscript.
func (r *Requester) sendReceiveVCA(ctx context.Context, req msgs.RequestMessage) ([]byte, error) {
	reqBytes, err := req.Marshal()
	if err != nil {
		return nil, &ErrMarshalRequest{Err: err}
	}
	resp, err := r.sendReceive(ctx, req)
	if err != nil {
		return nil, err
	}
	r.vcaTranscript = append(r.vcaTranscript, reqBytes...)
	r.vcaTranscript = append(r.vcaTranscript, resp...)
	return resp, nil
}
