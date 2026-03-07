package session

import (
	"hash"
	"sync"

	"github.com/xaionaro-go/spdm/pkg/gen/algo"
)

// SessionID is a typed session identifier.
type SessionID uint32

// State represents the lifecycle state of a session.
type State int

const (
	StateNone State = iota
	StateHandshake
	StateEstablished
	StateEnded
)

func (s State) String() string {
	switch s {
	case StateNone:
		return "none"
	case StateHandshake:
		return "handshake"
	case StateEstablished:
		return "established"
	case StateEnded:
		return "ended"
	default:
		return "unknown"
	}
}

// Session tracks the state and keys for a single SPDM session
// per DSP0274 Section 10 (Session Management).
type Session struct {
	mu sync.Mutex

	ID       SessionID
	State    State
	Version  algo.Version
	HashAlgo algo.BaseHashAlgo
	AEAD     algo.AEADCipherSuite

	HandshakeKeys *HandshakeKeys
	DataKeys      *DataKeys

	// Sequence numbers for replay protection
	ReqSeqNum uint64
	RspSeqNum uint64

	// Whether encryption (vs auth-only) is used
	EncryptionRequired bool

	// SeqNumSize is the transport-specific sequence number size in bytes
	// used in the secured message record header and nonce construction.
	// Common values: 0 (no seqnum), 2 (MCTP), 8 (NONE/TCP).
	SeqNumSize int

	// Handshake secret for deriving master secret later
	HandshakeSecret []byte
	MasterSecret    []byte

	// PendingResponseKeyUpdate is set when KEY_UPDATE with UpdateAllKeys
	// needs to defer the response key update until after the ACK is sent.
	PendingResponseKeyUpdate bool
}

// NewSession creates a new session in the handshake state.
func NewSession(id SessionID, version algo.Version, hashAlgo algo.BaseHashAlgo, aead algo.AEADCipherSuite, encReq bool) *Session {
	return &Session{
		ID:                 id,
		State:              StateHandshake,
		Version:            version,
		HashAlgo:           hashAlgo,
		AEAD:               aead,
		EncryptionRequired: encReq,
	}
}

// NextReqSeqNum returns and increments the request sequence number.
func (s *Session) NextReqSeqNum() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := s.ReqSeqNum
	if seq == ^uint64(0) {
		return 0, ErrSequenceOverflow
	}
	s.ReqSeqNum++
	return seq, nil
}

// UpdateRequestKeys derives new request data keys for KEY_UPDATE per DSP0274 Section 10.14.
// Resets the request sequence number to 0 per DSP0274.
func (s *Session) UpdateRequestKeys(newHash func() hash.Hash) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	newSecret, err := DeriveUpdatedDataSecret(newHash, s.Version, s.DataKeys.RequestSecret)
	if err != nil {
		return err
	}
	key, iv, err := DeriveKeyAndIVFromSecret(newHash, s.Version, s.AEAD, newSecret)
	if err != nil {
		return err
	}
	s.DataKeys.RequestSecret = newSecret
	s.DataKeys.RequestKey = key
	s.DataKeys.RequestIV = iv
	s.ReqSeqNum = 0
	return nil
}

// UpdateResponseKeys derives new response data keys for KEY_UPDATE per DSP0274 Section 10.14.
// Resets the response sequence number to 0 per DSP0274.
func (s *Session) UpdateResponseKeys(newHash func() hash.Hash) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	newSecret, err := DeriveUpdatedDataSecret(newHash, s.Version, s.DataKeys.ResponseSecret)
	if err != nil {
		return err
	}
	key, iv, err := DeriveKeyAndIVFromSecret(newHash, s.Version, s.AEAD, newSecret)
	if err != nil {
		return err
	}
	s.DataKeys.ResponseSecret = newSecret
	s.DataKeys.ResponseKey = key
	s.DataKeys.ResponseIV = iv
	s.RspSeqNum = 0
	return nil
}

// NextRspSeqNum returns and increments the response sequence number.
func (s *Session) NextRspSeqNum() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := s.RspSeqNum
	if seq == ^uint64(0) {
		return 0, ErrSequenceOverflow
	}
	s.RspSeqNum++
	return seq, nil
}
