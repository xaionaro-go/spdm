package requester

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
	"github.com/xaionaro-go/spdm/pkg/session"
)

// Heartbeat sends a HEARTBEAT request within an established session and waits
// for the HEARTBEAT_ACK response per DSP0274 Section 10.16.
func (r *Requester) Heartbeat(ctx context.Context, sessionID session.SessionID) error {
	logger.Debugf(ctx, "Heartbeat: session=0x%08x", sessionID)

	sess, err := r.getSession(sessionID)
	if err != nil {
		return &ErrHeartbeat{Err: err}
	}

	ver := uint8(r.conn.PeerVersion)
	req := &msgs.Heartbeat{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.RequestHeartbeat),
		}},
	}

	reqBytes, err := req.Marshal()
	if err != nil {
		return &ErrHeartbeatMarshal{Err: err}
	}

	resp, err := r.SendReceiveSecured(ctx, sess, reqBytes)
	if err != nil {
		return &ErrHeartbeat{Err: err}
	}

	if resp[1] != uint8(codes.ResponseHeartbeatAck) {
		return &ErrHeartbeatUnexpectedResponseCode{Code: resp[1]}
	}

	logger.Debugf(ctx, "Heartbeat: received ACK")
	return nil
}

// KeyUpdate sends a KEY_UPDATE request within an established session per DSP0274
// Section 10.17. The operation parameter controls which keys are updated:
//   - KeyUpdateOpUpdateKey (1): update request-direction keys only
//   - KeyUpdateOpUpdateAllKeys (2): update both request and response keys
//
// Request keys are updated BEFORE sending (so the message is encrypted with new keys).
// If operation is UpdateAllKeys, response keys are updated AFTER receiving the ACK.
func (r *Requester) KeyUpdate(ctx context.Context, sessionID session.SessionID, operation uint8) error {
	logger.Debugf(ctx, "KeyUpdate: session=0x%08x op=%d", sessionID, operation)

	if operation < msgs.KeyUpdateOpUpdateKey || operation > msgs.KeyUpdateOpVerifyNewKey {
		return &ErrKeyUpdateInvalidOp{Operation: operation}
	}

	sess, err := r.getSession(sessionID)
	if err != nil {
		return &ErrKeyUpdate{Err: err}
	}

	// Update request keys BEFORE sending so the message uses the new key.
	// Note: if sending fails after this point, the session is in an inconsistent
	// state and cannot recover — this matches the spec's requirement that keys
	// must be rotated before the KEY_UPDATE message is sent.
	newHash := r.newHash()
	if err := sess.UpdateRequestKeys(newHash); err != nil {
		return &ErrKeyUpdateRequestKeys{Err: err}
	}

	ver := uint8(r.conn.PeerVersion)
	req := &msgs.KeyUpdate{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.RequestKeyUpdate),
			Param1:              operation,
			Param2:              1, // tag
		}},
	}

	reqBytes, err := req.Marshal()
	if err != nil {
		return &ErrKeyUpdateMarshal{Err: err}
	}

	resp, err := r.SendReceiveSecured(ctx, sess, reqBytes)
	if err != nil {
		return &ErrKeyUpdate{Err: err}
	}

	if resp[1] != uint8(codes.ResponseKeyUpdateAck) {
		return &ErrKeyUpdateUnexpectedResponseCode{Code: resp[1]}
	}

	// If UpdateAllKeys, also update response keys AFTER receiving ACK.
	if operation == msgs.KeyUpdateOpUpdateAllKeys {
		if err := sess.UpdateResponseKeys(newHash); err != nil {
			return &ErrKeyUpdateResponseKeys{Err: err}
		}
	}

	logger.Debugf(ctx, "KeyUpdate: completed op=%d", operation)
	return nil
}

// EndSession sends an END_SESSION request within an established session per DSP0274
// Section 10.19. On success it marks the session as ended and removes it from the
// requester's session map.
func (r *Requester) EndSession(ctx context.Context, sessionID session.SessionID) error {
	logger.Debugf(ctx, "EndSession: session=0x%08x", sessionID)

	sess, err := r.getSession(sessionID)
	if err != nil {
		return &ErrEndSession{Err: err}
	}

	ver := uint8(r.conn.PeerVersion)
	req := &msgs.EndSession{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.RequestEndSession),
		}},
	}

	reqBytes, err := req.Marshal()
	if err != nil {
		return &ErrEndSessionMarshal{Err: err}
	}

	resp, err := r.SendReceiveSecured(ctx, sess, reqBytes)
	if err != nil {
		return &ErrEndSession{Err: err}
	}

	if resp[1] != uint8(codes.ResponseEndSessionAck) {
		return &ErrEndSessionUnexpectedResponseCode{Code: resp[1]}
	}

	sess.State = session.StateEnded
	delete(r.sessions, sessionID)

	logger.Debugf(ctx, "EndSession: session 0x%08x ended", sessionID)
	return nil
}
