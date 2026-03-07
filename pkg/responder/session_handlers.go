package responder

import (
	"context"
	"hash"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

func (r *Responder) handleHeartbeat(ctx context.Context, request []byte) ([]byte, error) {
	var req msgs.Heartbeat
	if err := req.Unmarshal(request); err != nil {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	resp := &msgs.HeartbeatResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(r.version),
			RequestResponseCode: uint8(codes.ResponseHeartbeatAck),
		}},
	}
	logger.Debugf(ctx, "handleHeartbeat")
	return resp.Marshal()
}

func (r *Responder) handleKeyUpdate(ctx context.Context, request []byte) ([]byte, error) {
	var req msgs.KeyUpdate
	if err := req.Unmarshal(request); err != nil {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	op := req.Header.Param1
	logger.Debugf(ctx, "handleKeyUpdate: op=%d tag=%d", op, req.Header.Param2)

	sess := r.ActiveSession()
	if sess == nil {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	newHash := func() hash.Hash { return r.hashAlgo.CryptoHash().New() }

	// Per DSP0274 Section 10.17: update request-direction keys immediately.
	// Response-direction keys are updated AFTER the ACK is sent (deferred).
	switch op {
	case msgs.KeyUpdateOpUpdateKey:
		// Update requester (request direction) keys only.
		if err := sess.UpdateRequestKeys(newHash); err != nil {
			return r.buildError(codes.ErrorUnspecified, 0), nil
		}
	case msgs.KeyUpdateOpUpdateAllKeys:
		// Update request keys now; response keys will be updated after ACK is sent.
		if err := sess.UpdateRequestKeys(newHash); err != nil {
			return r.buildError(codes.ErrorUnspecified, 0), nil
		}
		// Mark that response keys need updating after this response is encrypted.
		sess.PendingResponseKeyUpdate = true
	case msgs.KeyUpdateOpVerifyNewKey:
		// No key update — just verify the requester can use the new key.
	}

	resp := &msgs.KeyUpdateResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(r.version),
			RequestResponseCode: uint8(codes.ResponseKeyUpdateAck),
			Param1:              op,
			Param2:              req.Header.Param2,
		}},
	}
	return resp.Marshal()
}

func (r *Responder) handleEndSession(ctx context.Context, request []byte) ([]byte, error) {
	var req msgs.EndSession
	if err := req.Unmarshal(request); err != nil {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	logger.Debugf(ctx, "handleEndSession")
	resp := &msgs.EndSessionResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(r.version),
			RequestResponseCode: uint8(codes.ResponseEndSessionAck),
		}},
	}
	return resp.Marshal()
}

func (r *Responder) handleVendorDefined(ctx context.Context, request []byte) ([]byte, error) {
	var req msgs.VendorDefinedRequest
	if err := req.Unmarshal(request); err != nil {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	logger.Debugf(ctx, "handleVendorDefined: standardID=%d", req.StandardID)
	// Echo back with empty payload.
	resp := &msgs.VendorDefinedResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(r.version),
			RequestResponseCode: uint8(codes.ResponseVendorDefined),
		}},
		StandardID: req.StandardID,
		VendorID:   req.VendorID,
	}
	return resp.Marshal()
}
