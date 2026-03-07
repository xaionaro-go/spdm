package responder

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/caps"
	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

func (r *Responder) handleGetCapabilities(ctx context.Context, request []byte) ([]byte, error) {
	var req msgs.GetCapabilities
	if err := req.Unmarshal(request); err != nil {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	// Validate DataTransferSize per DSP0274 Section 10.4: minimum is 42 bytes.
	if req.DataTransferSize != 0 && req.DataTransferSize < 42 {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	// Replay detection per DSP0274 Section 10.4: identical GET_CAPABILITIES is allowed,
	// but non-identical after the first returns ERROR(UnexpectedRequest).
	if r.prevCaps != nil {
		if !capsEqual(r.prevCaps, &req) {
			return r.buildError(codes.ErrorUnexpectedRequest, 0), nil
		}
	}

	// Use the highest version we support as the negotiated version.
	// In a real flow, GET_VERSION already ran and the requester selected a version.
	if r.version == 0 && len(r.cfg.Versions) > 0 {
		r.version = r.cfg.Versions[len(r.cfg.Versions)-1]
	}

	r.peerCaps = caps.RequesterCaps(req.Flags)
	r.prevCaps = &req
	r.state = StateAfterCapabilities

	resp := &msgs.CapabilitiesResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(r.version),
			RequestResponseCode: uint8(codes.ResponseCapabilities),
		}},
		CTExponent:       r.cfg.CTExponent,
		Flags:            uint32(r.cfg.Caps),
		DataTransferSize: r.cfg.DataTransferSize,
		MaxSPDMmsgSize:   r.cfg.MaxSPDMmsgSize,
	}
	data, err := resp.Marshal()
	if err != nil {
		return nil, err
	}
	// Record VCA transcript: GET_CAPABILITIES request + CAPABILITIES response.
	r.transcript = append(r.transcript, request...)
	r.transcript = append(r.transcript, data...)
	logger.Debugf(ctx, "handleGetCapabilities: negotiated version=%s peerCaps=0x%08X", r.version, uint32(r.peerCaps))
	return data, nil
}

// capsEqual compares two GET_CAPABILITIES requests for replay detection per DSP0274 Section 10.4.
func capsEqual(a, b *msgs.GetCapabilities) bool {
	return a.CTExponent == b.CTExponent &&
		a.Flags == b.Flags &&
		a.DataTransferSize == b.DataTransferSize &&
		a.MaxSPDMmsgSize == b.MaxSPDMmsgSize
}
