package responder

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

func (r *Responder) handleGetDigests(ctx context.Context, request []byte) ([]byte, error) {
	if !r.negotiated {
		return r.buildError(codes.ErrorUnexpectedRequest, 0), nil
	}
	if r.cfg.CertProvider == nil {
		return r.buildError(codes.ErrorUnsupportedRequest, 0), nil
	}

	var slotMask uint8
	var digests [][]byte

	// Try slots 0-7 for provisioned certificates.
	for slot := uint8(0); slot < 8; slot++ {
		d, err := r.cfg.CertProvider.DigestForSlot(ctx, slot)
		if err != nil || len(d) == 0 {
			continue
		}
		slotMask |= 1 << slot
		digests = append(digests, d)
	}

	if slotMask == 0 {
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}

	resp := &msgs.DigestResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(r.version),
			RequestResponseCode: uint8(codes.ResponseDigests),
			Param1:              slotMask, // supported_slot_mask (1.3+)
			Param2:              slotMask, // provisioned_slot_mask
		}},
		Digests: digests,
	}
	data, err := resp.Marshal()
	if err != nil {
		return nil, err
	}
	// Record B transcript: GET_DIGESTS request + DIGESTS response.
	r.transcript = append(r.transcript, request...)
	r.transcript = append(r.transcript, data...)
	logger.Debugf(ctx, "handleGetDigests: slotMask=0x%02X digestCount=%d", slotMask, len(digests))
	return data, nil
}
