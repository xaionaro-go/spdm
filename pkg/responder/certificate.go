package responder

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

func (r *Responder) handleGetCertificate(ctx context.Context, request []byte) ([]byte, error) {
	if !r.negotiated {
		return r.buildError(codes.ErrorUnexpectedRequest, 0), nil
	}
	if r.cfg.CertProvider == nil {
		return r.buildError(codes.ErrorUnsupportedRequest, 0), nil
	}

	var req msgs.GetCertificate
	if err := req.Unmarshal(request); err != nil {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	slotID := req.SlotID()
	chain, err := r.cfg.CertProvider.CertChain(ctx, slotID)
	if err != nil {
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}

	offset := int(req.Offset)
	length := int(req.Length)

	if offset >= len(chain) {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	end := offset + length
	if end > len(chain) {
		end = len(chain)
	}

	portion := chain[offset:end]
	remainder := len(chain) - end

	resp := &msgs.CertificateResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(r.version),
			RequestResponseCode: uint8(codes.ResponseCertificate),
			Param1:              slotID,
		}},
		PortionLength:   uint16(len(portion)),
		RemainderLength: uint16(remainder),
		CertChain:       portion,
	}
	data, err := resp.Marshal()
	if err != nil {
		return nil, err
	}
	// Record B transcript: GET_CERTIFICATE request + CERTIFICATE response.
	r.transcript = append(r.transcript, request...)
	r.transcript = append(r.transcript, data...)
	logger.Debugf(ctx, "handleGetCertificate: slot=%d offset=%d portion=%d remainder=%d",
		slotID, offset, len(portion), remainder)
	return data, nil
}
