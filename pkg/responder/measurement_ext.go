package responder

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

// MELProvider supplies Measurement Extension Log data per DSP0274 Section 10.24.
type MELProvider interface {
	GetMEL(ctx context.Context, offset, length uint32) (portion []byte, remainder uint32, err error)
}

func (r *Responder) handleGetMEL(ctx context.Context, request []byte) ([]byte, error) {
	if !r.negotiated {
		return r.buildError(codes.ErrorUnexpectedRequest, 0), nil
	}
	if r.cfg.MELProvider == nil {
		return r.buildError(codes.ErrorUnsupportedRequest, 0), nil
	}

	var req msgs.GetMeasurementExtensionLog
	if err := req.Unmarshal(request); err != nil {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	portion, remainder, err := r.cfg.MELProvider.GetMEL(ctx, req.Offset, req.Length)
	if err != nil {
		logger.Debugf(ctx, "handleGetMEL: provider error: %v", err)
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}

	resp := &msgs.MeasurementExtensionLogResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(r.version),
			RequestResponseCode: uint8(codes.ResponseMeasurementExtensionLog),
		}},
		MEL:             portion,
		RemainderLength: remainder,
	}

	logger.Debugf(ctx, "handleGetMEL: offset=%d portionLen=%d remainder=%d", req.Offset, len(portion), remainder)
	return resp.Marshal()
}
