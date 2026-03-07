package responder

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

// EndpointInfoProvider supplies endpoint information per DSP0274 Section 10.26.
type EndpointInfoProvider interface {
	GetEndpointInfo(ctx context.Context, subCode uint8) ([]byte, error)
}

func (r *Responder) handleGetEndpointInfo(ctx context.Context, request []byte) ([]byte, error) {
	if !r.negotiated {
		return r.buildError(codes.ErrorUnexpectedRequest, 0), nil
	}
	if r.cfg.EndpointInfoProvider == nil {
		return r.buildError(codes.ErrorUnsupportedRequest, 0), nil
	}

	var req msgs.GetEndpointInfo
	if err := req.Unmarshal(request); err != nil {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	subCode := req.Header.Param1
	info, err := r.cfg.EndpointInfoProvider.GetEndpointInfo(ctx, subCode)
	if err != nil {
		logger.Debugf(ctx, "handleGetEndpointInfo: provider error: %v", err)
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}

	resp := &msgs.EndpointInfoResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(r.version),
			RequestResponseCode: uint8(codes.ResponseEndpointInfo),
		}},
		EndpointInfo: info,
	}

	logger.Debugf(ctx, "handleGetEndpointInfo: subCode=%d infoLen=%d", subCode, len(info))
	return resp.Marshal()
}
