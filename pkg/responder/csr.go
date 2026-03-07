package responder

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

// CSRProvider generates Certificate Signing Requests per DSP0274 Section 10.22.
type CSRProvider interface {
	GenerateCSR(ctx context.Context, requesterInfo, opaqueData []byte) (csr []byte, err error)
}

func (r *Responder) handleGetCSR(ctx context.Context, request []byte) ([]byte, error) {
	if !r.negotiated {
		return r.buildError(codes.ErrorUnexpectedRequest, 0), nil
	}
	if r.cfg.CSRProvider == nil {
		return r.buildError(codes.ErrorUnsupportedRequest, 0), nil
	}

	var req msgs.GetCSR
	if err := req.Unmarshal(request); err != nil {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	csr, err := r.cfg.CSRProvider.GenerateCSR(ctx, req.RequesterInfo, req.OpaqueData)
	if err != nil {
		logger.Debugf(ctx, "handleGetCSR: provider error: %v", err)
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}

	resp := &msgs.CSRResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(r.version),
			RequestResponseCode: uint8(codes.ResponseCSR),
		}},
		CSR: csr,
	}

	logger.Debugf(ctx, "handleGetCSR: csrLen=%d", len(csr))
	return resp.Marshal()
}
