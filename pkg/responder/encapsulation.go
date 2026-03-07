package responder

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
)

// handleGetEncapsulatedRequest handles GET_ENCAPSULATED_REQUEST per DSP0274 Section 10.15.
// Encapsulated messages support mutual authentication. Since ENCAP_CAP is not
// advertised by this responder, return ERROR(UnsupportedRequest).
func (r *Responder) handleGetEncapsulatedRequest(ctx context.Context, _ []byte) ([]byte, error) {
	logger.Debugf(ctx, "handleGetEncapsulatedRequest: unsupported, returning ErrorUnsupportedRequest")
	return r.buildError(codes.ErrorUnsupportedRequest, 0), nil
}

// handleDeliverEncapsulatedResponse handles DELIVER_ENCAPSULATED_RESPONSE per DSP0274 Section 10.15.
// Encapsulated messages support mutual authentication. Since ENCAP_CAP is not
// advertised by this responder, return ERROR(UnsupportedRequest).
func (r *Responder) handleDeliverEncapsulatedResponse(ctx context.Context, _ []byte) ([]byte, error) {
	logger.Debugf(ctx, "handleDeliverEncapsulatedResponse: unsupported, returning ErrorUnsupportedRequest")
	return r.buildError(codes.ErrorUnsupportedRequest, 0), nil
}
