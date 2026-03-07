package responder

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
)

// handleRespondIfReady handles RESPOND_IF_READY per DSP0274 Section 10.18.
// The requester sends RESPOND_IF_READY when it previously received
// ERROR(ResponseNotReady). Since this responder never sends ResponseNotReady,
// receiving RESPOND_IF_READY is unexpected; return ERROR(UnsupportedRequest).
func (r *Responder) handleRespondIfReady(ctx context.Context, _ []byte) ([]byte, error) {
	logger.Debugf(ctx, "handleRespondIfReady: unsupported, returning ErrorUnsupportedRequest")
	return r.buildError(codes.ErrorUnsupportedRequest, 0), nil
}
