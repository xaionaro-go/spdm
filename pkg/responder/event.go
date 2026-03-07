package responder

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
)

// handleGetSupportedEventTypes handles GET_SUPPORTED_EVENT_TYPES per DSP0274 Section 10.22.
// Event notifications are not supported by this responder, return ERROR(UnsupportedRequest).
func (r *Responder) handleGetSupportedEventTypes(ctx context.Context, _ []byte) ([]byte, error) {
	logger.Debugf(ctx, "handleGetSupportedEventTypes: unsupported, returning ErrorUnsupportedRequest")
	return r.buildError(codes.ErrorUnsupportedRequest, 0), nil
}

// handleSubscribeEventTypes handles SUBSCRIBE_EVENT_TYPES per DSP0274 Section 10.23.
// Event notifications are not supported by this responder, return ERROR(UnsupportedRequest).
func (r *Responder) handleSubscribeEventTypes(ctx context.Context, _ []byte) ([]byte, error) {
	logger.Debugf(ctx, "handleSubscribeEventTypes: unsupported, returning ErrorUnsupportedRequest")
	return r.buildError(codes.ErrorUnsupportedRequest, 0), nil
}

// handleSendEvent handles SEND_EVENT per DSP0274 Section 10.24.
// Event notifications are not supported by this responder, return ERROR(UnsupportedRequest).
func (r *Responder) handleSendEvent(ctx context.Context, _ []byte) ([]byte, error) {
	logger.Debugf(ctx, "handleSendEvent: unsupported, returning ErrorUnsupportedRequest")
	return r.buildError(codes.ErrorUnsupportedRequest, 0), nil
}
