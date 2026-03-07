package requester

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

// RespondIfReady sends RESPOND_IF_READY per DSP0274 Section 10.18.
// Param1 = original request code that received ResponseNotReady, Param2 = token.
// Returns the raw response bytes for the caller to parse according to the
// original request type.
func (r *Requester) RespondIfReady(
	ctx context.Context,
	originalRequestCode codes.RequestCode,
	token uint8,
) ([]byte, error) {
	logger.Debugf(ctx, "RespondIfReady: originalRequestCode=%s token=%d", originalRequestCode, token)

	ver := uint8(r.conn.PeerVersion)
	req := &msgs.RespondIfReady{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.RequestRespondIfReady),
			Param1:              uint8(originalRequestCode),
			Param2:              token,
		}},
	}

	resp, err := r.sendReceive(ctx, req)
	if err != nil {
		return nil, &ErrRespondIfReady{Err: err}
	}

	logger.Debugf(ctx, "RespondIfReady: received response code 0x%02X", resp[1])
	return resp, nil
}
