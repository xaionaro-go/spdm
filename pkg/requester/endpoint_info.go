package requester

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

// GetEndpointInfo sends GET_ENDPOINT_INFO per DSP0274 Section 10.26.
// Param1 = subCode identifies which endpoint info is requested.
func (r *Requester) GetEndpointInfo(ctx context.Context, subCode uint8) ([]byte, error) {
	logger.Debugf(ctx, "GetEndpointInfo: subCode=%d", subCode)

	ver := uint8(r.conn.PeerVersion)
	req := &msgs.GetEndpointInfo{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.RequestGetEndpointInfo),
			Param1:              subCode,
		}},
	}

	resp, err := r.sendReceive(ctx, req)
	if err != nil {
		return nil, &ErrGetEndpointInfo{Err: err}
	}

	if resp[1] != uint8(codes.ResponseEndpointInfo) {
		return nil, &ErrGetEndpointInfoUnexpectedResponseCode{Code: resp[1]}
	}

	var eir msgs.EndpointInfoResponse
	if err := eir.Unmarshal(resp); err != nil {
		return nil, &ErrGetEndpointInfo{Err: err}
	}

	logger.Debugf(ctx, "GetEndpointInfo: received len=%d remainder=%d", len(eir.EndpointInfo), eir.RemainderLength)
	return eir.EndpointInfo, nil
}
