package requester

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

// GetMeasurementExtensionLog sends GET_MEASUREMENT_EXTENSION_LOG per DSP0274 Section 10.24.
func (r *Requester) GetMeasurementExtensionLog(ctx context.Context, offset, length uint32) (*msgs.MeasurementExtensionLogResponse, error) {
	logger.Debugf(ctx, "GetMeasurementExtensionLog: offset=%d length=%d", offset, length)

	ver := uint8(r.conn.PeerVersion)
	req := &msgs.GetMeasurementExtensionLog{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.RequestGetMeasurementExtensionLog),
		}},
		Offset: offset,
		Length: length,
	}

	resp, err := r.sendReceive(ctx, req)
	if err != nil {
		return nil, &ErrGetMEL{Err: err}
	}

	if resp[1] != uint8(codes.ResponseMeasurementExtensionLog) {
		return nil, &ErrGetMELUnexpectedResponseCode{Code: resp[1]}
	}

	var mr msgs.MeasurementExtensionLogResponse
	if err := mr.Unmarshal(resp); err != nil {
		return nil, &ErrGetMEL{Err: err}
	}

	logger.Debugf(ctx, "GetMeasurementExtensionLog: portionLen=%d remainder=%d", mr.PortionLength, mr.RemainderLength)
	return &mr, nil
}
