package requester

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

// GetCSR sends GET_CSR and returns the CSR bytes per DSP0274 Section 10.22.
func (r *Requester) GetCSR(ctx context.Context, requesterInfo, opaqueData []byte) ([]byte, error) {
	logger.Debugf(ctx, "GetCSR: requesterInfoLen=%d opaqueDataLen=%d", len(requesterInfo), len(opaqueData))

	ver := uint8(r.conn.PeerVersion)
	req := &msgs.GetCSR{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.RequestGetCSR),
		}},
		RequesterInfo: requesterInfo,
		OpaqueData:    opaqueData,
	}

	resp, err := r.sendReceive(ctx, req)
	if err != nil {
		return nil, &ErrGetCSR{Err: err}
	}

	if resp[1] != uint8(codes.ResponseCSR) {
		return nil, &ErrGetCSRUnexpectedResponseCode{Code: resp[1]}
	}

	var cr msgs.CSRResponse
	if err := cr.Unmarshal(resp); err != nil {
		return nil, &ErrGetCSR{Err: err}
	}

	logger.Debugf(ctx, "GetCSR: received CSR len=%d", len(cr.CSR))
	return cr.CSR, nil
}
