package requester

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

// VendorDefinedRequest sends VENDOR_DEFINED_REQUEST and returns the VENDOR_DEFINED_RESPONSE
// per DSP0274 Section 10.9.
func (r *Requester) VendorDefinedRequest(ctx context.Context, standardID uint16, vendorID, payload []byte) (*msgs.VendorDefinedResponse, error) {
	logger.Debugf(ctx, "VendorDefinedRequest: standardID=%d vendorIDLen=%d payloadLen=%d", standardID, len(vendorID), len(payload))

	ver := uint8(r.conn.PeerVersion)
	req := &msgs.VendorDefinedRequest{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.RequestVendorDefined),
		}},
		StandardID: standardID,
		VendorID:   vendorID,
		Payload:    payload,
	}

	resp, err := r.sendReceive(ctx, req)
	if err != nil {
		return nil, &ErrVendorDefined{Err: err}
	}

	if resp[1] != uint8(codes.ResponseVendorDefined) {
		return nil, &ErrVendorDefinedUnexpectedResponseCode{Code: resp[1]}
	}

	var vr msgs.VendorDefinedResponse
	if err := vr.Unmarshal(resp); err != nil {
		return nil, &ErrVendorDefined{Err: err}
	}

	logger.Debugf(ctx, "VendorDefinedRequest: received response payloadLen=%d", len(vr.Payload))
	return &vr, nil
}
