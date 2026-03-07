package requester

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

// GetEncapsulatedRequest sends GET_ENCAPSULATED_REQUEST per DSP0274 Section 10.15.
// Returns the encapsulated SPDM request from the responder for mutual authentication.
func (r *Requester) GetEncapsulatedRequest(ctx context.Context) (*msgs.EncapsulatedRequestResponse, error) {
	logger.Debugf(ctx, "GetEncapsulatedRequest")

	ver := uint8(r.conn.PeerVersion)
	req := &msgs.GetEncapsulatedRequest{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.RequestGetEncapsulatedRequest),
		}},
	}

	resp, err := r.sendReceive(ctx, req)
	if err != nil {
		return nil, &ErrGetEncapsulatedRequest{Err: err}
	}

	if resp[1] != uint8(codes.ResponseEncapsulatedRequest) {
		return nil, &ErrGetEncapsulatedRequestUnexpectedResponseCode{Code: resp[1]}
	}

	var er msgs.EncapsulatedRequestResponse
	if err := er.Unmarshal(resp); err != nil {
		return nil, &ErrGetEncapsulatedRequest{Err: err}
	}

	logger.Debugf(ctx, "GetEncapsulatedRequest: received encapsulated data len=%d", len(er.EncapsulatedData))
	return &er, nil
}

// DeliverEncapsulatedResponse sends DELIVER_ENCAPSULATED_RESPONSE per DSP0274 Section 10.15.
// Delivers the requester's response to the responder's encapsulated request.
func (r *Requester) DeliverEncapsulatedResponse(
	ctx context.Context,
	requestID uint8,
	encapsulatedData []byte,
) (*msgs.EncapsulatedResponseAck, error) {
	logger.Debugf(ctx, "DeliverEncapsulatedResponse: requestID=%d dataLen=%d", requestID, len(encapsulatedData))

	ver := uint8(r.conn.PeerVersion)
	req := &msgs.DeliverEncapsulatedResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.RequestDeliverEncapsulatedResponse),
			Param1:              requestID,
		}},
		EncapsulatedData: encapsulatedData,
	}

	resp, err := r.sendReceive(ctx, req)
	if err != nil {
		return nil, &ErrDeliverEncapsulatedResponse{Err: err}
	}

	if resp[1] != uint8(codes.ResponseEncapsulatedResponseAck) {
		return nil, &ErrDeliverEncapsulatedResponseUnexpectedResponseCode{Code: resp[1]}
	}

	var ack msgs.EncapsulatedResponseAck
	if err := ack.Unmarshal(resp); err != nil {
		return nil, &ErrDeliverEncapsulatedResponse{Err: err}
	}

	logger.Debugf(ctx, "DeliverEncapsulatedResponse: received ack, encapsulated data len=%d", len(ack.EncapsulatedData))
	return &ack, nil
}
