package requester

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

// GetSupportedEventTypes sends GET_SUPPORTED_EVENT_TYPES per DSP0274 Section 10.22.
// Returns the raw event group data from the responder.
func (r *Requester) GetSupportedEventTypes(
	ctx context.Context,
) (_result []byte, _err error) {
	logger.Tracef(ctx, "GetSupportedEventTypes")
	defer func() { logger.Tracef(ctx, "/GetSupportedEventTypes: %v", _err) }()

	ver := uint8(r.conn.PeerVersion)
	req := &msgs.GetSupportedEventTypes{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.RequestGetSupportedEventTypes),
		}},
	}

	resp, err := r.sendReceive(ctx, req)
	if err != nil {
		return nil, &ErrGetSupportedEventTypes{Err: err}
	}

	if resp[1] != uint8(codes.ResponseSupportedEventTypes) {
		return nil, &ErrGetSupportedEventTypesUnexpectedResponseCode{Code: resp[1]}
	}

	var setr msgs.SupportedEventTypesResponse
	if err := setr.Unmarshal(resp); err != nil {
		return nil, &ErrGetSupportedEventTypes{Err: err}
	}

	logger.Debugf(ctx, "GetSupportedEventTypes: count=%d data_len=%d", setr.SupportedEventCount, len(setr.EventGroupData))
	return setr.EventGroupData, nil
}

// SubscribeEventTypes sends SUBSCRIBE_EVENT_TYPES per DSP0274 Section 10.23.
// eventGroups contains the serialized event group subscription data.
func (r *Requester) SubscribeEventTypes(
	ctx context.Context,
	eventGroups []byte,
) (_err error) {
	logger.Tracef(ctx, "SubscribeEventTypes")
	defer func() { logger.Tracef(ctx, "/SubscribeEventTypes: %v", _err) }()

	ver := uint8(r.conn.PeerVersion)
	req := &msgs.SubscribeEventTypes{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.RequestSubscribeEventTypes),
		}},
		EventGroupData: eventGroups,
	}

	resp, err := r.sendReceive(ctx, req)
	if err != nil {
		return &ErrSubscribeEventTypes{Err: err}
	}

	if resp[1] != uint8(codes.ResponseSubscribeEventTypesAck) {
		return &ErrSubscribeEventTypesUnexpectedResponseCode{Code: resp[1]}
	}

	return nil
}

// SendEvent sends SEND_EVENT per DSP0274 Section 10.24.
// eventData contains the serialized event notification data.
func (r *Requester) SendEvent(
	ctx context.Context,
	eventData []byte,
) (_err error) {
	logger.Tracef(ctx, "SendEvent")
	defer func() { logger.Tracef(ctx, "/SendEvent: %v", _err) }()

	ver := uint8(r.conn.PeerVersion)
	req := &msgs.SendEvent{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.RequestSendEvent),
		}},
		EventData: eventData,
	}

	resp, err := r.sendReceive(ctx, req)
	if err != nil {
		return &ErrSendEvent{Err: err}
	}

	if resp[1] != uint8(codes.ResponseEventAck) {
		return &ErrSendEventUnexpectedResponseCode{Code: resp[1]}
	}

	return nil
}
