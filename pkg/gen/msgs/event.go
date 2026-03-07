package msgs

import "github.com/xaionaro-go/spdm/pkg/gen/codes"

// GetSupportedEventTypes is the SPDM GET_SUPPORTED_EVENT_TYPES request
// per DSP0274 Section 10.22.
type GetSupportedEventTypes struct {
	Header MessageHeader
}

func (m *GetSupportedEventTypes) RequestCode() codes.RequestCode {
	return codes.RequestGetSupportedEventTypes
}

func (m *GetSupportedEventTypes) Marshal() ([]byte, error)    { return m.Header.Marshal() }
func (m *GetSupportedEventTypes) Unmarshal(data []byte) error { return m.Header.Unmarshal(data) }

// SupportedEventTypesResponse is the SPDM SUPPORTED_EVENT_TYPES response
// per DSP0274 Section 10.22.
type SupportedEventTypesResponse struct {
	Header              MessageHeader
	SupportedEventCount uint8
	EventGroupData      []byte
}

func (m *SupportedEventTypesResponse) ResponseCode() codes.ResponseCode {
	return codes.ResponseSupportedEventTypes
}

func (m *SupportedEventTypesResponse) Marshal() ([]byte, error) {
	buf := make([]byte, 0, HeaderSize+1+len(m.EventGroupData))
	hdr, _ := m.Header.Marshal()
	buf = append(buf, hdr...)
	buf = append(buf, m.SupportedEventCount)
	buf = append(buf, m.EventGroupData...)
	return buf, nil
}

func (m *SupportedEventTypesResponse) Unmarshal(data []byte) error {
	if len(data) < HeaderSize+1 {
		return ErrShortBuffer
	}
	if err := m.Header.Unmarshal(data); err != nil {
		return err
	}
	m.SupportedEventCount = data[HeaderSize]
	if len(data) > HeaderSize+1 {
		m.EventGroupData = make([]byte, len(data)-HeaderSize-1)
		copy(m.EventGroupData, data[HeaderSize+1:])
	}
	return nil
}

// SubscribeEventTypes is the SPDM SUBSCRIBE_EVENT_TYPES request
// per DSP0274 Section 10.23.
type SubscribeEventTypes struct {
	Header         MessageHeader
	SubscribeCount uint8
	EventGroupData []byte
}

func (m *SubscribeEventTypes) RequestCode() codes.RequestCode {
	return codes.RequestSubscribeEventTypes
}

func (m *SubscribeEventTypes) Marshal() ([]byte, error) {
	buf := make([]byte, 0, HeaderSize+1+len(m.EventGroupData))
	hdr, _ := m.Header.Marshal()
	buf = append(buf, hdr...)
	buf = append(buf, m.SubscribeCount)
	buf = append(buf, m.EventGroupData...)
	return buf, nil
}

func (m *SubscribeEventTypes) Unmarshal(data []byte) error {
	if len(data) < HeaderSize+1 {
		return ErrShortBuffer
	}
	if err := m.Header.Unmarshal(data); err != nil {
		return err
	}
	m.SubscribeCount = data[HeaderSize]
	if len(data) > HeaderSize+1 {
		m.EventGroupData = make([]byte, len(data)-HeaderSize-1)
		copy(m.EventGroupData, data[HeaderSize+1:])
	}
	return nil
}

// SubscribeEventTypesAckResponse is the SPDM SUBSCRIBE_EVENT_TYPES_ACK response
// per DSP0274 Section 10.23.
type SubscribeEventTypesAckResponse struct {
	Header MessageHeader
}

func (m *SubscribeEventTypesAckResponse) ResponseCode() codes.ResponseCode {
	return codes.ResponseSubscribeEventTypesAck
}

func (m *SubscribeEventTypesAckResponse) Marshal() ([]byte, error) { return m.Header.Marshal() }
func (m *SubscribeEventTypesAckResponse) Unmarshal(data []byte) error {
	return m.Header.Unmarshal(data)
}

// SendEvent is the SPDM SEND_EVENT request per DSP0274 Section 10.24.
type SendEvent struct {
	Header    MessageHeader
	EventData []byte
}

func (m *SendEvent) RequestCode() codes.RequestCode {
	return codes.RequestSendEvent
}

func (m *SendEvent) Marshal() ([]byte, error) {
	buf := make([]byte, 0, HeaderSize+len(m.EventData))
	hdr, _ := m.Header.Marshal()
	buf = append(buf, hdr...)
	buf = append(buf, m.EventData...)
	return buf, nil
}

func (m *SendEvent) Unmarshal(data []byte) error {
	if err := m.Header.Unmarshal(data); err != nil {
		return err
	}
	if len(data) > HeaderSize {
		m.EventData = make([]byte, len(data)-HeaderSize)
		copy(m.EventData, data[HeaderSize:])
	}
	return nil
}

// EventAckResponse is the SPDM EVENT_ACK response per DSP0274 Section 10.24.
type EventAckResponse struct {
	Header MessageHeader
}

func (m *EventAckResponse) ResponseCode() codes.ResponseCode {
	return codes.ResponseEventAck
}

func (m *EventAckResponse) Marshal() ([]byte, error)    { return m.Header.Marshal() }
func (m *EventAckResponse) Unmarshal(data []byte) error { return m.Header.Unmarshal(data) }
