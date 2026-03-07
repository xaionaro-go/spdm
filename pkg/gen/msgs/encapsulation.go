package msgs

import "github.com/xaionaro-go/spdm/pkg/gen/codes"

// GetEncapsulatedRequest is the SPDM GET_ENCAPSULATED_REQUEST request
// per DSP0274 Section 10.15.
type GetEncapsulatedRequest struct {
	Header MessageHeader
}

func (m *GetEncapsulatedRequest) RequestCode() codes.RequestCode {
	return codes.RequestGetEncapsulatedRequest
}

func (m *GetEncapsulatedRequest) Marshal() ([]byte, error)    { return m.Header.Marshal() }
func (m *GetEncapsulatedRequest) Unmarshal(data []byte) error { return m.Header.Unmarshal(data) }

// EncapsulatedRequestResponse is the SPDM ENCAPSULATED_REQUEST response
// per DSP0274 Section 10.15.
type EncapsulatedRequestResponse struct {
	Header           MessageHeader
	EncapsulatedData []byte
}

func (m *EncapsulatedRequestResponse) ResponseCode() codes.ResponseCode {
	return codes.ResponseEncapsulatedRequest
}

func (m *EncapsulatedRequestResponse) Marshal() ([]byte, error) {
	buf := make([]byte, 0, HeaderSize+len(m.EncapsulatedData))
	hdr, _ := m.Header.Marshal()
	buf = append(buf, hdr...)
	buf = append(buf, m.EncapsulatedData...)
	return buf, nil
}

func (m *EncapsulatedRequestResponse) Unmarshal(data []byte) error {
	if err := m.Header.Unmarshal(data); err != nil {
		return err
	}
	if len(data) > HeaderSize {
		m.EncapsulatedData = make([]byte, len(data)-HeaderSize)
		copy(m.EncapsulatedData, data[HeaderSize:])
	}
	return nil
}

// DeliverEncapsulatedResponse is the SPDM DELIVER_ENCAPSULATED_RESPONSE request
// per DSP0274 Section 10.15.
type DeliverEncapsulatedResponse struct {
	Header           MessageHeader
	EncapsulatedData []byte
}

func (m *DeliverEncapsulatedResponse) RequestCode() codes.RequestCode {
	return codes.RequestDeliverEncapsulatedResponse
}

func (m *DeliverEncapsulatedResponse) Marshal() ([]byte, error) {
	buf := make([]byte, 0, HeaderSize+len(m.EncapsulatedData))
	hdr, _ := m.Header.Marshal()
	buf = append(buf, hdr...)
	buf = append(buf, m.EncapsulatedData...)
	return buf, nil
}

func (m *DeliverEncapsulatedResponse) Unmarshal(data []byte) error {
	if err := m.Header.Unmarshal(data); err != nil {
		return err
	}
	if len(data) > HeaderSize {
		m.EncapsulatedData = make([]byte, len(data)-HeaderSize)
		copy(m.EncapsulatedData, data[HeaderSize:])
	}
	return nil
}

// EncapsulatedResponseAck is the SPDM ENCAPSULATED_RESPONSE_ACK response
// per DSP0274 Section 10.15.
type EncapsulatedResponseAck struct {
	Header           MessageHeader
	EncapsulatedData []byte
}

func (m *EncapsulatedResponseAck) ResponseCode() codes.ResponseCode {
	return codes.ResponseEncapsulatedResponseAck
}

func (m *EncapsulatedResponseAck) Marshal() ([]byte, error) {
	buf := make([]byte, 0, HeaderSize+len(m.EncapsulatedData))
	hdr, _ := m.Header.Marshal()
	buf = append(buf, hdr...)
	buf = append(buf, m.EncapsulatedData...)
	return buf, nil
}

func (m *EncapsulatedResponseAck) Unmarshal(data []byte) error {
	if err := m.Header.Unmarshal(data); err != nil {
		return err
	}
	if len(data) > HeaderSize {
		m.EncapsulatedData = make([]byte, len(data)-HeaderSize)
		copy(m.EncapsulatedData, data[HeaderSize:])
	}
	return nil
}
