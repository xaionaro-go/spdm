package tcp

import (
	"encoding/binary"

	"github.com/xaionaro-go/spdm/pkg/transport"
)

const (
	TCPMessageTypeOutOfSession            = 0x05
	TCPMessageTypeInSession               = 0x06
	TCPMessageTypeRoleInquiry             = 0xBF
	TCPErrorTooLarge                      = 0xC0
	TCPErrorNotSupported                  = 0xC1
	TCPErrorCannotOperateAsRequester      = 0xC2
	TCPErrorCannotOperateAsResponder      = 0xC3
	TCPSequenceNumberCount                = 0
	TCPMaxRandomNumberCount               = 0
	TCPBindingHeaderSize             uint = 4
)

var le = binary.LittleEndian

// TCPBindingHeader is the 4-byte SPDM-over-TCP binding header per DSP0287.
type TCPBindingHeader struct {
	PayloadLength  uint16
	BindingVersion uint8
	MessageType    uint8
}

// Marshal serializes the header into a 4-byte little-endian buffer.
func (h *TCPBindingHeader) Marshal() ([]byte, error) {
	buf := make([]byte, TCPBindingHeaderSize)
	le.PutUint16(buf[0:2], h.PayloadLength)
	buf[2] = h.BindingVersion
	buf[3] = h.MessageType
	return buf, nil
}

// Unmarshal deserializes a 4-byte little-endian buffer into the header.
func (h *TCPBindingHeader) Unmarshal(data []byte) error {
	if uint(len(data)) < TCPBindingHeaderSize {
		return transport.ErrShortBuffer
	}

	h.PayloadLength = le.Uint16(data[0:2])
	h.BindingVersion = data[2]
	h.MessageType = data[3]
	return nil
}
