package qemusock

import (
	"encoding/binary"
	"io"

	"github.com/xaionaro-go/spdm/pkg/transport/pcidoe"
)

const doeHeaderSize = 8

// ServerLoop runs a request-response loop over the QEMU SPDM socket protocol.
// It handles TEST commands (echo back) and SHUTDOWN (graceful exit)
// transparently. For each normal command, processFn is called with the
// request payload and the returned response is sent back.
func ServerLoop(
	conn io.ReadWriter,
	transportType uint32,
	processFn func(request []byte) ([]byte, error),
) error {
	c := NewConn(conn, transportType)

	for {
		cmd, payload, err := c.RecvCommand()
		if err != nil {
			return err
		}

		switch cmd {
		case CommandTest:
			if err := c.SendCommand(CommandTest, nil); err != nil {
				return err
			}
		case CommandShutdown:
			_ = c.SendCommand(CommandShutdown, nil)
			return nil
		case CommandNormal:
			response, err := processFn(payload)
			if err != nil {
				return err
			}
			if err := c.SendCommand(CommandNormal, response); err != nil {
				return err
			}
		default:
			return &ErrUnexpectedCommand{Command: cmd}
		}
	}
}

// ServerLoopDOE runs a request-response loop like ServerLoop, but wraps
// the processFn with PCI DOE framing: the 8-byte DOE header is stripped
// from incoming requests before calling processFn, and a DOE header is
// prepended to the response.
func ServerLoopDOE(
	conn io.ReadWriter,
	processFn func(request []byte) ([]byte, error),
) error {
	return ServerLoop(conn, TransportPCIDOE, func(request []byte) ([]byte, error) {
		if len(request) < doeHeaderSize {
			return nil, &ErrReadPayload{Err: io.ErrUnexpectedEOF}
		}
		spdmRequest := request[doeHeaderSize:]

		spdmResponse, err := processFn(spdmRequest)
		if err != nil {
			return nil, err
		}

		totalBytes := doeHeaderSize + len(spdmResponse)
		padded := (totalBytes + 3) &^ 3
		lengthDW := uint32(padded / 4)

		frame := make([]byte, padded)
		binary.LittleEndian.PutUint16(frame[0:2], pcidoe.DOEVendorIDPCISIG)
		frame[2] = pcidoe.DOEDataObjectTypeSPDM
		frame[3] = 0
		binary.LittleEndian.PutUint32(frame[4:8], lengthDW)
		copy(frame[doeHeaderSize:], spdmResponse)

		return frame, nil
	})
}
