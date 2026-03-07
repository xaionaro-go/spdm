package qemusock

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

const (
	// CommandNormal indicates a normal SPDM message exchange.
	CommandNormal = 0x0001

	// CommandShutdown requests graceful shutdown of the connection.
	CommandShutdown = 0xFFFE

	// CommandTest is a keep-alive/echo command.
	CommandTest = 0xDEAD

	// TransportNone indicates no transport encapsulation.
	TransportNone = 0x00

	// TransportMCTP indicates MCTP transport encapsulation.
	TransportMCTP = 0x01

	// TransportPCIDOE indicates PCI DOE transport encapsulation.
	TransportPCIDOE = 0x02

	// TransportTCP indicates TCP transport encapsulation.
	TransportTCP = 0x03

	headerSize = 12

	// maxPayloadSize is the maximum payload size accepted by RecvCommand.
	// SPDM messages are typically under 64 KB; this limit prevents OOM
	// from corrupted or malicious peers.
	maxPayloadSize = 1 << 20 // 1 MB
)

// Conn provides low-level access to the QEMU SPDM socket protocol.
//
// Wire format (big-endian):
//
//	Command:       4 bytes
//	TransportType: 4 bytes
//	PayloadSize:   4 bytes
//	Payload:       PayloadSize bytes
type Conn struct {
	conn          io.ReadWriter
	transportType uint32
	mu            sync.Mutex
}

// NewConn creates a new Conn over the given connection with the specified
// transport type.
func NewConn(
	conn io.ReadWriter,
	transportType uint32,
) *Conn {
	return &Conn{
		conn:          conn,
		transportType: transportType,
	}
}

// SendCommand writes a framed command with the given payload to the connection.
func (c *Conn) SendCommand(
	command uint32,
	payload []byte,
) error {
	var hdr [headerSize]byte
	binary.BigEndian.PutUint32(hdr[0:4], command)
	binary.BigEndian.PutUint32(hdr[4:8], c.transportType)
	binary.BigEndian.PutUint32(hdr[8:12], uint32(len(payload)))

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, err := c.conn.Write(hdr[:]); err != nil {
		return &ErrWriteHeader{Err: err}
	}
	if len(payload) > 0 {
		if _, err := c.conn.Write(payload); err != nil {
			return &ErrWritePayload{Err: err}
		}
	}
	return nil
}

// RecvCommand reads a framed command from the connection.
//
// RecvCommand is NOT safe for concurrent use. When using a Bridge, the
// receiveLoop is the sole reader; callers must not call RecvCommand on
// the underlying Conn while the receive loop is running.
func (c *Conn) RecvCommand() (command uint32, payload []byte, err error) {
	var hdr [headerSize]byte
	if _, err := io.ReadFull(c.conn, hdr[:]); err != nil {
		return 0, nil, &ErrReadHeader{Err: err}
	}

	command = binary.BigEndian.Uint32(hdr[0:4])
	payloadSize := binary.BigEndian.Uint32(hdr[8:12])

	if payloadSize > maxPayloadSize {
		return 0, nil, &ErrReadPayload{
			Err: fmt.Errorf("payload size %d exceeds maximum %d", payloadSize, maxPayloadSize),
		}
	}

	if payloadSize > 0 {
		payload = make([]byte, payloadSize)
		if _, err := io.ReadFull(c.conn, payload); err != nil {
			return 0, nil, &ErrReadPayload{Err: err}
		}
	}

	return command, payload, nil
}

// Shutdown sends a CommandShutdown to the remote side.
func (c *Conn) Shutdown() error {
	return c.SendCommand(CommandShutdown, nil)
}

// TransportType returns the transport type configured for this connection.
func (c *Conn) TransportType() uint32 {
	return c.transportType
}
