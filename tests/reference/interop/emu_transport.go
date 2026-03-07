//go:build reference

// Package interop provides transport and test harness for interop testing
// against the DMTF spdm-emu reference implementation.
package interop

import (
	"context"
	"fmt"
	"net"

	"github.com/xaionaro-go/spdm/pkg/transport/qemusock"
)

// EmuTransport implements transport.Transport for communicating with spdm-emu
// over TCP using the spdm-emu socket protocol framing.
type EmuTransport struct {
	conn    *qemusock.Conn
	rawConn net.Conn
}

// NewEmuTransport creates a transport connected to spdm-emu at the given address.
// transportType should be one of qemusock.Transport* constants.
func NewEmuTransport(conn net.Conn, transportType uint32) *EmuTransport {
	return &EmuTransport{
		conn:    qemusock.NewConn(conn, transportType),
		rawConn: conn,
	}
}

func (t *EmuTransport) SendMessage(_ context.Context, _ *uint32, msg []byte) error {
	return t.conn.SendCommand(qemusock.CommandNormal, msg)
}

func (t *EmuTransport) ReceiveMessage(_ context.Context) (*uint32, []byte, error) {
	_, payload, err := t.conn.RecvCommand()
	if err != nil {
		return nil, nil, err
	}
	return nil, payload, nil
}

// ReceiveMessageHandlingEmuProtocol is like ReceiveMessage but also handles
// spdm-emu socket protocol commands (TEST, SHUTDOWN) transparently.
func (t *EmuTransport) ReceiveMessageHandlingEmuProtocol(_ context.Context) (*uint32, []byte, error) {
	for {
		cmd, payload, err := t.conn.RecvCommand()
		if err != nil {
			return nil, nil, err
		}
		switch cmd {
		case qemusock.CommandTest:
			if err := t.conn.SendCommand(qemusock.CommandTest, nil); err != nil {
				return nil, nil, err
			}
			continue
		case qemusock.CommandShutdown:
			_ = t.conn.SendCommand(qemusock.CommandShutdown, nil)
			return nil, nil, fmt.Errorf("emu: shutdown received")
		default:
			return nil, payload, nil
		}
	}
}

func (t *EmuTransport) HeaderSize() int { return 0 }

// Shutdown sends a SHUTDOWN command to the spdm-emu process.
func (t *EmuTransport) Shutdown() error {
	return t.conn.Shutdown()
}

// Close closes the underlying TCP connection.
func (t *EmuTransport) Close() error {
	return t.rawConn.Close()
}

// Conn returns the underlying qemusock.Conn for direct protocol access.
func (t *EmuTransport) Conn() *qemusock.Conn {
	return t.conn
}
