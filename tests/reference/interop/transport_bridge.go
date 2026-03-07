//go:build reference

package interop

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/xaionaro-go/spdm/pkg/transport/qemusock"
)

// MCTPSocketBridge adapts between the spdm-emu socket protocol (with MCTP
// transport type) and an io.ReadWriter expected by mctp.Transport.
//
// spdm-emu sends/receives: [12B socket header][MCTP payload]
// mctp.Transport sends/receives: [4B length][MCTP type byte][SPDM bytes]
//
// The bridge sits in the middle, translating between these two framings.
type MCTPSocketBridge struct {
	conn      *qemusock.Conn
	raw       net.Conn
	mu        sync.Mutex
	pr        *io.PipeReader
	pw        *io.PipeWriter
	done      chan struct{}
	closeOnce sync.Once
}

// NewMCTPSocketBridge creates a bridge that reads MCTP-framed data from
// spdm-emu and makes it available via the returned io.ReadWriter for
// mctp.Transport.
func NewMCTPSocketBridge(conn net.Conn) *MCTPSocketBridge {
	pr, pw := io.Pipe()
	return &MCTPSocketBridge{
		conn: qemusock.NewConn(conn, qemusock.TransportMCTP),
		raw:  conn,
		pr:   pr,
		pw:   pw,
		done: make(chan struct{}),
	}
}

// ReadWriter returns the io.ReadWriter to pass to mctp.New().
// Reads from this return MCTP-framed data received from spdm-emu.
// Writes to this send MCTP-framed data to spdm-emu.
func (b *MCTPSocketBridge) ReadWriter() io.ReadWriter {
	return &bridgeRW{bridge: b}
}

// StartReceiveLoop starts a goroutine that reads from the spdm-emu socket
// and writes length-prefixed MCTP frames to the pipe for mctp.Transport.
func (b *MCTPSocketBridge) StartReceiveLoop() {
	go func() {
		defer b.pw.Close()
		for {
			select {
			case <-b.done:
				return
			default:
			}

			cmd, payload, err := b.conn.RecvCommand()
			if err != nil {
				b.pw.CloseWithError(err)
				return
			}

			switch cmd {
			case qemusock.CommandShutdown:
				return
			case qemusock.CommandTest:
				b.mu.Lock()
				_ = b.conn.SendCommand(qemusock.CommandTest, nil)
				b.mu.Unlock()
				continue
			case qemusock.CommandNormal:
				if len(payload) == 0 {
					continue
				}
				// Write length-prefixed frame for mctp.Transport:
				// [4B big-endian length][MCTP payload]
				var lenBuf [4]byte
				binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
				if _, err := b.pw.Write(lenBuf[:]); err != nil {
					return
				}
				if _, err := b.pw.Write(payload); err != nil {
					return
				}
			default:
				continue
			}
		}
	}()
}

// Close shuts down the bridge. It is safe to call Close multiple times.
func (b *MCTPSocketBridge) Close() error {
	b.closeOnce.Do(func() {
		close(b.done)
	})
	b.pr.Close()
	b.pw.Close()
	return b.raw.Close()
}

type bridgeRW struct {
	bridge *MCTPSocketBridge
}

func (rw *bridgeRW) Read(p []byte) (int, error) {
	return rw.bridge.pr.Read(p)
}

func (rw *bridgeRW) Write(p []byte) (int, error) {
	// mctp.Transport writes: [4B length][MCTP type byte][SPDM]
	// We need to strip the 4B length prefix and send the rest
	// via the spdm-emu socket protocol with MCTP transport type.
	if len(p) < 4 {
		return 0, fmt.Errorf("bridge: write too short")
	}
	payloadLen := binary.BigEndian.Uint32(p[:4])
	if uint32(len(p)-4) < payloadLen {
		return 0, fmt.Errorf("bridge: payload length %d exceeds buffer size %d", payloadLen, len(p)-4)
	}
	mctpPayload := p[4 : 4+payloadLen]

	rw.bridge.mu.Lock()
	defer rw.bridge.mu.Unlock()
	if err := rw.bridge.conn.SendCommand(qemusock.CommandNormal, mctpPayload); err != nil {
		return 0, err
	}
	return len(p), nil
}

// DOESocketBridge adapts between the spdm-emu socket protocol (with PCI_DOE
// transport type) and an io.ReadWriter expected by pcidoe.Transport.
//
// spdm-emu sends/receives: [12B socket header][DOE frame]
// pcidoe.Transport sends/receives raw DOE frames directly on the connection.
type DOESocketBridge struct {
	bridge *qemusock.Bridge
	raw    net.Conn
}

// NewDOESocketBridge creates a bridge for PCI DOE transport.
func NewDOESocketBridge(conn net.Conn) *DOESocketBridge {
	return &DOESocketBridge{
		bridge: qemusock.NewBridge(conn, qemusock.TransportPCIDOE),
		raw:    conn,
	}
}

// ReadWriter returns the io.ReadWriter to pass to pcidoe.New().
func (b *DOESocketBridge) ReadWriter() io.ReadWriter {
	return b.bridge
}

// StartReceiveLoop reads DOE frames from spdm-emu and writes them
// to the pipe for pcidoe.Transport to consume.
func (b *DOESocketBridge) StartReceiveLoop() {
	b.bridge.Start()
}

// Close shuts down the bridge.
func (b *DOESocketBridge) Close() error {
	b.bridge.Close()
	return b.raw.Close()
}
