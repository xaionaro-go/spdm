package qemusock

import (
	"fmt"
	"io"
	"sync"
)

// Bridge adapts between the QEMU SPDM socket protocol and an io.ReadWriter
// suitable for composing with transport layers such as pcidoe.Transport
// or mctp.Transport.
//
// The receive loop handles TEST commands (echo back) and SHUTDOWN (graceful
// stop) transparently. Normal command payloads are forwarded through an
// internal pipe.
type Bridge struct {
	conn      *Conn
	mu        sync.Mutex
	pr        *io.PipeReader
	pw        *io.PipeWriter
	done      chan struct{}
	closeOnce sync.Once
}

// NewBridge creates a Bridge over the given connection with the specified
// transport type.
func NewBridge(
	conn io.ReadWriter,
	transportType uint32,
) *Bridge {
	pr, pw := io.Pipe()
	return &Bridge{
		conn: NewConn(conn, transportType),
		pr:   pr,
		pw:   pw,
		done: make(chan struct{}),
	}
}

// Start launches the background receive loop that reads from the socket
// protocol connection and writes payloads into the internal pipe.
func (b *Bridge) Start() {
	go b.receiveLoop()
}

// Read returns payload data received from the socket protocol connection.
func (b *Bridge) Read(p []byte) (int, error) {
	return b.pr.Read(p)
}

// Write sends data as a normal command over the socket protocol connection.
func (b *Bridge) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.conn.SendCommand(CommandNormal, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close shuts down the bridge, closing both the pipe ends and signaling
// the receive loop to stop. It is safe to call Close multiple times.
func (b *Bridge) Close() error {
	b.closeOnce.Do(func() {
		close(b.done)
	})
	b.pr.Close()
	b.pw.Close()
	return nil
}

// Conn returns the underlying Conn for direct protocol access (e.g.,
// sending Shutdown).
func (b *Bridge) Conn() *Conn {
	return b.conn
}

func (b *Bridge) receiveLoop() {
	defer b.pw.Close()

	for {
		select {
		case <-b.done:
			return
		default:
		}

		cmd, payload, err := b.conn.RecvCommand()
		if err != nil {
			b.pw.CloseWithError(fmt.Errorf("qemusock: receive loop: %w", err))
			return
		}

		switch cmd {
		case CommandTest:
			b.mu.Lock()
			sendErr := b.conn.SendCommand(CommandTest, nil)
			b.mu.Unlock()
			if sendErr != nil {
				b.pw.CloseWithError(sendErr)
				return
			}
		case CommandShutdown:
			return
		case CommandNormal:
			if len(payload) == 0 {
				continue
			}
			if _, err := b.pw.Write(payload); err != nil {
				return
			}
		default:
			b.pw.CloseWithError(&ErrUnexpectedCommand{Command: cmd})
			return
		}
	}
}
