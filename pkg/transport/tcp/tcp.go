package tcp

import (
	"context"
	"encoding/binary"
	"io"
	"sync"
)

// Transport implements transport.Transport using simple length-prefixed
// framing over a TCP-like stream.
type Transport struct {
	conn io.ReadWriter
	mu   sync.Mutex
}

// New creates a new TCP transport over the given connection.
func New(conn io.ReadWriter) *Transport {
	return &Transport{conn: conn}
}

func (t *Transport) SendMessage(_ context.Context, _ *uint32, msg []byte) error {
	// Frame: [4-byte big-endian length][payload]
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(msg)))

	t.mu.Lock()
	defer t.mu.Unlock()
	if _, err := t.conn.Write(lenBuf[:]); err != nil {
		return &ErrWriteLength{Err: err}
	}
	if _, err := t.conn.Write(msg); err != nil {
		return &ErrWritePayload{Err: err}
	}
	return nil
}

func (t *Transport) ReceiveMessage(_ context.Context) (*uint32, []byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(t.conn, lenBuf[:]); err != nil {
		return nil, nil, &ErrReadLength{Err: err}
	}
	length := binary.BigEndian.Uint32(lenBuf[:])

	payload := make([]byte, length)
	if _, err := io.ReadFull(t.conn, payload); err != nil {
		return nil, nil, &ErrReadPayload{Err: err}
	}
	return nil, payload, nil
}

func (t *Transport) HeaderSize() int { return 4 }
