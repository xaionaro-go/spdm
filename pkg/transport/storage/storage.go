package storage

import (
	"context"
	"encoding/binary"
	"io"
	"sync"
)

// Transport implements transport.Transport for SPDM-over-Storage.
// It uses simple 2-byte big-endian length-prefixed framing over the
// underlying connection.
type Transport struct {
	conn io.ReadWriter
	mu   sync.Mutex
}

// New creates a new Storage transport over the given connection.
func New(conn io.ReadWriter) *Transport {
	return &Transport{conn: conn}
}

func (t *Transport) SendMessage(_ context.Context, _ *uint32, msg []byte) error {
	if len(msg) > 0xFFFF {
		return &ErrMessageTooLarge{Size: len(msg)}
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(msg)))

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
	var lenBuf [2]byte
	if _, err := io.ReadFull(t.conn, lenBuf[:]); err != nil {
		return nil, nil, &ErrReadLength{Err: err}
	}
	length := binary.BigEndian.Uint16(lenBuf[:])

	payload := make([]byte, length)
	if _, err := io.ReadFull(t.conn, payload); err != nil {
		return nil, nil, &ErrReadPayload{Err: err}
	}
	return nil, payload, nil
}

func (t *Transport) HeaderSize() int { return 2 }
