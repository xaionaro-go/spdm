package mctp

import (
	"context"
	"encoding/binary"
	"io"
	"sync"
)

// Transport implements transport.Transport for MCTP.
// It wraps messages with the 1-byte MCTP message type header and
// uses a simple length-prefixed framing over the underlying connection.
type Transport struct {
	conn io.ReadWriter
	mu   sync.Mutex
}

// New creates a new MCTP transport over the given connection.
func New(conn io.ReadWriter) *Transport {
	return &Transport{conn: conn}
}

func (t *Transport) SendMessage(_ context.Context, _ *uint32, msg []byte) error {
	// Frame: [4-byte length][1-byte MCTP header][payload]
	frame := make([]byte, 4+1+len(msg))
	binary.BigEndian.PutUint32(frame[0:4], uint32(1+len(msg)))
	frame[4] = MCTPMessageTypeSPDM
	copy(frame[5:], msg)

	t.mu.Lock()
	defer t.mu.Unlock()
	_, err := t.conn.Write(frame)
	return err
}

func (t *Transport) ReceiveMessage(_ context.Context) (*uint32, []byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(t.conn, lenBuf[:]); err != nil {
		return nil, nil, &ErrReadLength{Err: err}
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length < 1 {
		return nil, nil, &ErrFrameTooShort{}
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(t.conn, payload); err != nil {
		return nil, nil, &ErrReadPayload{Err: err}
	}

	msgType := payload[0]
	if msgType != MCTPMessageTypeSPDM && msgType != MCTPMessageTypeSecuredSPDM {
		return nil, nil, &ErrUnexpectedMessageType{MessageType: msgType}
	}

	return nil, payload[1:], nil
}

func (t *Transport) HeaderSize() int { return 1 }
