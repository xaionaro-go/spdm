package transport

import (
	"context"
	"errors"
)

// ErrShortBuffer is returned when a buffer is too short for unmarshalling.
var ErrShortBuffer = errors.New("transport: buffer too short")

// Transport abstracts the underlying message transport per DSP0274 Section 6.
type Transport interface {
	SendMessage(ctx context.Context, sessionID *uint32, msg []byte) error
	ReceiveMessage(ctx context.Context) (sessionID *uint32, msg []byte, err error)
	HeaderSize() int
}
