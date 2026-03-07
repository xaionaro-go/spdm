package testutil

import (
	"context"

	"github.com/xaionaro-go/spdm/pkg/transport"
)

// Compile-time check that LoopbackTransport implements transport.Transport.
var _ transport.Transport = (*LoopbackTransport)(nil)

// LoopbackTransport provides an in-memory bidirectional transport.
// Create a pair with NewLoopbackPair() -- messages sent on one side
// are received on the other.
type LoopbackTransport struct {
	sendCh chan loopbackMsg
	recvCh chan loopbackMsg
}

type loopbackMsg struct {
	sessionID *uint32
	data      []byte
}

// NewLoopbackPair returns two connected transports. Messages sent on
// requesterSide are received on responderSide and vice versa.
func NewLoopbackPair() (requesterSide, responderSide *LoopbackTransport) {
	ch1 := make(chan loopbackMsg, 16)
	ch2 := make(chan loopbackMsg, 16)
	return &LoopbackTransport{sendCh: ch1, recvCh: ch2},
		&LoopbackTransport{sendCh: ch2, recvCh: ch1}
}

func (t *LoopbackTransport) SendMessage(ctx context.Context, sessionID *uint32, msg []byte) error {
	data := make([]byte, len(msg))
	copy(data, msg)
	var sid *uint32
	if sessionID != nil {
		s := *sessionID
		sid = &s
	}
	select {
	case t.sendCh <- loopbackMsg{sessionID: sid, data: data}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *LoopbackTransport) ReceiveMessage(ctx context.Context) (*uint32, []byte, error) {
	select {
	case m := <-t.recvCh:
		return m.sessionID, m.data, nil
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}

func (t *LoopbackTransport) HeaderSize() int { return 0 }
