package testutil

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoopbackSendReceive(t *testing.T) {
	req, resp := NewLoopbackPair()
	ctx := context.Background()

	msg := []byte("hello spdm")
	require.NoError(t, req.SendMessage(ctx, nil, msg))

	sid, data, err := resp.ReceiveMessage(ctx)
	require.NoError(t, err)
	assert.Nil(t, sid)
	assert.Equal(t, msg, data)
}

func TestLoopbackBidirectional(t *testing.T) {
	req, resp := NewLoopbackPair()
	ctx := context.Background()

	// Send from requester to responder.
	require.NoError(t, req.SendMessage(ctx, nil, []byte("req->resp")))
	_, data, err := resp.ReceiveMessage(ctx)
	require.NoError(t, err)
	assert.Equal(t, "req->resp", string(data))

	// Send from responder to requester.
	require.NoError(t, resp.SendMessage(ctx, nil, []byte("resp->req")))
	_, data, err = req.ReceiveMessage(ctx)
	require.NoError(t, err)
	assert.Equal(t, "resp->req", string(data))
}

func TestLoopbackSessionID(t *testing.T) {
	req, resp := NewLoopbackPair()
	ctx := context.Background()

	sid := uint32(0xDEADBEEF)
	require.NoError(t, req.SendMessage(ctx, &sid, []byte("with-session")))

	gotSID, data, err := resp.ReceiveMessage(ctx)
	require.NoError(t, err)
	require.NotNil(t, gotSID)
	assert.Equal(t, sid, *gotSID)
	assert.Equal(t, []byte("with-session"), data)

	// Verify the session ID is a copy (modifying original doesn't affect received).
	sid = 0
	assert.Equal(t, uint32(0xDEADBEEF), *gotSID)
}

func TestLoopbackContextCancellation(t *testing.T) {
	req, _ := NewLoopbackPair()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Send on cancelled context may succeed (buffered channel) or return Canceled.
	// Both are acceptable. The key guarantee is ReceiveMessage.
	_ = req.SendMessage(ctx, nil, []byte("data"))

	// Receive on cancelled context should fail.
	_, _, err := req.ReceiveMessage(ctx)
	assert.Equal(t, context.Canceled, err)
}

func TestLoopbackContextTimeout(t *testing.T) {
	_, resp := NewLoopbackPair()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	// No message sent, so receive should time out.
	_, _, err := resp.ReceiveMessage(ctx)
	assert.Equal(t, context.DeadlineExceeded, err)
}

func TestLoopbackDataIsolation(t *testing.T) {
	req, resp := NewLoopbackPair()
	ctx := context.Background()

	// Verify sent data is copied (modifying original doesn't affect received).
	msg := []byte("original")
	require.NoError(t, req.SendMessage(ctx, nil, msg))
	msg[0] = 'X' // mutate after send

	_, data, err := resp.ReceiveMessage(ctx)
	require.NoError(t, err)
	assert.True(t, bytes.HasPrefix(data, []byte("o")), "sent data should be a copy")
}

func TestLoopbackHeaderSize(t *testing.T) {
	req, _ := NewLoopbackPair()
	assert.Equal(t, 0, req.HeaderSize())
}
