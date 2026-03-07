package tcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHeaderSize(t *testing.T) {
	tr := New(new(bytes.Buffer))
	assert.Equal(t, 4, tr.HeaderSize())
}

func TestRoundTrip(t *testing.T) {
	buf := new(bytes.Buffer)
	tr := New(buf)
	ctx := context.Background()

	payload := []byte("hello spdm")
	require.NoError(t, tr.SendMessage(ctx, nil, payload))

	_, got, err := tr.ReceiveMessage(ctx)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

func TestEmptyMessage(t *testing.T) {
	buf := new(bytes.Buffer)
	tr := New(buf)
	ctx := context.Background()

	require.NoError(t, tr.SendMessage(ctx, nil, nil))

	_, got, err := tr.ReceiveMessage(ctx)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestLargeMessage(t *testing.T) {
	buf := new(bytes.Buffer)
	tr := New(buf)
	ctx := context.Background()

	payload := make([]byte, 64*1024)
	for i := range payload {
		payload[i] = byte(i)
	}

	require.NoError(t, tr.SendMessage(ctx, nil, payload))

	_, got, err := tr.ReceiveMessage(ctx)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

func TestFrameFormat(t *testing.T) {
	buf := new(bytes.Buffer)
	tr := New(buf)

	payload := []byte{0xAA, 0xBB}
	require.NoError(t, tr.SendMessage(context.Background(), nil, payload))

	frame := buf.Bytes()
	require.Len(t, frame, 6) // 4 length + 2 payload
	length := binary.BigEndian.Uint32(frame[0:4])
	assert.Equal(t, uint32(2), length)
	assert.Equal(t, payload, frame[4:])
}

func TestShortRead(t *testing.T) {
	buf := bytes.NewBuffer([]byte{0x00, 0x00})
	tr := New(buf)
	_, _, err := tr.ReceiveMessage(context.Background())
	require.Error(t, err)
}

func TestTruncatedPayload(t *testing.T) {
	buf := new(bytes.Buffer)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], 100)
	buf.Write(lenBuf[:])
	buf.Write([]byte{0x01, 0x02})

	tr := New(buf)
	_, _, err := tr.ReceiveMessage(context.Background())
	require.Error(t, err)
}

// errorWriter returns an error after writing at most n bytes.
type errorWriter struct {
	n   int
	err error
}

func (w *errorWriter) Write(p []byte) (int, error) {
	if w.n <= 0 {
		return 0, w.err
	}
	if len(p) <= w.n {
		w.n -= len(p)
		return len(p), nil
	}
	n := w.n
	w.n = 0
	return n, w.err
}

func (w *errorWriter) Read(p []byte) (int, error) {
	return 0, w.err
}

func TestSendMessage_WriteLengthError(t *testing.T) {
	ew := &errorWriter{n: 0, err: fmt.Errorf("write error")}
	tr := New(ew)
	err := tr.SendMessage(context.Background(), nil, []byte("data"))
	require.Error(t, err)
}

func TestSendMessage_WritePayloadError(t *testing.T) {
	ew := &errorWriter{n: 4, err: fmt.Errorf("write error")} // allow length write, fail on payload
	tr := New(ew)
	err := tr.SendMessage(context.Background(), nil, []byte("data"))
	require.Error(t, err)
}

func TestMultipleMessages(t *testing.T) {
	buf := new(bytes.Buffer)
	tr := New(buf)
	ctx := context.Background()

	messages := [][]byte{
		{0x01, 0x02},
		{0x03, 0x04, 0x05},
		{0x06},
	}

	for _, msg := range messages {
		require.NoError(t, tr.SendMessage(ctx, nil, msg))
	}

	for i, want := range messages {
		_, got, err := tr.ReceiveMessage(ctx)
		require.NoError(t, err, "ReceiveMessage[%d]", i)
		assert.Equal(t, want, got, "message[%d]", i)
	}
}
