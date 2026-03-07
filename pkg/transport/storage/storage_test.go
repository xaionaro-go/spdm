package storage

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
	assert.Equal(t, 2, tr.HeaderSize())
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

	payload := make([]byte, 60000) // under 65535 limit
	for i := range payload {
		payload[i] = byte(i)
	}

	require.NoError(t, tr.SendMessage(ctx, nil, payload))

	_, got, err := tr.ReceiveMessage(ctx)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

func TestMessageTooLarge(t *testing.T) {
	buf := new(bytes.Buffer)
	tr := New(buf)

	payload := make([]byte, 0x10000) // exceeds 65535
	err := tr.SendMessage(context.Background(), nil, payload)
	require.Error(t, err)
}

func TestFrameFormat(t *testing.T) {
	buf := new(bytes.Buffer)
	tr := New(buf)

	payload := []byte{0xAA, 0xBB}
	require.NoError(t, tr.SendMessage(context.Background(), nil, payload))

	frame := buf.Bytes()
	require.Len(t, frame, 4) // 2 length + 2 payload
	length := binary.BigEndian.Uint16(frame[0:2])
	assert.Equal(t, uint16(2), length)
	assert.Equal(t, payload, frame[2:])
}

func TestShortRead(t *testing.T) {
	buf := bytes.NewBuffer([]byte{0x00})
	tr := New(buf)
	_, _, err := tr.ReceiveMessage(context.Background())
	require.Error(t, err)
}

func TestTruncatedPayload(t *testing.T) {
	buf := new(bytes.Buffer)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], 100)
	buf.Write(lenBuf[:])
	buf.Write([]byte{0x01, 0x02})

	tr := New(buf)
	_, _, err := tr.ReceiveMessage(context.Background())
	require.Error(t, err)
}

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
	ew := &errorWriter{n: 2, err: fmt.Errorf("write error")}
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
