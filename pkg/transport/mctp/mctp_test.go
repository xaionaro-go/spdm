package mctp

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHeaderSize(t *testing.T) {
	tr := New(new(bytes.Buffer))
	assert.Equal(t, 1, tr.HeaderSize())
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
	ctx := context.Background()

	payload := []byte{0xAA, 0xBB}
	require.NoError(t, tr.SendMessage(ctx, nil, payload))

	frame := buf.Bytes()
	// 4 length + 1 MCTP type + 2 payload = 7 bytes
	require.Len(t, frame, 7)
	length := binary.BigEndian.Uint32(frame[0:4])
	assert.Equal(t, uint32(3), length) // 1 byte type + 2 bytes payload
	assert.Equal(t, byte(MCTPMessageTypeSPDM), frame[4])
}

func TestInvalidMessageType(t *testing.T) {
	buf := new(bytes.Buffer)

	// Write a frame with invalid message type 0x07
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], 3)
	buf.Write(lenBuf[:])
	buf.Write([]byte{0x07, 0xAA, 0xBB})

	tr := New(buf)
	_, _, err := tr.ReceiveMessage(context.Background())
	require.Error(t, err)
}

func TestSecuredSPDMMessageType(t *testing.T) {
	buf := new(bytes.Buffer)

	// Write a frame with secured SPDM message type (0x06) -- should be accepted
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], 3)
	buf.Write(lenBuf[:])
	buf.Write([]byte{MCTPMessageTypeSecuredSPDM, 0xCC, 0xDD})

	tr := New(buf)
	_, got, err := tr.ReceiveMessage(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []byte{0xCC, 0xDD}, got)
}

func TestShortRead(t *testing.T) {
	// Only write 2 bytes of the 4-byte length prefix
	buf := bytes.NewBuffer([]byte{0x00, 0x00})
	tr := New(buf)
	_, _, err := tr.ReceiveMessage(context.Background())
	require.Error(t, err)
}

func TestTruncatedPayload(t *testing.T) {
	buf := new(bytes.Buffer)
	// Write length indicating 10 bytes but only provide 3
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], 10)
	buf.Write(lenBuf[:])
	buf.Write([]byte{0x05, 0xAA, 0xBB})

	tr := New(buf)
	_, _, err := tr.ReceiveMessage(context.Background())
	require.Error(t, err)
}

func TestZeroLengthFrame(t *testing.T) {
	buf := new(bytes.Buffer)
	// Length 0 means no MCTP type byte -- should fail
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], 0)
	buf.Write(lenBuf[:])

	tr := New(buf)
	_, _, err := tr.ReceiveMessage(context.Background())
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
