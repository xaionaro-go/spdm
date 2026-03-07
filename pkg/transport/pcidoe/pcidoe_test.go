package pcidoe

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
	assert.Equal(t, 8, tr.HeaderSize())
}

func TestRoundTrip(t *testing.T) {
	buf := new(bytes.Buffer)
	tr := New(buf)
	ctx := context.Background()

	payload := []byte("hello spdm")
	require.NoError(t, tr.SendMessage(ctx, nil, payload))

	_, got, err := tr.ReceiveMessage(ctx)
	require.NoError(t, err)
	// Received payload may include padding bytes
	assert.True(t, bytes.HasPrefix(got, payload), "payload prefix mismatch: got %x, want prefix %x", got, payload)
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
	assert.True(t, bytes.HasPrefix(got, payload), "large payload mismatch (len got=%d, want prefix len=%d)", len(got), len(payload))
}

func TestDWORDPadding(t *testing.T) {
	tests := []struct {
		name         string
		payloadLen   int
		wantFrameLen int // total frame size including header
	}{
		{"aligned_0", 0, 8},  // 8+0=8, already aligned
		{"aligned_4", 4, 12}, // 8+4=12, aligned
		{"pad_1", 1, 12},     // 8+1=9 -> 12
		{"pad_2", 2, 12},     // 8+2=10 -> 12
		{"pad_3", 3, 12},     // 8+3=11 -> 12
		{"pad_5", 5, 16},     // 8+5=13 -> 16
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			tr := New(buf)
			payload := make([]byte, tc.payloadLen)
			require.NoError(t, tr.SendMessage(context.Background(), nil, payload))
			assert.Equal(t, tc.wantFrameLen, buf.Len())
		})
	}
}

func TestFrameFormat(t *testing.T) {
	buf := new(bytes.Buffer)
	tr := New(buf)

	payload := []byte{0xAA, 0xBB, 0xCC}
	require.NoError(t, tr.SendMessage(context.Background(), nil, payload))

	frame := buf.Bytes()
	// 8 header + 3 payload + 1 pad = 12 bytes
	require.Len(t, frame, 12)

	vendorID := binary.LittleEndian.Uint16(frame[0:2])
	assert.Equal(t, uint16(DOEVendorIDPCISIG), vendorID)
	assert.Equal(t, byte(DOEDataObjectTypeSPDM), frame[2])
	lengthDW := binary.LittleEndian.Uint32(frame[4:8])
	assert.Equal(t, uint32(3), lengthDW) // 12 / 4 = 3 DWORDs
}

func TestShortRead(t *testing.T) {
	// Only write 4 bytes of the 8-byte header
	buf := bytes.NewBuffer([]byte{0x01, 0x00, 0x01, 0x00})
	tr := New(buf)
	_, _, err := tr.ReceiveMessage(context.Background())
	require.Error(t, err)
}

func TestInvalidLengthTooSmall(t *testing.T) {
	buf := new(bytes.Buffer)
	// Write a valid-looking header with length=1 DWORD (less than 2 DW header)
	var hdr [8]byte
	binary.LittleEndian.PutUint16(hdr[0:2], DOEVendorIDPCISIG)
	hdr[2] = DOEDataObjectTypeSPDM
	binary.LittleEndian.PutUint32(hdr[4:8], 1) // too small
	buf.Write(hdr[:])

	tr := New(buf)
	_, _, err := tr.ReceiveMessage(context.Background())
	require.Error(t, err)
}

func TestTruncatedPayload(t *testing.T) {
	buf := new(bytes.Buffer)
	var hdr [8]byte
	binary.LittleEndian.PutUint16(hdr[0:2], DOEVendorIDPCISIG)
	hdr[2] = DOEDataObjectTypeSPDM
	binary.LittleEndian.PutUint32(hdr[4:8], 10) // 10 DWORDs = 40 bytes total, 32 bytes payload
	buf.Write(hdr[:])
	buf.Write([]byte{0x01, 0x02}) // only 2 payload bytes

	tr := New(buf)
	_, _, err := tr.ReceiveMessage(context.Background())
	require.Error(t, err)
}

func TestMultipleMessages(t *testing.T) {
	buf := new(bytes.Buffer)
	tr := New(buf)
	ctx := context.Background()

	// Use DWORD-aligned payloads to avoid padding ambiguity
	messages := [][]byte{
		{0x01, 0x02, 0x03, 0x04},
		{0x05, 0x06, 0x07, 0x08},
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
