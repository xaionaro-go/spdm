package qemusock

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSendCommand_FrameFormat(t *testing.T) {
	buf := new(bytes.Buffer)
	c := NewConn(buf, TransportPCIDOE)

	payload := []byte{0xAA, 0xBB, 0xCC}
	require.NoError(t, c.SendCommand(CommandNormal, payload))

	frame := buf.Bytes()
	require.Len(t, frame, headerSize+len(payload))

	assert.Equal(t, uint32(CommandNormal), binary.BigEndian.Uint32(frame[0:4]))
	assert.Equal(t, uint32(TransportPCIDOE), binary.BigEndian.Uint32(frame[4:8]))
	assert.Equal(t, uint32(len(payload)), binary.BigEndian.Uint32(frame[8:12]))
	assert.Equal(t, payload, frame[12:])
}

func TestRecvCommand(t *testing.T) {
	buf := new(bytes.Buffer)
	payload := []byte{0x01, 0x02, 0x03}

	var hdr [headerSize]byte
	binary.BigEndian.PutUint32(hdr[0:4], CommandNormal)
	binary.BigEndian.PutUint32(hdr[4:8], TransportMCTP)
	binary.BigEndian.PutUint32(hdr[8:12], uint32(len(payload)))
	buf.Write(hdr[:])
	buf.Write(payload)

	c := NewConn(buf, TransportMCTP)
	cmd, got, err := c.RecvCommand()
	require.NoError(t, err)
	assert.Equal(t, uint32(CommandNormal), cmd)
	assert.Equal(t, payload, got)
}

func TestRoundTrip(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	server := NewConn(serverConn, TransportPCIDOE)
	client := NewConn(clientConn, TransportPCIDOE)

	payload := []byte("hello qemusock")
	errCh := make(chan error, 1)
	go func() {
		errCh <- client.SendCommand(CommandNormal, payload)
	}()

	cmd, got, err := server.RecvCommand()
	require.NoError(t, err)
	assert.Equal(t, uint32(CommandNormal), cmd)
	assert.Equal(t, payload, got)

	require.NoError(t, <-errCh)
}

func TestRoundTrip_EmptyPayload(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	server := NewConn(serverConn, TransportNone)
	client := NewConn(clientConn, TransportNone)

	errCh := make(chan error, 1)
	go func() {
		errCh <- client.SendCommand(CommandTest, nil)
	}()

	cmd, got, err := server.RecvCommand()
	require.NoError(t, err)
	assert.Equal(t, uint32(CommandTest), cmd)
	assert.Empty(t, got)

	require.NoError(t, <-errCh)
}

func TestShutdown(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	server := NewConn(serverConn, TransportNone)
	client := NewConn(clientConn, TransportNone)

	errCh := make(chan error, 1)
	go func() {
		errCh <- client.Shutdown()
	}()

	cmd, got, err := server.RecvCommand()
	require.NoError(t, err)
	assert.Equal(t, uint32(CommandShutdown), cmd)
	assert.Empty(t, got)

	require.NoError(t, <-errCh)
}

func TestTransportType(t *testing.T) {
	c := NewConn(new(bytes.Buffer), TransportMCTP)
	assert.Equal(t, uint32(TransportMCTP), c.TransportType())
}

func TestRecvCommand_ShortHeader(t *testing.T) {
	buf := bytes.NewBuffer([]byte{0x00, 0x01})
	c := NewConn(buf, TransportNone)
	_, _, err := c.RecvCommand()
	require.Error(t, err)
	assert.IsType(t, &ErrReadHeader{}, err)
}

func TestRecvCommand_TruncatedPayload(t *testing.T) {
	buf := new(bytes.Buffer)
	var hdr [headerSize]byte
	binary.BigEndian.PutUint32(hdr[0:4], CommandNormal)
	binary.BigEndian.PutUint32(hdr[4:8], TransportNone)
	binary.BigEndian.PutUint32(hdr[8:12], 100)
	buf.Write(hdr[:])
	buf.Write([]byte{0x01, 0x02})

	c := NewConn(buf, TransportNone)
	_, _, err := c.RecvCommand()
	require.Error(t, err)
	assert.IsType(t, &ErrReadPayload{}, err)
}

func TestSendCommand_WriteHeaderError(t *testing.T) {
	ew := &errorWriter{n: 0, err: fmt.Errorf("header write error")}
	c := NewConn(ew, TransportNone)
	err := c.SendCommand(CommandNormal, []byte("data"))
	require.Error(t, err)
	assert.IsType(t, &ErrWriteHeader{}, err)
}

func TestSendCommand_WritePayloadError(t *testing.T) {
	ew := &errorWriter{n: headerSize, err: fmt.Errorf("payload write error")}
	c := NewConn(ew, TransportNone)
	err := c.SendCommand(CommandNormal, []byte("data"))
	require.Error(t, err)
	assert.IsType(t, &ErrWritePayload{}, err)
}

func TestMultipleRoundTrips(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	server := NewConn(serverConn, TransportPCIDOE)
	client := NewConn(clientConn, TransportPCIDOE)

	messages := [][]byte{
		{0x01, 0x02},
		{0x03, 0x04, 0x05},
		{0x06},
	}

	errCh := make(chan error, 1)
	go func() {
		for _, msg := range messages {
			if err := client.SendCommand(CommandNormal, msg); err != nil {
				errCh <- err
				return
			}
		}
		errCh <- nil
	}()

	for i, want := range messages {
		cmd, got, err := server.RecvCommand()
		require.NoError(t, err, "RecvCommand[%d]", i)
		assert.Equal(t, uint32(CommandNormal), cmd, "command[%d]", i)
		assert.Equal(t, want, got, "payload[%d]", i)
	}

	require.NoError(t, <-errCh)
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

func (w *errorWriter) Read(_ []byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func TestErrorMessages(t *testing.T) {
	inner := fmt.Errorf("underlying")

	t.Run("ErrWriteHeader", func(t *testing.T) {
		e := &ErrWriteHeader{Err: inner}
		assert.Contains(t, e.Error(), "write header")
		assert.Equal(t, inner, e.Unwrap())
	})

	t.Run("ErrWritePayload", func(t *testing.T) {
		e := &ErrWritePayload{Err: inner}
		assert.Contains(t, e.Error(), "write payload")
		assert.Equal(t, inner, e.Unwrap())
	})

	t.Run("ErrReadHeader", func(t *testing.T) {
		e := &ErrReadHeader{Err: inner}
		assert.Contains(t, e.Error(), "read header")
		assert.Equal(t, inner, e.Unwrap())
	})

	t.Run("ErrReadPayload", func(t *testing.T) {
		e := &ErrReadPayload{Err: inner}
		assert.Contains(t, e.Error(), "read payload")
		assert.Equal(t, inner, e.Unwrap())
	})

	t.Run("ErrUnexpectedCommand", func(t *testing.T) {
		e := &ErrUnexpectedCommand{Command: 0xBEEF}
		assert.Contains(t, e.Error(), "0xBEEF")
		assert.Nil(t, e.Unwrap())
	})
}
