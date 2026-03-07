package tcp

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xaionaro-go/spdm/pkg/transport"
)

func TestTCPBindingHeaderSize(t *testing.T) {
	var h TCPBindingHeader
	assert.Equal(t, uintptr(TCPBindingHeaderSize), unsafe.Sizeof(h))
}

func TestTCPBindingHeaderRoundTrip(t *testing.T) {
	original := TCPBindingHeader{
		PayloadLength:  0x1234,
		BindingVersion: 0x01,
		MessageType:    TCPMessageTypeOutOfSession,
	}

	data, err := original.Marshal()
	require.NoError(t, err)
	assert.Len(t, data, int(TCPBindingHeaderSize))

	var decoded TCPBindingHeader
	err = decoded.Unmarshal(data)
	require.NoError(t, err)
	assert.Equal(t, original, decoded)
}

func TestTCPBindingHeaderUnmarshalShortBuffer(t *testing.T) {
	var h TCPBindingHeader
	err := h.Unmarshal([]byte{0x01, 0x02})
	assert.ErrorIs(t, err, transport.ErrShortBuffer)
}

func TestTCPBindingHeaderMarshalByteOrder(t *testing.T) {
	h := TCPBindingHeader{
		PayloadLength:  0xAABB,
		BindingVersion: 0xCC,
		MessageType:    0xDD,
	}

	data, err := h.Marshal()
	require.NoError(t, err)

	// PayloadLength is little-endian: low byte first
	assert.Equal(t, byte(0xBB), data[0])
	assert.Equal(t, byte(0xAA), data[1])
	assert.Equal(t, byte(0xCC), data[2])
	assert.Equal(t, byte(0xDD), data[3])
}
