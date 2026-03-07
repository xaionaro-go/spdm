package storage

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xaionaro-go/spdm/pkg/transport"
)

func TestStorageBindingHeaderSize(t *testing.T) {
	var h StorageBindingHeader
	assert.Equal(t, uintptr(StorageBindingHeaderSize), unsafe.Sizeof(h))
}

func TestStorageBindingHeaderRoundTrip(t *testing.T) {
	original := StorageBindingHeader{
		DataLength:            0x0100,
		StorageBindingVersion: StorageSecurityBindingVersion,
	}

	data, err := original.Marshal()
	require.NoError(t, err)
	assert.Len(t, data, int(StorageBindingHeaderSize))

	var decoded StorageBindingHeader
	err = decoded.Unmarshal(data)
	require.NoError(t, err)
	assert.Equal(t, original, decoded)
}

func TestStorageBindingHeaderUnmarshalShortBuffer(t *testing.T) {
	var h StorageBindingHeader
	err := h.Unmarshal([]byte{0x01})
	assert.ErrorIs(t, err, transport.ErrShortBuffer)
}

func TestStorageBindingHeaderMarshalByteOrder(t *testing.T) {
	h := StorageBindingHeader{
		DataLength:            0xAABB,
		StorageBindingVersion: 0xCCDD,
	}

	data, err := h.Marshal()
	require.NoError(t, err)

	// Both fields are little-endian uint16
	assert.Equal(t, byte(0xBB), data[0])
	assert.Equal(t, byte(0xAA), data[1])
	assert.Equal(t, byte(0xDD), data[2])
	assert.Equal(t, byte(0xCC), data[3])
}

func TestStorageSecuredMessageDescriptorSize(t *testing.T) {
	var d StorageSecuredMessageDescriptor
	assert.Equal(t, uintptr(StorageSecuredMessageDescriptorSize), unsafe.Sizeof(d))
}

func TestStorageSecuredMessageDescriptorRoundTrip(t *testing.T) {
	original := StorageSecuredMessageDescriptor{
		Reserved1:      0x00,
		DescriptorType: StorageDescriptorSPDM,
		Status:         0x01,
		Reserved2:      0x00,
		Length:         0x00001000,
		Offset:         0x00002000,
		Reserved3:      0x00000000,
	}

	data, err := original.Marshal()
	require.NoError(t, err)
	assert.Len(t, data, int(StorageSecuredMessageDescriptorSize))

	var decoded StorageSecuredMessageDescriptor
	err = decoded.Unmarshal(data)
	require.NoError(t, err)
	assert.Equal(t, original, decoded)
}

func TestStorageSecuredMessageDescriptorUnmarshalShortBuffer(t *testing.T) {
	var d StorageSecuredMessageDescriptor
	err := d.Unmarshal([]byte{0x01, 0x02, 0x03})
	assert.ErrorIs(t, err, transport.ErrShortBuffer)
}

func TestStorageSecuredMessageDescriptorMarshalByteOrder(t *testing.T) {
	d := StorageSecuredMessageDescriptor{
		Reserved1:      0x11,
		DescriptorType: 0x22,
		Status:         0x33,
		Reserved2:      0x44,
		Length:         0xAABBCCDD,
		Offset:         0x11223344,
		Reserved3:      0x55667788,
	}

	data, err := d.Marshal()
	require.NoError(t, err)

	assert.Equal(t, byte(0x11), data[0])
	assert.Equal(t, byte(0x22), data[1])
	assert.Equal(t, byte(0x33), data[2])
	assert.Equal(t, byte(0x44), data[3])

	// Length (LE): 0xAABBCCDD -> DD CC BB AA
	assert.Equal(t, byte(0xDD), data[4])
	assert.Equal(t, byte(0xCC), data[5])
	assert.Equal(t, byte(0xBB), data[6])
	assert.Equal(t, byte(0xAA), data[7])

	// Offset (LE): 0x11223344 -> 44 33 22 11
	assert.Equal(t, byte(0x44), data[8])
	assert.Equal(t, byte(0x33), data[9])
	assert.Equal(t, byte(0x22), data[10])
	assert.Equal(t, byte(0x11), data[11])

	// Reserved3 (LE): 0x55667788 -> 88 77 66 55
	assert.Equal(t, byte(0x88), data[12])
	assert.Equal(t, byte(0x77), data[13])
	assert.Equal(t, byte(0x66), data[14])
	assert.Equal(t, byte(0x55), data[15])
}
