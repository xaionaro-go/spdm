package pcidoe

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

func TestPCIDOEHeaderSize(t *testing.T) {
	var h PCIDOEHeader
	// Binary wire format: uint16 + uint8 + uint8 + uint32 = 8 bytes.
	assert.Equal(t, uintptr(8), unsafe.Sizeof(h))
}
