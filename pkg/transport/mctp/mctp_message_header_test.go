package mctp

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

func TestMCTPMessageHeaderSize(t *testing.T) {
	var h MCTPMessageHeader
	// Binary wire format: single byte header.
	assert.Equal(t, uintptr(1), unsafe.Sizeof(h))
}
