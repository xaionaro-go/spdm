package pcidoe

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// simulatedConfigSpace is a byte slice backed ConfigSpaceAccessor
// for testing extended capability linked list traversal.
type simulatedConfigSpace struct {
	data []byte
}

func newSimulatedConfigSpace(size int) *simulatedConfigSpace {
	return &simulatedConfigSpace{
		data: make([]byte, size),
	}
}

func (s *simulatedConfigSpace) ReadAt(
	p []byte,
	off int64,
) (int, error) {
	if int(off)+len(p) > len(s.data) {
		return 0, fmt.Errorf("read at offset 0x%X: out of bounds", off)
	}
	n := copy(p, s.data[off:])
	return n, nil
}

func (s *simulatedConfigSpace) WriteAt(
	p []byte,
	off int64,
) (int, error) {
	n := copy(s.data[off:], p)
	return n, nil
}

// putExtCapHeader writes a PCIe extended capability header at the given
// offset in the simulated config space.
//
// PCIe Extended Capability Header format (32-bit DWORD):
//   - Bits [15:0]:  Capability ID
//   - Bits [19:16]: Capability Version
//   - Bits [31:20]: Next Capability Offset
func putExtCapHeader(
	cs *simulatedConfigSpace,
	offset int,
	capID uint16,
	version uint8,
	nextOffset int,
) {
	var header uint32
	header |= uint32(capID)
	header |= uint32(version&0x0F) << 16
	header |= uint32(nextOffset&0xFFF) << 20
	binary.LittleEndian.PutUint32(cs.data[offset:offset+4], header)
}

func TestFindDOECapability_DOEInChain(t *testing.T) {
	cs := newSimulatedConfigSpace(0x1000)

	// Build a chain: 0x100 -> 0x200 -> 0x300 (DOE)
	putExtCapHeader(cs, 0x100, 0x0001, 1, 0x200)      // Capability ID 0x0001 (Advanced Error Reporting)
	putExtCapHeader(cs, 0x200, 0x0003, 1, 0x300)      // Capability ID 0x0003 (Device Serial Number)
	putExtCapHeader(cs, 0x300, PCIeExtCapIDDOE, 1, 0) // DOE, end of list

	offset, err := FindDOECapability(cs)
	require.NoError(t, err)
	assert.Equal(t, 0x300, offset)
}

func TestFindDOECapability_DOEAtFirst(t *testing.T) {
	cs := newSimulatedConfigSpace(0x1000)

	// DOE is the first (and only) capability at 0x100.
	putExtCapHeader(cs, 0x100, PCIeExtCapIDDOE, 1, 0)

	offset, err := FindDOECapability(cs)
	require.NoError(t, err)
	assert.Equal(t, 0x100, offset)
}

func TestFindDOECapability_NoDOE(t *testing.T) {
	cs := newSimulatedConfigSpace(0x1000)

	// Chain without DOE: 0x100 -> 0x200 -> end
	putExtCapHeader(cs, 0x100, 0x0001, 1, 0x200)
	putExtCapHeader(cs, 0x200, 0x0003, 1, 0)

	_, err := FindDOECapability(cs)
	require.Error(t, err)

	var notFound *ErrDOECapabilityNotFound
	assert.ErrorAs(t, err, &notFound)
}

func TestFindDOECapability_EmptyChain(t *testing.T) {
	cs := newSimulatedConfigSpace(0x1000)

	// First entry at 0x100 has capability ID 0 and next=0.
	// This means the extended capability space is empty/unused.
	putExtCapHeader(cs, 0x100, 0x0000, 0, 0)

	_, err := FindDOECapability(cs)
	require.Error(t, err)

	var notFound *ErrDOECapabilityNotFound
	assert.ErrorAs(t, err, &notFound)
}

func TestFindDOECapability_ReadError(t *testing.T) {
	// Config space too small to even read the first header at 0x100.
	cs := newSimulatedConfigSpace(0x100)

	_, err := FindDOECapability(cs)
	require.Error(t, err)

	var readErr *ErrReadExtCapHeader
	assert.ErrorAs(t, err, &readErr)
}
