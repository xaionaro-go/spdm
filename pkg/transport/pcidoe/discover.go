package pcidoe

import (
	"encoding/binary"
	"os"
	"path/filepath"
)

const (
	// pcieExtCapStart is the offset where the PCIe extended capability
	// linked list begins in PCI config space.
	pcieExtCapStart = 0x100

	// pcieExtCapHeaderSize is the size of each extended capability
	// header in bytes (one 32-bit DWORD).
	pcieExtCapHeaderSize = 4
)

// FindDOECapability walks the PCIe extended capability linked list
// in the given config space, looking for the DOE extended capability
// (ID = 0x002E). Returns the offset of the DOE capability header.
//
// PCIe Extended Capability Header format (32-bit DWORD at each offset):
//   - Bits [15:0]:  Capability ID
//   - Bits [19:16]: Capability Version
//   - Bits [31:20]: Next Capability Offset (0 = end of list)
func FindDOECapability(
	config ConfigSpaceAccessor,
) (int, error) {
	offset := pcieExtCapStart

	for offset != 0 {
		var buf [pcieExtCapHeaderSize]byte
		if _, err := config.ReadAt(buf[:], int64(offset)); err != nil {
			return 0, &ErrReadExtCapHeader{Offset: offset, Err: err}
		}

		header := binary.LittleEndian.Uint32(buf[:])
		capID := uint16(header & 0xFFFF)
		nextOffset := int((header >> 20) & 0xFFF)

		// A capability ID of 0x0000 with next=0 indicates an empty/unused
		// extended capability space.
		if capID == 0 && nextOffset == 0 {
			break
		}

		if capID == PCIeExtCapIDDOE {
			return offset, nil
		}

		offset = nextOffset
	}

	return 0, &ErrDOECapabilityNotFound{}
}

// FindDOEDevice walks PCI devices in sysfs and returns the config space
// path and DOE capability offset of the first device that has a DOE
// extended capability.
func FindDOEDevice() (
	configPath string,
	capOffset int,
	err error,
) {
	matches, err := filepath.Glob("/sys/bus/pci/devices/*/config")
	if err != nil {
		return "", 0, err
	}

	for _, path := range matches {
		f, err := os.Open(path)
		if err != nil {
			continue
		}

		offset, err := FindDOECapability(f)
		_ = f.Close()
		if err != nil {
			continue
		}

		return path, offset, nil
	}

	return "", 0, &ErrNoDOEDevice{}
}
