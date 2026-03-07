package storage

import (
	"encoding/binary"

	"github.com/xaionaro-go/spdm/pkg/transport"
)

const (
	StorageSequenceNumberCount               = 2
	StorageSecurityBindingVersion            = 0x1000
	StorageSecurityProtocolDMTF              = 0xE8
	StorageOpCodeDiscovery                   = 0x01
	StorageOpCodePendingInfo                 = 0x02
	StorageOpCodeMessage                     = 0x05
	StorageOpCodeSecuredMessage              = 0x06
	StorageDescriptorNVME                    = 0x01
	StorageDescriptorSCSI                    = 0x02
	StorageDescriptorATA                     = 0x03
	StorageDescriptorSPDM                    = 0x04
	StorageDescriptorDataBuffer              = 0x40
	StorageMaxConnectionIDMask               = 0x3
	StorageBindingHeaderSize            uint = 4
	StorageSecuredMessageDescriptorSize uint = 16
)

var le = binary.LittleEndian

// StorageBindingHeader is the 4-byte SPDM-over-Storage response header per DSP0286.
type StorageBindingHeader struct {
	DataLength            uint16
	StorageBindingVersion uint16
}

// Marshal serializes the header into a 4-byte little-endian buffer.
func (h *StorageBindingHeader) Marshal() ([]byte, error) {
	buf := make([]byte, StorageBindingHeaderSize)
	le.PutUint16(buf[0:2], h.DataLength)
	le.PutUint16(buf[2:4], h.StorageBindingVersion)
	return buf, nil
}

// Unmarshal deserializes a 4-byte little-endian buffer into the header.
func (h *StorageBindingHeader) Unmarshal(data []byte) error {
	if uint(len(data)) < StorageBindingHeaderSize {
		return transport.ErrShortBuffer
	}

	h.DataLength = le.Uint16(data[0:2])
	h.StorageBindingVersion = le.Uint16(data[2:4])
	return nil
}

// StorageSecuredMessageDescriptor is the 16-byte secured message descriptor per DSP0286.
type StorageSecuredMessageDescriptor struct {
	Reserved1      uint8
	DescriptorType uint8
	Status         uint8
	Reserved2      uint8
	Length         uint32
	Offset         uint32
	Reserved3      uint32
}

// Marshal serializes the descriptor into a 16-byte little-endian buffer.
func (d *StorageSecuredMessageDescriptor) Marshal() ([]byte, error) {
	buf := make([]byte, StorageSecuredMessageDescriptorSize)
	buf[0] = d.Reserved1
	buf[1] = d.DescriptorType
	buf[2] = d.Status
	buf[3] = d.Reserved2
	le.PutUint32(buf[4:8], d.Length)
	le.PutUint32(buf[8:12], d.Offset)
	le.PutUint32(buf[12:16], d.Reserved3)
	return buf, nil
}

// Unmarshal deserializes a 16-byte little-endian buffer into the descriptor.
func (d *StorageSecuredMessageDescriptor) Unmarshal(data []byte) error {
	if uint(len(data)) < StorageSecuredMessageDescriptorSize {
		return transport.ErrShortBuffer
	}

	d.Reserved1 = data[0]
	d.DescriptorType = data[1]
	d.Status = data[2]
	d.Reserved2 = data[3]
	d.Length = le.Uint32(data[4:8])
	d.Offset = le.Uint32(data[8:12])
	d.Reserved3 = le.Uint32(data[12:16])
	return nil
}
