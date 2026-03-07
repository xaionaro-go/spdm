package pcidoe

const (
	DOEVendorIDPCISIG        = 0x0001
	DOEDataObjectTypeSPDM    = 0x01
	DOEDataObjectTypeSecured = 0x02
)

// PCIDOEHeader is the 8-byte PCI Data Object Exchange header per PCIe ECN (DOE).
type PCIDOEHeader struct {
	VendorID       uint16
	DataObjectType uint8
	Reserved       uint8
	Length         uint32 // in DWORDs, including header (2 DW)
}
