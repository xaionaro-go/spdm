package mctp

const (
	MCTPMessageTypeSPDM        = 0x05
	MCTPMessageTypeSecuredSPDM = 0x06
)

// MCTPMessageHeader is the 1-byte MCTP message type header prepended
// to SPDM messages carried over MCTP per DSP0239 (MCTP Base Specification).
type MCTPMessageHeader struct {
	MessageType uint8
}
