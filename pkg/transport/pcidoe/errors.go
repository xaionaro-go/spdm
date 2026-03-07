package pcidoe

import "fmt"

// ErrReadHeader is returned when reading the DOE header fails.
type ErrReadHeader struct {
	Err error
}

func (e *ErrReadHeader) Error() string {
	return fmt.Sprintf("pcidoe: read header: %v", e.Err)
}

func (e *ErrReadHeader) Unwrap() error {
	return e.Err
}

// ErrReadPayload is returned when reading the DOE payload fails.
type ErrReadPayload struct {
	Err error
}

func (e *ErrReadPayload) Error() string {
	return fmt.Sprintf("pcidoe: read payload: %v", e.Err)
}

func (e *ErrReadPayload) Unwrap() error {
	return e.Err
}

// ErrInvalidLength is returned when the DOE header length field
// is too small to contain the header itself.
type ErrInvalidLength struct {
	LengthDW uint32
}

func (e *ErrInvalidLength) Error() string {
	return fmt.Sprintf("pcidoe: invalid length %d DWORDs", e.LengthDW)
}

func (e *ErrInvalidLength) Unwrap() error {
	return nil
}

// ErrNegativePayloadLength is returned when the computed payload
// length underflows (should not happen if ErrInvalidLength is checked first).
type ErrNegativePayloadLength struct{}

func (e *ErrNegativePayloadLength) Error() string {
	return "pcidoe: negative payload length"
}

func (e *ErrNegativePayloadLength) Unwrap() error {
	return nil
}

// ErrMailboxBusy is returned when the DOE mailbox status register
// indicates the device is busy.
type ErrMailboxBusy struct{}

func (e *ErrMailboxBusy) Error() string {
	return "pcidoe: mailbox is busy"
}

func (e *ErrMailboxBusy) Unwrap() error {
	return nil
}

// ErrMailboxError is returned when the DOE mailbox status register
// reports an error condition.
type ErrMailboxError struct{}

func (e *ErrMailboxError) Error() string {
	return "pcidoe: mailbox status error"
}

func (e *ErrMailboxError) Unwrap() error {
	return nil
}

// ErrMailboxTimeout is returned when polling the DOE mailbox status
// register times out waiting for Data Object Ready.
type ErrMailboxTimeout struct{}

func (e *ErrMailboxTimeout) Error() string {
	return "pcidoe: mailbox polling timed out"
}

func (e *ErrMailboxTimeout) Unwrap() error {
	return nil
}

// ErrMailboxNotAligned is returned when data written to the mailbox
// is not DWORD-aligned (not a multiple of 4 bytes).
type ErrMailboxNotAligned struct {
	Size int
}

func (e *ErrMailboxNotAligned) Error() string {
	return fmt.Sprintf("pcidoe: data size %d is not DWORD-aligned", e.Size)
}

func (e *ErrMailboxNotAligned) Unwrap() error {
	return nil
}

// ErrReadExtCapHeader is returned when reading a PCIe extended
// capability header fails during capability discovery.
type ErrReadExtCapHeader struct {
	Offset int
	Err    error
}

func (e *ErrReadExtCapHeader) Error() string {
	return fmt.Sprintf("pcidoe: read extended capability header at 0x%X: %v", e.Offset, e.Err)
}

func (e *ErrReadExtCapHeader) Unwrap() error {
	return e.Err
}

// ErrDOECapabilityNotFound is returned when no DOE extended capability
// is found in the PCI Express extended capability linked list.
type ErrDOECapabilityNotFound struct{}

func (e *ErrDOECapabilityNotFound) Error() string {
	return "pcidoe: DOE extended capability not found"
}

func (e *ErrDOECapabilityNotFound) Unwrap() error {
	return nil
}

// ErrNoDOEDevice is returned when no PCI device with DOE capability
// is found during sysfs device discovery.
type ErrNoDOEDevice struct{}

func (e *ErrNoDOEDevice) Error() string {
	return "pcidoe: no PCI device with DOE capability found"
}

func (e *ErrNoDOEDevice) Unwrap() error {
	return nil
}
