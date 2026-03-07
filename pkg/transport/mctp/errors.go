package mctp

import "fmt"

// ErrReadLength indicates a failure to read the length prefix from the MCTP frame.
type ErrReadLength struct {
	Err error
}

func (e ErrReadLength) Error() string {
	return "mctp: read length: " + e.Err.Error()
}

func (e ErrReadLength) Unwrap() error {
	return e.Err
}

// ErrReadPayload indicates a failure to read the payload from the MCTP frame.
type ErrReadPayload struct {
	Err error
}

func (e ErrReadPayload) Error() string {
	return "mctp: read payload: " + e.Err.Error()
}

func (e ErrReadPayload) Unwrap() error {
	return e.Err
}

// ErrFrameTooShort indicates that the MCTP frame length is too short to contain
// the required message type header.
type ErrFrameTooShort struct{}

func (e ErrFrameTooShort) Error() string {
	return "mctp: frame too short"
}

func (e ErrFrameTooShort) Unwrap() error {
	return nil
}

// ErrUnexpectedMessageType indicates that the MCTP message type byte
// was not a recognized SPDM or Secured SPDM type.
type ErrUnexpectedMessageType struct {
	MessageType byte
}

func (e ErrUnexpectedMessageType) Error() string {
	return fmt.Sprintf("mctp: unexpected message type 0x%02x", e.MessageType)
}

func (e ErrUnexpectedMessageType) Unwrap() error {
	return nil
}
