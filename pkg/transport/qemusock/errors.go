package qemusock

import "fmt"

// ErrWriteHeader is returned when writing the 12-byte socket header fails.
type ErrWriteHeader struct {
	Err error
}

func (e *ErrWriteHeader) Error() string {
	return fmt.Sprintf("qemusock: write header: %v", e.Err)
}

func (e *ErrWriteHeader) Unwrap() error {
	return e.Err
}

// ErrWritePayload is returned when writing the payload fails.
type ErrWritePayload struct {
	Err error
}

func (e *ErrWritePayload) Error() string {
	return fmt.Sprintf("qemusock: write payload: %v", e.Err)
}

func (e *ErrWritePayload) Unwrap() error {
	return e.Err
}

// ErrReadHeader is returned when reading the 12-byte socket header fails.
type ErrReadHeader struct {
	Err error
}

func (e *ErrReadHeader) Error() string {
	return fmt.Sprintf("qemusock: read header: %v", e.Err)
}

func (e *ErrReadHeader) Unwrap() error {
	return e.Err
}

// ErrReadPayload is returned when reading the payload fails.
type ErrReadPayload struct {
	Err error
}

func (e *ErrReadPayload) Error() string {
	return fmt.Sprintf("qemusock: read payload: %v", e.Err)
}

func (e *ErrReadPayload) Unwrap() error {
	return e.Err
}

// ErrUnexpectedCommand is returned when a received command does not match
// the expected value.
type ErrUnexpectedCommand struct {
	Command uint32
}

func (e *ErrUnexpectedCommand) Error() string {
	return fmt.Sprintf("qemusock: unexpected command: 0x%04X", e.Command)
}

func (e *ErrUnexpectedCommand) Unwrap() error {
	return nil
}
