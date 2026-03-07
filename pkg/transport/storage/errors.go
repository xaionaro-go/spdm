package storage

import "fmt"

// ErrWriteLength indicates a failure to write the length prefix.
type ErrWriteLength struct {
	Err error
}

func (e *ErrWriteLength) Error() string {
	return "storage: write length: " + e.Err.Error()
}

func (e *ErrWriteLength) Unwrap() error {
	return e.Err
}

// ErrWritePayload indicates a failure to write the message payload.
type ErrWritePayload struct {
	Err error
}

func (e *ErrWritePayload) Error() string {
	return "storage: write payload: " + e.Err.Error()
}

func (e *ErrWritePayload) Unwrap() error {
	return e.Err
}

// ErrReadLength indicates a failure to read the length prefix.
type ErrReadLength struct {
	Err error
}

func (e *ErrReadLength) Error() string {
	return "storage: read length: " + e.Err.Error()
}

func (e *ErrReadLength) Unwrap() error {
	return e.Err
}

// ErrReadPayload indicates a failure to read the message payload.
type ErrReadPayload struct {
	Err error
}

func (e *ErrReadPayload) Error() string {
	return "storage: read payload: " + e.Err.Error()
}

func (e *ErrReadPayload) Unwrap() error {
	return e.Err
}

// ErrMessageTooLarge indicates that the message exceeds the 65535-byte limit.
type ErrMessageTooLarge struct {
	Size int
}

func (e *ErrMessageTooLarge) Error() string {
	return fmt.Sprintf("storage: message too large (%d bytes, max 65535)", e.Size)
}

func (e *ErrMessageTooLarge) Unwrap() error {
	return nil
}
