package responder

// ErrReceive indicates a failure to receive a message from the transport.
type ErrReceive struct {
	Err error
}

func (e ErrReceive) Error() string {
	return "receive: " + e.Err.Error()
}

func (e ErrReceive) Unwrap() error {
	return e.Err
}

// ErrProcess indicates a failure to process an SPDM message.
type ErrProcess struct {
	Err error
}

func (e ErrProcess) Error() string {
	return "process: " + e.Err.Error()
}

func (e ErrProcess) Unwrap() error {
	return e.Err
}

// ErrSendResponse indicates a failure to send a response via the transport.
type ErrSendResponse struct {
	Err error
}

func (e ErrSendResponse) Error() string {
	return "send: " + e.Err.Error()
}

func (e ErrSendResponse) Unwrap() error {
	return e.Err
}
