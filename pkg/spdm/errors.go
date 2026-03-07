package spdm

// ErrSessionNotInitialized indicates that a session method was called
// on a Session that has not been properly initialized via KeyExchange or PSKExchange.
type ErrSessionNotInitialized struct{}

func (e ErrSessionNotInitialized) Error() string {
	return "session not initialized"
}

func (e ErrSessionNotInitialized) Unwrap() error {
	return nil
}

// ErrVendorDefined indicates a failure in a vendor-defined request/response exchange.
type ErrVendorDefined struct {
	Err error
}

func (e ErrVendorDefined) Error() string {
	return "vendor_defined: " + e.Err.Error()
}

func (e ErrVendorDefined) Unwrap() error {
	return e.Err
}
