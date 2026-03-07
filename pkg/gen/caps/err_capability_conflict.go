package caps

// ErrCapabilityConflict is returned when capability flags violate
// the mutual-dependency or exclusivity rules defined in the SPDM spec.
type ErrCapabilityConflict struct {
	Msg string
}

// Error implements the error interface.
func (e *ErrCapabilityConflict) Error() string {
	return e.Msg
}

// Unwrap implements the errors unwrapping interface.
func (e *ErrCapabilityConflict) Unwrap() error {
	return nil
}
