package pcidoe

import "io"

// ConfigSpaceAccessor abstracts reading/writing PCI config space registers.
// Both *os.File and test fakes satisfy this interface.
type ConfigSpaceAccessor interface {
	io.ReaderAt
	io.WriterAt
}
