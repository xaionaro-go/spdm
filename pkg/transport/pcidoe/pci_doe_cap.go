package pcidoe

const (
	// PCIeExtCapIDDOE is the PCI Express Extended Capability ID for DOE.
	PCIeExtCapIDDOE = 0x002E

	// Register offsets relative to the DOE capability base.
	doeControlOffset          = 0x08
	doeStatusOffset           = 0x0C
	doeWriteDataMailboxOffset = 0x10
	doeReadDataMailboxOffset  = 0x14

	// Control register bits.
	doeControlAbort = 1 << 0
	doeControlGO    = 1 << 31

	// Status register bits.
	doeStatusBusy            = 1 << 0
	doeStatusError           = 1 << 2
	doeStatusDataObjectReady = 1 << 31
)
