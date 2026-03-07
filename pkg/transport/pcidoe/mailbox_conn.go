package pcidoe

import (
	"encoding/binary"
	"time"
)

const (
	defaultPollTimeout  = 5 * time.Second
	defaultPollInterval = 1 * time.Millisecond
	dwordSize           = 4

	// doeLengthMask extracts the 18-bit length field from DOE header DWORD 1.
	doeLengthMask = 0x3FFFF

	// maxDOELengthDW is the maximum DOE data object length (in DWORDs).
	// Per the PCIe DOE spec, the 18-bit length field can represent up to
	// 2^18 = 262144 DWORDs (1 MB). We use a lower bound for safety.
	maxDOELengthDW = 1 << 16 // 256K bytes
)

// MailboxConn implements io.ReadWriter over PCI DOE mailbox registers.
// Write sends a DOE frame via the Write Data Mailbox register and
// triggers the GO bit. Read polls until Data Object Ready, then reads
// DWORDs from the Read Data Mailbox register.
//
// MailboxConn is not safe for concurrent use.
type MailboxConn struct {
	config  ConfigSpaceAccessor
	capBase uint32

	PollTimeout  time.Duration
	PollInterval time.Duration

	// readBuf holds data fetched from hardware that hasn't been
	// returned to the caller yet.
	readBuf []byte
}

// NewMailboxConn creates a MailboxConn that accesses DOE registers at
// the given capability base offset within the PCI config space.
func NewMailboxConn(
	config ConfigSpaceAccessor,
	capBase uint32,
) *MailboxConn {
	return &MailboxConn{
		config:       config,
		capBase:      capBase,
		PollTimeout:  defaultPollTimeout,
		PollInterval: defaultPollInterval,
	}
}

// Write sends a DWORD-aligned DOE frame through the mailbox.
// It writes each DWORD to the Write Data Mailbox register, then
// sets the GO bit in the Control register.
func (m *MailboxConn) Write(p []byte) (int, error) {
	if len(p)%dwordSize != 0 {
		return 0, &ErrMailboxNotAligned{Size: len(p)}
	}

	status, err := m.readRegister(doeStatusOffset)
	if err != nil {
		return 0, err
	}

	if status&doeStatusBusy != 0 {
		return 0, &ErrMailboxBusy{}
	}

	if status&doeStatusError != 0 {
		return 0, &ErrMailboxError{}
	}

	numDwords := len(p) / dwordSize
	for i := 0; i < numDwords; i++ {
		dw := binary.LittleEndian.Uint32(p[i*dwordSize : (i+1)*dwordSize])
		if err := m.writeRegister(doeWriteDataMailboxOffset, dw); err != nil {
			return i * dwordSize, err
		}
	}

	if err := m.writeRegister(doeControlOffset, doeControlGO); err != nil {
		return len(p), err
	}

	return len(p), nil
}

// Read returns data from the DOE Read Data Mailbox. On the first call
// after a Write (when the internal buffer is empty), it polls the Status
// register until Data Object Ready is set, reads the DOE header to
// determine the frame length, then reads remaining DWORDs into an
// internal buffer. Subsequent calls drain the buffer.
func (m *MailboxConn) Read(p []byte) (int, error) {
	if len(m.readBuf) == 0 {
		if err := m.fetchFrame(); err != nil {
			return 0, err
		}
	}

	n := copy(p, m.readBuf)
	m.readBuf = m.readBuf[n:]
	return n, nil
}

// fetchFrame polls until Data Object Ready, then reads the full DOE
// frame from the Read Data Mailbox into m.readBuf.
func (m *MailboxConn) fetchFrame() error {
	if err := m.pollDataReady(); err != nil {
		return err
	}

	// Read first 2 DWORDs (DOE header) to get the total length.
	dw0, err := m.readMailboxDWORD()
	if err != nil {
		return err
	}

	dw1, err := m.readMailboxDWORD()
	if err != nil {
		return err
	}

	lengthDW := dw1 & doeLengthMask // bits [17:0] of DOE header DWORD 1
	if lengthDW < 2 {
		return &ErrInvalidLength{LengthDW: lengthDW}
	}
	if lengthDW > maxDOELengthDW {
		return &ErrInvalidLength{LengthDW: lengthDW}
	}

	frame := make([]byte, lengthDW*dwordSize)
	binary.LittleEndian.PutUint32(frame[0:4], dw0)
	binary.LittleEndian.PutUint32(frame[4:8], dw1)

	for i := uint32(2); i < lengthDW; i++ {
		dw, err := m.readMailboxDWORD()
		if err != nil {
			return err
		}
		binary.LittleEndian.PutUint32(frame[i*dwordSize:(i+1)*dwordSize], dw)
	}

	m.readBuf = frame
	return nil
}

// readMailboxDWORD reads one DWORD from the DOE Read Data Mailbox and
// writes back to advance to the next DWORD. Per PCIe 6.0 Section 6.30.3,
// software must write to the Read Data Mailbox register to advance the
// internal pointer after each read.
func (m *MailboxConn) readMailboxDWORD() (uint32, error) {
	dw, err := m.readRegister(doeReadDataMailboxOffset)
	if err != nil {
		return 0, err
	}

	if err := m.writeRegister(doeReadDataMailboxOffset, 0); err != nil {
		return 0, err
	}

	return dw, nil
}

// pollDataReady polls the DOE Status register until the Data Object
// Ready bit is set or the timeout expires.
func (m *MailboxConn) pollDataReady() error {
	deadline := time.Now().Add(m.PollTimeout)

	for {
		status, err := m.readRegister(doeStatusOffset)
		if err != nil {
			return err
		}

		if status&doeStatusError != 0 {
			return &ErrMailboxError{}
		}

		if status&doeStatusDataObjectReady != 0 {
			return nil
		}

		if time.Now().After(deadline) {
			return &ErrMailboxTimeout{}
		}

		time.Sleep(m.PollInterval)
	}
}

func (m *MailboxConn) readRegister(offset uint32) (uint32, error) {
	var buf [dwordSize]byte

	_, err := m.config.ReadAt(buf[:], int64(m.capBase+offset))
	if err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint32(buf[:]), nil
}

func (m *MailboxConn) writeRegister(
	offset uint32,
	value uint32,
) error {
	var buf [dwordSize]byte
	binary.LittleEndian.PutUint32(buf[:], value)

	_, err := m.config.WriteAt(buf[:], int64(m.capBase+offset))
	return err
}
