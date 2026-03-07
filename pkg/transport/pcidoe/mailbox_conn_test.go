package pcidoe

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// simulatedDOEDevice provides a fake PCI config space with DOE mailbox
// register behavior. It implements ConfigSpaceAccessor.
type simulatedDOEDevice struct {
	mu sync.Mutex

	capBase uint32

	// Simulated register state.
	busy         bool
	errorFlag    bool
	dataReady    bool
	writeMailbox []uint32
	readMailbox  []uint32
	readIndex    int
}

func newSimulatedDOEDevice(capBase uint32) *simulatedDOEDevice {
	return &simulatedDOEDevice{
		capBase: capBase,
	}
}

func (d *simulatedDOEDevice) ReadAt(
	p []byte,
	off int64,
) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	regOff := uint32(off) - d.capBase
	switch regOff {
	case doeStatusOffset:
		var status uint32
		if d.dataReady {
			status |= doeStatusDataObjectReady
		}
		if d.busy {
			status |= doeStatusBusy
		}
		if d.errorFlag {
			status |= doeStatusError
		}
		binary.LittleEndian.PutUint32(p[:4], status)
		return 4, nil

	case doeReadDataMailboxOffset:
		// Per PCIe DOE spec, reading the Read Data Mailbox returns the
		// current DWORD but does NOT advance the index. A write to this
		// register advances the index (see WriteAt).
		if d.readIndex < len(d.readMailbox) {
			binary.LittleEndian.PutUint32(p[:4], d.readMailbox[d.readIndex])
			return 4, nil
		}
		binary.LittleEndian.PutUint32(p[:4], 0)
		return 4, nil

	default:
		// Return zeros for unknown registers.
		for i := range p {
			p[i] = 0
		}
		return len(p), nil
	}
}

func (d *simulatedDOEDevice) WriteAt(
	p []byte,
	off int64,
) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	regOff := uint32(off) - d.capBase
	switch regOff {
	case doeWriteDataMailboxOffset:
		dw := binary.LittleEndian.Uint32(p[:4])
		d.writeMailbox = append(d.writeMailbox, dw)
		return 4, nil

	case doeControlOffset:
		val := binary.LittleEndian.Uint32(p[:4])
		if val&doeControlGO != 0 {
			// Echo: copy written data to read mailbox.
			d.readMailbox = make([]uint32, len(d.writeMailbox))
			copy(d.readMailbox, d.writeMailbox)
			d.writeMailbox = nil
			d.readIndex = 0
			d.dataReady = true
		}
		return 4, nil

	case doeReadDataMailboxOffset:
		// Per PCIe DOE spec, writing to the Read Data Mailbox register
		// advances the internal pointer to the next DWORD.
		d.readIndex++
		if d.readIndex >= len(d.readMailbox) {
			d.dataReady = false
		}
		return 4, nil

	default:
		return len(p), nil
	}
}

func TestMailboxConn_WriteRead(t *testing.T) {
	dev := newSimulatedDOEDevice(0x100)
	conn := NewMailboxConn(dev, 0x100)

	// Build a DOE frame: header (2 DWORDs) + 1 DWORD payload = 12 bytes.
	frame := make([]byte, 12)
	binary.LittleEndian.PutUint16(frame[0:2], DOEVendorIDPCISIG)
	frame[2] = DOEDataObjectTypeSPDM
	frame[3] = 0
	binary.LittleEndian.PutUint32(frame[4:8], 3) // 3 DWORDs
	binary.LittleEndian.PutUint32(frame[8:12], 0xDEADBEEF)

	n, err := conn.Write(frame)
	require.NoError(t, err)
	assert.Equal(t, 12, n)

	// Read the echoed frame back.
	buf := make([]byte, 12)
	n, err = conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 12, n)
	assert.Equal(t, frame, buf[:n])
}

func TestMailboxConn_WithTransport(t *testing.T) {
	dev := newSimulatedDOEDevice(0x100)
	conn := NewMailboxConn(dev, 0x100)
	tr := New(conn)
	ctx := context.Background()

	payload := []byte{0x01, 0x02, 0x03, 0x04}
	require.NoError(t, tr.SendMessage(ctx, nil, payload))

	_, got, err := tr.ReceiveMessage(ctx)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

func TestMailboxConn_BusyError(t *testing.T) {
	dev := newSimulatedDOEDevice(0x100)
	dev.busy = true
	conn := NewMailboxConn(dev, 0x100)

	frame := make([]byte, 8)
	binary.LittleEndian.PutUint16(frame[0:2], DOEVendorIDPCISIG)
	frame[2] = DOEDataObjectTypeSPDM
	binary.LittleEndian.PutUint32(frame[4:8], 2)

	_, err := conn.Write(frame)
	require.Error(t, err)

	var busyErr *ErrMailboxBusy
	assert.ErrorAs(t, err, &busyErr)
}

func TestMailboxConn_StatusError(t *testing.T) {
	dev := newSimulatedDOEDevice(0x100)
	dev.errorFlag = true
	conn := NewMailboxConn(dev, 0x100)

	frame := make([]byte, 8)
	binary.LittleEndian.PutUint16(frame[0:2], DOEVendorIDPCISIG)
	frame[2] = DOEDataObjectTypeSPDM
	binary.LittleEndian.PutUint32(frame[4:8], 2)

	_, err := conn.Write(frame)
	require.Error(t, err)

	var mboxErr *ErrMailboxError
	assert.ErrorAs(t, err, &mboxErr)
}

func TestMailboxConn_NotAligned(t *testing.T) {
	dev := newSimulatedDOEDevice(0x100)
	conn := NewMailboxConn(dev, 0x100)

	// 7 bytes is not DWORD-aligned.
	_, err := conn.Write(make([]byte, 7))
	require.Error(t, err)

	var alignErr *ErrMailboxNotAligned
	require.ErrorAs(t, err, &alignErr)
	assert.Equal(t, 7, alignErr.Size)
}

func TestMailboxConn_Timeout(t *testing.T) {
	dev := newSimulatedDOEDevice(0x100)
	conn := NewMailboxConn(dev, 0x100)

	// dataReady is false, so Read should poll and time out.
	conn.PollTimeout = 50 * time.Millisecond
	conn.PollInterval = 5 * time.Millisecond

	buf := make([]byte, 64)
	_, err := conn.Read(buf)
	require.Error(t, err)

	var timeoutErr *ErrMailboxTimeout
	assert.ErrorAs(t, err, &timeoutErr)
}

func TestMailboxConn_MultipleMessages(t *testing.T) {
	dev := newSimulatedDOEDevice(0x100)
	conn := NewMailboxConn(dev, 0x100)
	tr := New(conn)
	ctx := context.Background()

	messages := [][]byte{
		{0x01, 0x02, 0x03, 0x04},
		{0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C},
	}

	for _, msg := range messages {
		require.NoError(t, tr.SendMessage(ctx, nil, msg))

		_, got, err := tr.ReceiveMessage(ctx)
		require.NoError(t, err)
		assert.Equal(t, msg, got)
	}
}

func TestMailboxConn_ReadBuffering(t *testing.T) {
	dev := newSimulatedDOEDevice(0x100)
	conn := NewMailboxConn(dev, 0x100)

	// Write a 12-byte frame (3 DWORDs).
	frame := make([]byte, 12)
	binary.LittleEndian.PutUint16(frame[0:2], DOEVendorIDPCISIG)
	frame[2] = DOEDataObjectTypeSPDM
	frame[3] = 0
	binary.LittleEndian.PutUint32(frame[4:8], 3)
	binary.LittleEndian.PutUint32(frame[8:12], 0x12345678)

	n, err := conn.Write(frame)
	require.NoError(t, err)
	assert.Equal(t, 12, n)

	// Read in small chunks to verify internal buffering.
	var result bytes.Buffer
	smallBuf := make([]byte, 4)
	for result.Len() < 12 {
		n, err = conn.Read(smallBuf)
		require.NoError(t, err)
		result.Write(smallBuf[:n])
	}

	assert.Equal(t, frame, result.Bytes())
}
