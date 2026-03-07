# QEMU PCI-DOE E2E Test Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Validate PCI-DOE works end-to-end through QEMU with three test combinations: Go+Go, Ref+Go, Go+Ref.

**Architecture:** Promote the QEMU socket protocol from test-only code to a reusable `pkg/transport/qemusock/` package. Add a PCI DOE hardware mailbox `io.ReadWriter` (`MailboxConn`) to `pkg/transport/pcidoe/` for accessing real/emulated DOE via PCI config space. Extend CLI tools with new transport types. Build a QEMU E2E test harness that boots VMs with NVMe DOE devices.

**Tech Stack:** Go 1.24, QEMU 9.2.1, PCI DOE (PCIe spec), spdm-emu (DMTF reference), testify, cpio (initramfs)

---

### Task 1: Create `pkg/transport/qemusock/` package

Promote `tests/reference/interop/emu_transport.go` and `transport_bridge.go` into a proper, reusable package. The package provides two things:
1. Constants and protocol framing for the QEMU SPDM socket protocol
2. A `Bridge` that provides an `io.ReadWriter` for composing with existing transports like `pcidoe.Transport`

**Files:**
- Create: `pkg/transport/qemusock/qemusock.go`
- Create: `pkg/transport/qemusock/bridge.go`
- Create: `pkg/transport/qemusock/errors.go`
- Create: `pkg/transport/qemusock/qemusock_test.go`
- Create: `pkg/transport/qemusock/bridge_test.go`

**Step 1: Write unit tests for socket protocol framing**

Create `pkg/transport/qemusock/qemusock_test.go`:

```go
package qemusock

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSendCommand(t *testing.T) {
	var buf bytes.Buffer
	conn := &Conn{conn: &buf, transportType: TransportPCIDOE}

	payload := []byte{0xAA, 0xBB}
	require.NoError(t, conn.SendCommand(CommandNormal, payload))

	data := buf.Bytes()
	require.Len(t, data, 14) // 12 header + 2 payload

	assert.Equal(t, uint32(CommandNormal), binary.BigEndian.Uint32(data[0:4]))
	assert.Equal(t, uint32(TransportPCIDOE), binary.BigEndian.Uint32(data[4:8]))
	assert.Equal(t, uint32(2), binary.BigEndian.Uint32(data[8:12]))
	assert.Equal(t, []byte{0xAA, 0xBB}, data[12:14])
}

func TestRecvCommand(t *testing.T) {
	var buf bytes.Buffer
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint32(hdr[0:4], CommandNormal)
	binary.BigEndian.PutUint32(hdr[4:8], TransportPCIDOE)
	binary.BigEndian.PutUint32(hdr[8:12], 3)
	buf.Write(hdr)
	buf.Write([]byte{0x01, 0x02, 0x03})

	conn := &Conn{conn: &buf, transportType: TransportPCIDOE}
	cmd, payload, err := conn.RecvCommand()
	require.NoError(t, err)
	assert.Equal(t, uint32(CommandNormal), cmd)
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, payload)
}

func TestSendCommandEmptyPayload(t *testing.T) {
	var buf bytes.Buffer
	conn := &Conn{conn: &buf, transportType: TransportPCIDOE}

	require.NoError(t, conn.SendCommand(CommandShutdown, nil))

	data := buf.Bytes()
	require.Len(t, data, 12) // header only
	assert.Equal(t, uint32(CommandShutdown), binary.BigEndian.Uint32(data[0:4]))
	assert.Equal(t, uint32(0), binary.BigEndian.Uint32(data[8:12]))
}

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	conn := &Conn{conn: &buf, transportType: TransportPCIDOE}

	payload := []byte("hello spdm doe")
	require.NoError(t, conn.SendCommand(CommandNormal, payload))

	conn2 := &Conn{conn: &buf, transportType: TransportPCIDOE}
	cmd, got, err := conn2.RecvCommand()
	require.NoError(t, err)
	assert.Equal(t, uint32(CommandNormal), cmd)
	assert.Equal(t, payload, got)
}
```

**Step 2: Run tests to verify they fail**

Run: `cd /home/streaming/go/src/github.com/xaionaro-go/spdm && go test ./pkg/transport/qemusock/ -v -run TestSendCommand`
Expected: compilation error (package doesn't exist yet)

**Step 3: Implement `qemusock.go` — constants and Conn type**

Create `pkg/transport/qemusock/qemusock.go`:

```go
// Package qemusock implements the QEMU SPDM socket protocol (12-byte header framing)
// used by QEMU to communicate with external SPDM responders.
//
// Wire format (all header fields big-endian):
//
//	[4B Command] [4B TransportType] [4B PayloadSize] [PayloadSize bytes]
//
// Reference: QEMU include/system/spdm-socket.h and DMTF spdm-emu command.h.
package qemusock

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

const headerSize = 12

// Command constants for the socket protocol.
const (
	CommandNormal   uint32 = 0x0001
	CommandShutdown uint32 = 0xFFFE
	CommandTest     uint32 = 0xDEAD
)

// TransportType constants identifying the SPDM transport binding.
const (
	TransportNone   uint32 = 0x00
	TransportMCTP   uint32 = 0x01
	TransportPCIDOE uint32 = 0x02
)

// Conn wraps an io.ReadWriter and speaks the QEMU SPDM socket protocol.
type Conn struct {
	conn          io.ReadWriter
	transportType uint32
	mu            sync.Mutex
}

// NewConn creates a Conn over the given connection with the specified transport type.
func NewConn(
	conn io.ReadWriter,
	transportType uint32,
) *Conn {
	return &Conn{
		conn:          conn,
		transportType: transportType,
	}
}

// SendCommand writes a framed command to the connection.
func (c *Conn) SendCommand(command uint32, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var hdr [headerSize]byte
	binary.BigEndian.PutUint32(hdr[0:4], command)
	binary.BigEndian.PutUint32(hdr[4:8], c.transportType)
	binary.BigEndian.PutUint32(hdr[8:12], uint32(len(payload)))

	if _, err := c.conn.Write(hdr[:]); err != nil {
		return &ErrWriteHeader{Err: err}
	}
	if len(payload) > 0 {
		if _, err := c.conn.Write(payload); err != nil {
			return &ErrWritePayload{Err: err}
		}
	}
	return nil
}

// RecvCommand reads a framed response from the connection.
func (c *Conn) RecvCommand() (command uint32, payload []byte, err error) {
	var hdr [headerSize]byte
	if _, err := io.ReadFull(c.conn, hdr[:]); err != nil {
		return 0, nil, &ErrReadHeader{Err: err}
	}

	command = binary.BigEndian.Uint32(hdr[0:4])
	payloadSize := binary.BigEndian.Uint32(hdr[8:12])

	if payloadSize > 0 {
		payload = make([]byte, payloadSize)
		if _, err := io.ReadFull(c.conn, payload); err != nil {
			return 0, nil, &ErrReadPayload{Err: err}
		}
	}

	return command, payload, nil
}

// Shutdown sends a SHUTDOWN command.
func (c *Conn) Shutdown() error {
	return c.SendCommand(CommandShutdown, nil)
}

// TransportType returns the configured transport type.
func (c *Conn) TransportType() uint32 {
	return c.transportType
}
```

Create `pkg/transport/qemusock/errors.go`:

```go
package qemusock

import "fmt"

// ErrWriteHeader is returned when writing the socket protocol header fails.
type ErrWriteHeader struct{ Err error }

func (e *ErrWriteHeader) Error() string  { return fmt.Sprintf("qemusock: write header: %v", e.Err) }
func (e *ErrWriteHeader) Unwrap() error  { return e.Err }

// ErrWritePayload is returned when writing the socket protocol payload fails.
type ErrWritePayload struct{ Err error }

func (e *ErrWritePayload) Error() string { return fmt.Sprintf("qemusock: write payload: %v", e.Err) }
func (e *ErrWritePayload) Unwrap() error { return e.Err }

// ErrReadHeader is returned when reading the socket protocol header fails.
type ErrReadHeader struct{ Err error }

func (e *ErrReadHeader) Error() string   { return fmt.Sprintf("qemusock: read header: %v", e.Err) }
func (e *ErrReadHeader) Unwrap() error   { return e.Err }

// ErrReadPayload is returned when reading the socket protocol payload fails.
type ErrReadPayload struct{ Err error }

func (e *ErrReadPayload) Error() string  { return fmt.Sprintf("qemusock: read payload: %v", e.Err) }
func (e *ErrReadPayload) Unwrap() error  { return e.Err }

// ErrUnexpectedCommand is returned when an unexpected command is received.
type ErrUnexpectedCommand struct{ Command uint32 }

func (e *ErrUnexpectedCommand) Error() string {
	return fmt.Sprintf("qemusock: unexpected command 0x%04X", e.Command)
}
func (e *ErrUnexpectedCommand) Unwrap() error { return nil }
```

**Step 4: Run tests and verify they pass**

Run: `cd /home/streaming/go/src/github.com/xaionaro-go/spdm && go test ./pkg/transport/qemusock/ -v -run 'TestSendCommand|TestRecvCommand|TestRoundTrip'`
Expected: PASS

**Step 5: Write Bridge tests**

Create `pkg/transport/qemusock/bridge_test.go`:

```go
package qemusock

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/spdm/pkg/transport/pcidoe"
)

func TestBridge_DOERoundTrip(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Server side: qemusock bridge + pcidoe transport
	bridge := NewBridge(serverConn, TransportPCIDOE)
	bridge.Start()
	defer bridge.Close()

	doeTransport := pcidoe.New(bridge)

	// Client side: raw qemusock conn (simulates QEMU)
	qemuConn := NewConn(clientConn, TransportPCIDOE)

	// Build a DOE data object: DOE header + SPDM payload
	spdmPayload := []byte{0x10, 0x84, 0x00, 0x00} // GET_VERSION
	doeFrame := buildDOEFrame(spdmPayload)

	// QEMU sends DOE frame via socket protocol
	require.NoError(t, qemuConn.SendCommand(CommandNormal, doeFrame))

	// Server receives via pcidoe transport (DOE header stripped)
	_, msg, err := doeTransport.ReceiveMessage(context.Background())
	require.NoError(t, err)
	assert.True(t, bytes.HasPrefix(msg, spdmPayload))

	// Server sends response via pcidoe transport
	response := []byte{0x10, 0x04, 0x00, 0x00} // VERSION response
	require.NoError(t, doeTransport.SendMessage(context.Background(), nil, response))

	// QEMU receives DOE frame via socket protocol
	cmd, respFrame, err := qemuConn.RecvCommand()
	require.NoError(t, err)
	assert.Equal(t, uint32(CommandNormal), cmd)
	// respFrame should be a DOE frame containing the response
	assert.GreaterOrEqual(t, len(respFrame), 8+len(response))
}

func buildDOEFrame(spdmPayload []byte) []byte {
	totalBytes := 8 + len(spdmPayload)
	padded := (totalBytes + 3) &^ 3
	lengthDW := uint32(padded / 4)

	frame := make([]byte, padded)
	binary.LittleEndian.PutUint16(frame[0:2], pcidoe.DOEVendorIDPCISIG)
	frame[2] = pcidoe.DOEDataObjectTypeSPDM
	frame[3] = 0
	binary.LittleEndian.PutUint32(frame[4:8], lengthDW)
	copy(frame[8:], spdmPayload)
	return frame
}
```

**Step 6: Implement `bridge.go`**

Create `pkg/transport/qemusock/bridge.go`:

```go
package qemusock

import (
	"bytes"
	"io"
	"sync"
)

// Bridge adapts between the QEMU socket protocol and an io.ReadWriter
// suitable for composing with transport types like pcidoe.Transport.
//
// Usage:
//
//	bridge := qemusock.NewBridge(tcpConn, qemusock.TransportPCIDOE)
//	bridge.Start()
//	defer bridge.Close()
//	tr := pcidoe.New(bridge) // bridge implements io.ReadWriter
type Bridge struct {
	qemuConn *Conn
	pr       *io.PipeReader
	pw       *io.PipeWriter
	done     chan struct{}
	mu       sync.Mutex
}

// NewBridge creates a Bridge over the given connection.
func NewBridge(
	conn io.ReadWriter,
	transportType uint32,
) *Bridge {
	pr, pw := io.Pipe()
	return &Bridge{
		qemuConn: NewConn(conn, transportType),
		pr:       pr,
		pw:       pw,
		done:     make(chan struct{}),
	}
}

// Start begins the background receive loop that reads from the QEMU
// socket and writes payloads to the pipe for the transport layer.
func (b *Bridge) Start() {
	go b.receiveLoop()
}

// Read returns data from the receive pipe. Implements io.Reader.
func (b *Bridge) Read(p []byte) (int, error) {
	return b.pr.Read(p)
}

// Write sends data to QEMU via the socket protocol. Implements io.Writer.
func (b *Bridge) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.qemuConn.SendCommand(CommandNormal, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close shuts down the bridge.
func (b *Bridge) Close() error {
	select {
	case <-b.done:
	default:
		close(b.done)
	}
	b.pr.Close()
	b.pw.Close()
	return nil
}

// Conn returns the underlying Conn for direct protocol access (e.g. Shutdown).
func (b *Bridge) Conn() *Conn {
	return b.qemuConn
}

func (b *Bridge) receiveLoop() {
	defer b.pw.Close()
	for {
		select {
		case <-b.done:
			return
		default:
		}

		cmd, payload, err := b.qemuConn.RecvCommand()
		if err != nil {
			b.pw.CloseWithError(err)
			return
		}

		switch cmd {
		case CommandShutdown:
			return
		case CommandTest:
			b.mu.Lock()
			_ = b.qemuConn.SendCommand(CommandTest, nil)
			b.mu.Unlock()
			continue
		case CommandNormal:
			if len(payload) == 0 {
				continue
			}
			if _, err := b.pw.Write(payload); err != nil {
				return
			}
		default:
			b.pw.CloseWithError(&ErrUnexpectedCommand{Command: cmd})
			return
		}
	}
}

// ServerLoop runs a QEMU socket protocol server loop: receives SPDM requests,
// passes them to processFn, and sends the response back. Handles TEST and
// SHUTDOWN commands. Useful for running a Go responder behind the QEMU socket.
//
// The payloads are raw (no DOE framing stripped) — that is handled by the
// transport layer wrapping this.
func ServerLoop(
	conn io.ReadWriter,
	transportType uint32,
	processFn func(request []byte) ([]byte, error),
) error {
	qc := NewConn(conn, transportType)

	for {
		cmd, request, err := qc.RecvCommand()
		if err != nil {
			return &ErrReadHeader{Err: err}
		}

		switch cmd {
		case CommandTest:
			if err := qc.SendCommand(CommandTest, nil); err != nil {
				return err
			}
			continue
		case CommandShutdown:
			_ = qc.SendCommand(CommandShutdown, nil)
			return nil
		case CommandNormal:
			// handled below
		default:
			return &ErrUnexpectedCommand{Command: cmd}
		}

		if len(request) == 0 {
			continue
		}

		resp, err := processFn(request)
		if err != nil {
			return err
		}

		if err := qc.SendCommand(CommandNormal, resp); err != nil {
			return err
		}
	}
}

// ServerLoopDOE is like ServerLoop but wraps the process function with
// DOE framing: strips the DOE header from incoming requests and adds
// it to outgoing responses. This is what QEMU expects when
// TransportType=TransportPCIDOE.
func ServerLoopDOE(
	conn io.ReadWriter,
	processFn func(request []byte) ([]byte, error),
) error {
	doeProcess := func(request []byte) ([]byte, error) {
		// Strip 8-byte DOE header
		if len(request) < 8 {
			return nil, &ErrReadPayload{Err: io.ErrUnexpectedEOF}
		}
		spdmMsg := request[8:]
		// Remove DWORD padding
		spdmMsg = bytes.TrimRight(spdmMsg, "\x00")

		resp, err := processFn(spdmMsg)
		if err != nil {
			return nil, err
		}

		// Re-wrap in DOE header
		totalBytes := 8 + len(resp)
		padded := (totalBytes + 3) &^ 3
		frame := make([]byte, padded)
		// VendorID = PCI-SIG (0x0001), Type = SPDM (0x01)
		frame[0] = 0x01
		frame[1] = 0x00
		frame[2] = 0x01
		frame[3] = 0x00
		lengthDW := uint32(padded / 4)
		frame[4] = byte(lengthDW)
		frame[5] = byte(lengthDW >> 8)
		frame[6] = byte(lengthDW >> 16)
		frame[7] = byte(lengthDW >> 24)
		copy(frame[8:], resp)
		return frame, nil
	}
	return ServerLoop(conn, TransportPCIDOE, doeProcess)
}
```

**Step 7: Run all qemusock tests**

Run: `cd /home/streaming/go/src/github.com/xaionaro-go/spdm && go test ./pkg/transport/qemusock/ -v -count=1`
Expected: PASS

**Step 8: Commit**

```bash
git add pkg/transport/qemusock/
git commit -m "Add qemusock package for QEMU SPDM socket protocol"
```

---

### Task 2: Create PCI DOE MailboxConn

Implement `io.ReadWriter` over PCI DOE mailbox registers accessed via PCI config space (`/sys/bus/pci/devices/<BDF>/config`). This enables `pcidoe.Transport` to talk to real or QEMU-emulated DOE hardware.

**Files:**
- Create: `pkg/transport/pcidoe/mailbox_conn.go`
- Create: `pkg/transport/pcidoe/pci_doe_cap.go`
- Create: `pkg/transport/pcidoe/mailbox_conn_test.go`

**Step 1: Write tests with simulated PCI config space**

Create `pkg/transport/pcidoe/mailbox_conn_test.go`:

```go
package pcidoe

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// simulatedDOEDevice provides a fake PCI config space file for testing.
// It emulates the DOE mailbox register behavior.
type simulatedDOEDevice struct {
	writeMbox    []uint32
	readMbox     []uint32
	readMboxIdx  int
	statusReady  bool
	capOffset    int
	configSpace  []byte
}

func newSimulatedDOEDevice(capOffset int) *simulatedDOEDevice {
	configSpace := make([]byte, 4096)
	return &simulatedDOEDevice{
		capOffset:   capOffset,
		configSpace: configSpace,
	}
}

func (d *simulatedDOEDevice) ReadAt(p []byte, off int64) (int, error) {
	offset := int(off)
	if offset == d.capOffset+doeMboxStatusOffset && len(p) == 4 {
		var status uint32
		if d.statusReady {
			status |= doeStatusDataObjectReady
		}
		binary.LittleEndian.PutUint32(p, status)
		return 4, nil
	}
	if offset == d.capOffset+doeMboxReadOffset && len(p) == 4 {
		if d.readMboxIdx < len(d.readMbox) {
			binary.LittleEndian.PutUint32(p, d.readMbox[d.readMboxIdx])
			d.readMboxIdx++
			if d.readMboxIdx >= len(d.readMbox) {
				d.statusReady = false
				d.readMboxIdx = 0
				d.readMbox = nil
			}
		} else {
			binary.LittleEndian.PutUint32(p, 0)
		}
		return 4, nil
	}
	copy(p, d.configSpace[offset:offset+len(p)])
	return len(p), nil
}

func (d *simulatedDOEDevice) WriteAt(p []byte, off int64) (int, error) {
	offset := int(off)
	if offset == d.capOffset+doeMboxWriteOffset && len(p) == 4 {
		dw := binary.LittleEndian.Uint32(p)
		d.writeMbox = append(d.writeMbox, dw)
		return 4, nil
	}
	if offset == d.capOffset+doeMboxControlOffset && len(p) == 4 {
		ctrl := binary.LittleEndian.Uint32(p)
		if ctrl&doeControlGo != 0 {
			// Process the written data object — echo it back
			d.readMbox = make([]uint32, len(d.writeMbox))
			copy(d.readMbox, d.writeMbox)
			d.readMboxIdx = 0
			d.statusReady = true
			d.writeMbox = nil
		}
		return 4, nil
	}
	copy(d.configSpace[offset:offset+len(p)], p)
	return len(p), nil
}

func TestMailboxConn_WriteRead(t *testing.T) {
	dev := newSimulatedDOEDevice(0x100)
	mc := NewMailboxConn(dev, 0x100)

	// Build a DOE frame: header(8) + payload(4) = 12 bytes = 3 DWORDs
	frame := make([]byte, 12)
	binary.LittleEndian.PutUint16(frame[0:2], DOEVendorIDPCISIG)
	frame[2] = DOEDataObjectTypeSPDM
	binary.LittleEndian.PutUint32(frame[4:8], 3) // 3 DWORDs
	copy(frame[8:], []byte{0xAA, 0xBB, 0xCC, 0xDD})

	// Write the DOE frame
	n, err := mc.Write(frame)
	require.NoError(t, err)
	assert.Equal(t, 12, n)

	// Read the echoed response
	buf := make([]byte, 12)
	n, err = mc.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 12, n)
	assert.Equal(t, frame, buf[:n])
}

func TestMailboxConn_WithTransport(t *testing.T) {
	dev := newSimulatedDOEDevice(0x100)
	mc := NewMailboxConn(dev, 0x100)
	tr := New(mc)

	ctx := context.Background()
	payload := []byte{0x10, 0x84, 0x00, 0x00} // GET_VERSION
	require.NoError(t, tr.SendMessage(ctx, nil, payload))

	_, got, err := tr.ReceiveMessage(ctx)
	require.NoError(t, err)
	assert.True(t, bytes.HasPrefix(got, payload))
}
```

**Step 2: Run tests to verify they fail**

Run: `cd /home/streaming/go/src/github.com/xaionaro-go/spdm && go test ./pkg/transport/pcidoe/ -v -run TestMailboxConn`
Expected: compilation error

**Step 3: Implement MailboxConn and DOE capability constants**

Create `pkg/transport/pcidoe/pci_doe_cap.go`:

```go
package pcidoe

// PCI DOE Extended Capability register offsets (relative to capability base).
// Per PCI Express Base Specification, DOE Extended Capability.
const (
	doeMboxControlOffset = 0x08
	doeMboxStatusOffset  = 0x0C
	doeMboxWriteOffset   = 0x10
	doeMboxReadOffset    = 0x14

	doeControlGo    = 1 << 31
	doeControlAbort = 1 << 0

	doeStatusBusy             = 1 << 0
	doeStatusDataObjectReady  = 1 << 31
	doeStatusError            = 1 << 2

	// PCIe Extended Capability ID for DOE.
	pcieExtCapIDDOE = 0x002E
)
```

Create `pkg/transport/pcidoe/mailbox_conn.go`:

```go
package pcidoe

import (
	"encoding/binary"
	"fmt"
	"io"
)

// ConfigSpaceAccessor provides read/write access to PCI config space.
// Both *os.File (for sysfs config files) and test fakes implement this.
type ConfigSpaceAccessor interface {
	io.ReaderAt
	io.WriterAt
}

// MailboxConn implements io.ReadWriter over PCI DOE mailbox registers.
//
// Write sends a complete DOE data object through the DOE mailbox by writing
// DWORDs to the Write Data Mailbox register and setting the GO bit.
//
// Read polls the Status register for Data Object Ready, then reads DWORDs
// from the Read Data Mailbox register.
//
// Usage:
//
//	f, _ := os.OpenFile("/sys/bus/pci/devices/0000:00:05.0/config", os.O_RDWR, 0)
//	mc := pcidoe.NewMailboxConn(f, capOffset)
//	tr := pcidoe.New(mc) // reuse existing Transport
type MailboxConn struct {
	config    ConfigSpaceAccessor
	capOffset int
	readBuf   []byte
	readPos   int
}

// NewMailboxConn creates a MailboxConn for the DOE capability at the given
// offset in PCI config space.
func NewMailboxConn(
	config ConfigSpaceAccessor,
	capOffset int,
) *MailboxConn {
	return &MailboxConn{
		config:    config,
		capOffset: capOffset,
	}
}

// Write sends a DOE data object through the mailbox. The data must be a
// complete DOE frame (header + payload, DWORD-aligned).
func (mc *MailboxConn) Write(p []byte) (int, error) {
	if len(p)%4 != 0 {
		return 0, &ErrMailboxNotAligned{Size: len(p)}
	}

	status, err := mc.readStatus()
	if err != nil {
		return 0, err
	}
	if status&doeStatusBusy != 0 {
		return 0, &ErrMailboxBusy{}
	}
	if status&doeStatusError != 0 {
		return 0, &ErrMailboxError{}
	}

	// Write DWORDs to the Write Data Mailbox register
	for off := 0; off < len(p); off += 4 {
		dw := binary.LittleEndian.Uint32(p[off : off+4])
		if err := mc.writeReg(doeMboxWriteOffset, dw); err != nil {
			return off, fmt.Errorf("write DWORD at offset %d: %w", off, err)
		}
	}

	// Set GO bit
	if err := mc.writeReg(doeMboxControlOffset, doeControlGo); err != nil {
		return len(p), fmt.Errorf("set GO bit: %w", err)
	}

	return len(p), nil
}

// Read retrieves the DOE response from the mailbox. On the first call after
// a Write, it polls until Data Object Ready, reads all DWORDs, and buffers them.
// Subsequent calls return data from the buffer.
func (mc *MailboxConn) Read(p []byte) (int, error) {
	if mc.readPos >= len(mc.readBuf) {
		if err := mc.readResponse(); err != nil {
			return 0, err
		}
	}

	n := copy(p, mc.readBuf[mc.readPos:])
	mc.readPos += n
	if mc.readPos >= len(mc.readBuf) {
		mc.readBuf = nil
		mc.readPos = 0
	}
	return n, nil
}

func (mc *MailboxConn) readResponse() error {
	// Poll until Data Object Ready
	for i := 0; i < 1000000; i++ {
		status, err := mc.readStatus()
		if err != nil {
			return err
		}
		if status&doeStatusError != 0 {
			return &ErrMailboxError{}
		}
		if status&doeStatusDataObjectReady != 0 {
			break
		}
		if i == 999999 {
			return &ErrMailboxTimeout{}
		}
	}

	// Read first two DWORDs (DOE header) to get length
	dw0, err := mc.readReg(doeMboxReadOffset)
	if err != nil {
		return err
	}
	dw1, err := mc.readReg(doeMboxReadOffset)
	if err != nil {
		return err
	}

	lengthDW := dw1 & 0x3FFFF // 18-bit length field
	if lengthDW < 2 {
		return &ErrInvalidLength{LengthDW: lengthDW}
	}

	// Total response: lengthDW DWORDs (including the 2 header DWORDs already read)
	totalBytes := int(lengthDW) * 4
	mc.readBuf = make([]byte, totalBytes)
	binary.LittleEndian.PutUint32(mc.readBuf[0:4], dw0)
	binary.LittleEndian.PutUint32(mc.readBuf[4:8], dw1)

	for off := 8; off < totalBytes; off += 4 {
		dw, err := mc.readReg(doeMboxReadOffset)
		if err != nil {
			return err
		}
		binary.LittleEndian.PutUint32(mc.readBuf[off:off+4], dw)
	}

	mc.readPos = 0
	return nil
}

func (mc *MailboxConn) readStatus() (uint32, error) {
	return mc.readReg(doeMboxStatusOffset)
}

func (mc *MailboxConn) readReg(offset int) (uint32, error) {
	var buf [4]byte
	if _, err := mc.config.ReadAt(buf[:], int64(mc.capOffset+offset)); err != nil {
		return 0, fmt.Errorf("read reg 0x%X: %w", offset, err)
	}
	return binary.LittleEndian.Uint32(buf[:]), nil
}

func (mc *MailboxConn) writeReg(offset int, value uint32) error {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], value)
	if _, err := mc.config.WriteAt(buf[:], int64(mc.capOffset+offset)); err != nil {
		return fmt.Errorf("write reg 0x%X: %w", offset, err)
	}
	return nil
}
```

Add new error types to `pkg/transport/pcidoe/errors.go`:

```go
// ErrMailboxBusy is returned when the DOE mailbox is busy.
type ErrMailboxBusy struct{}
func (e *ErrMailboxBusy) Error() string { return "pcidoe: mailbox busy" }
func (e *ErrMailboxBusy) Unwrap() error { return nil }

// ErrMailboxError is returned when the DOE status register reports an error.
type ErrMailboxError struct{}
func (e *ErrMailboxError) Error() string { return "pcidoe: mailbox error" }
func (e *ErrMailboxError) Unwrap() error { return nil }

// ErrMailboxTimeout is returned when polling the DOE status times out.
type ErrMailboxTimeout struct{}
func (e *ErrMailboxTimeout) Error() string { return "pcidoe: mailbox timeout waiting for data object ready" }
func (e *ErrMailboxTimeout) Unwrap() error { return nil }

// ErrMailboxNotAligned is returned when data is not DWORD-aligned.
type ErrMailboxNotAligned struct{ Size int }
func (e *ErrMailboxNotAligned) Error() string {
	return fmt.Sprintf("pcidoe: data size %d is not DWORD-aligned", e.Size)
}
func (e *ErrMailboxNotAligned) Unwrap() error { return nil }
```

**Step 4: Run tests and verify they pass**

Run: `cd /home/streaming/go/src/github.com/xaionaro-go/spdm && go test ./pkg/transport/pcidoe/ -v -run TestMailboxConn -count=1`
Expected: PASS

**Step 5: Commit**

```bash
git add pkg/transport/pcidoe/mailbox_conn.go pkg/transport/pcidoe/pci_doe_cap.go pkg/transport/pcidoe/mailbox_conn_test.go pkg/transport/pcidoe/errors.go
git commit -m "Add PCI DOE mailbox hardware access via config space registers"
```

---

### Task 3: Add DOE capability discovery

Add `FindDOECapability` to scan PCI extended config space for the DOE extended capability and `FindDOEDevice` to discover devices with DOE support via sysfs.

**Files:**
- Create: `pkg/transport/pcidoe/discover.go`
- Create: `pkg/transport/pcidoe/discover_test.go`

**Step 1: Write tests**

Test `FindDOECapability` with a simulated config space that has extended capabilities chained at known offsets.

**Step 2: Implement**

`FindDOECapability(config ConfigSpaceAccessor) (int, error)` — walks the extended capability linked list starting at offset 0x100, looking for cap ID 0x002E. Returns the offset.

`FindDOEDevice() (configPath string, capOffset int, err error)` — walks `/sys/bus/pci/devices/*/config`, opens each, calls `FindDOECapability`. Returns first match.

**Step 3: Run tests, commit**

```bash
git commit -m "Add PCI DOE capability discovery via sysfs"
```

---

### Task 4: Extend `cmd/spdm-requester` with DOE and qemusock transports

**Files:**
- Modify: `cmd/spdm-requester/main.go`

**Step 1: Add transport creation logic**

Add a `createTransport(transportType, addr, pciAddr string) (transport.Transport, io.Closer, error)` function that:
- `"tcp"`: existing TCP behavior
- `"qemusock"`: dial TCP, create `qemusock.Bridge` + `pcidoe.New(bridge)`
- `"pcidoe"`: open PCI config space, find/use DOE capability, create `pcidoe.New(MailboxConn)`

Add `-pci-addr` flag (default "auto" — discover via sysfs).

Add PID 1 auto-detection: if `os.Getpid() == 1`, mount sysfs/procfs/devtmpfs and defer `syscall.Reboot(LINUX_REBOOT_CMD_POWER_OFF)`.

**Step 2: Test manually**

No automated test — this is CLI plumbing. Verified via the QEMU E2E tests in Task 6.

**Step 3: Commit**

```bash
git commit -m "Add pcidoe and qemusock transport support to spdm-requester"
```

---

### Task 5: Extend `cmd/spdm-responder` with qemusock transport

**Files:**
- Modify: `cmd/spdm-responder/main.go`

**Step 1: Add qemusock transport support**

When `-transport qemusock`:
- Listen on TCP (same `-listen` flag)
- Accept one connection
- Use `qemusock.ServerLoopDOE(conn, rsp.ProcessMessage)` to serve

**Step 2: Test manually**

Verify by running `spdm-responder -transport qemusock` and connecting with the QEMU socket protocol.

**Step 3: Commit**

```bash
git commit -m "Add qemusock transport support to spdm-responder"
```

---

### Task 6: Create QEMU E2E test harness

Build the infrastructure for running QEMU tests: initramfs creation, QEMU process management, serial output parsing.

**Files:**
- Create: `tests/qemu/harness_test.go`
- Create: `tests/qemu/initramfs_test.go`

Uses build tag `//go:build qemu` to avoid running in normal `go test ./...`.

**Step 1: Implement initramfs builder**

`buildInitramfs(t *testing.T, binaryPath string) string` — creates a cpio.gz archive containing the binary as `/init` plus empty dirs `/sys`, `/proc`, `/dev`. Returns path to temp file.

**Step 2: Implement QEMU launcher**

`launchQEMU(t *testing.T, cfg QEMUConfig) (serialOutput string, err error)` — starts QEMU with:
- `-M q35 -nographic -no-reboot`
- `-kernel <kernelPath> -initrd <initramfsPath>`
- `-append "console=ttyS0 panic=-1"`
- `-drive file=<nvmeImg>,if=none,id=nvme0,format=raw`
- `-device nvme,drive=nvme0,serial=test,spdm_port=<port>`
- Captures stdout+stderr (serial console output)
- Waits for QEMU to exit with timeout
- Returns combined output

**Step 3: Implement kernel discovery**

`findKernel() (string, error)` — checks `$QEMU_TEST_KERNEL`, then `/boot/vmlinuz-*`, returns path or error.

**Step 4: Commit**

```bash
git commit -m "Add QEMU E2E test harness with initramfs builder"
```

---

### Task 7: QEMU E2E test — Go requester + Go responder

**Files:**
- Create: `tests/qemu/go_go_test.go`

**Step 1: Write the test**

```go
//go:build qemu

func TestQEMU_GoRequester_GoResponder(t *testing.T) {
	kernelPath, err := findKernel()
	if err != nil {
		t.Skipf("no kernel available: %v", err)
	}

	// 1. Build guest binary (spdm-requester with pcidoe transport)
	guestBin := buildGuestBinary(t)

	// 2. Create initramfs
	initramfs := buildInitramfs(t, guestBin)

	// 3. Start Go SPDM responder on free port with qemusock
	port, cleanup := startGoResponder(t)
	defer cleanup()

	// 4. Create NVMe backing file
	nvmeImg := createNVMeImage(t)

	// 5. Launch QEMU
	output, err := launchQEMU(t, QEMUConfig{
		Kernel:    kernelPath,
		Initramfs: initramfs,
		NVMeImage: nvmeImg,
		SPDMPort:  port,
	})
	require.NoError(t, err)

	// 6. Verify output
	assert.Contains(t, output, "SPDM_DOE_TEST: PASS")
}
```

**Step 2: Implement helpers**

`startGoResponder(t) (port int, cleanup func())` — starts Go SPDM responder with `qemusock.ServerLoopDOE`, listening on a random free port.

`buildGuestBinary(t) string` — runs `go build -o <tmpdir>/init -ldflags '-extldflags -static' ./cmd/spdm-requester` with `CGO_ENABLED=0 GOOS=linux GOARCH=amd64`.

**Step 3: Run test**

Run: `cd /home/streaming/go/src/github.com/xaionaro-go/spdm && go test ./tests/qemu/ -v -tags=qemu -run TestQEMU_GoRequester_GoResponder -timeout 120s`
Expected: PASS (or SKIP if no kernel/QEMU)

**Step 4: Commit**

```bash
git commit -m "Add QEMU E2E test: Go requester + Go responder via PCI-DOE"
```

---

### Task 8: QEMU E2E test — Reference requester + Go responder

**Files:**
- Modify: `tests/qemu/ref_go_test.go`

**Step 1: Write the test**

Uses `spdm_requester_emu --trans PCI_DOE` connecting directly to our Go responder via QEMU socket protocol (no QEMU VM needed for this combination since spdm-emu speaks the socket protocol natively).

```go
//go:build qemu

func TestQEMU_RefRequester_GoResponder(t *testing.T) {
	emuBin := os.Getenv("SPDM_EMU_BIN")
	if emuBin == "" {
		t.Skip("SPDM_EMU_BIN not set")
	}

	port, cleanup := startGoResponder(t)
	defer cleanup()

	// Run spdm_requester_emu against our Go responder
	cmd := exec.Command(
		filepath.Join(emuBin, "spdm_requester_emu"),
		"--trans", "PCI_DOE",
		"--exe_conn", "NONE",
		"--pcap", "null",
	)
	cmd.Env = append(os.Environ(), fmt.Sprintf("SPDM_PORT=%d", port))
	output, err := cmd.CombinedOutput()
	t.Logf("spdm_requester_emu output:\n%s", output)
	require.NoError(t, err, "spdm_requester_emu failed")
}
```

**Step 2: Commit**

```bash
git commit -m "Add QEMU E2E test: reference requester + Go responder via PCI-DOE"
```

---

### Task 9: QEMU E2E test — Go requester + Reference responder

**Files:**
- Create: `tests/qemu/go_ref_test.go`

**Step 1: Write the test**

Start `spdm_responder_emu --trans PCI_DOE` on the host, boot QEMU with NVMe pointing to it, run our Go requester inside the VM.

```go
//go:build qemu

func TestQEMU_GoRequester_RefResponder(t *testing.T) {
	kernelPath, err := findKernel()
	if err != nil {
		t.Skipf("no kernel available: %v", err)
	}
	emuBin := os.Getenv("SPDM_EMU_BIN")
	if emuBin == "" {
		t.Skip("SPDM_EMU_BIN not set")
	}

	// 1. Start spdm_responder_emu
	port := findFreePort(t)
	proc := startEmuResponder(t, emuBin, port, "--trans", "PCI_DOE")
	defer proc.Stop()

	// 2. Build guest binary and initramfs
	guestBin := buildGuestBinary(t)
	initramfs := buildInitramfs(t, guestBin)
	nvmeImg := createNVMeImage(t)

	// 3. Launch QEMU pointing to spdm_responder_emu
	output, err := launchQEMU(t, QEMUConfig{
		Kernel:    kernelPath,
		Initramfs: initramfs,
		NVMeImage: nvmeImg,
		SPDMPort:  port,
	})
	require.NoError(t, err)
	assert.Contains(t, output, "SPDM_DOE_TEST: PASS")
}
```

**Step 2: Commit**

```bash
git commit -m "Add QEMU E2E test: Go requester + reference responder via PCI-DOE"
```

---

### Task 10: Update reference tests to use qemusock package

Refactor `tests/reference/interop/emu_transport.go` and `transport_bridge.go` to use the new `pkg/transport/qemusock/` package instead of duplicating the socket protocol implementation.

**Files:**
- Modify: `tests/reference/interop/emu_transport.go`
- Modify: `tests/reference/interop/transport_bridge.go`
- Modify: `tests/reference/interop/responder_infra_test.go`

**Step 1: Replace inline socket protocol code with qemusock.Conn/Bridge**

The `EmuTransport` becomes a thin wrapper around `qemusock.Conn`. The `DOESocketBridge` becomes `qemusock.NewBridge(conn, qemusock.TransportPCIDOE)`.

**Step 2: Run reference tests to verify no regression**

Run: `cd /home/streaming/go/src/github.com/xaionaro-go/spdm && go test ./tests/reference/interop/ -v -tags=reference -run TestInterop_GoRequester_LibspdmResponder_DOETransport`
Expected: PASS (same as before)

**Step 3: Commit**

```bash
git commit -m "Refactor reference tests to use pkg/transport/qemusock"
```

---

### Task 11: Add Makefile targets and CI

**Files:**
- Modify: `Makefile`
- Modify: `.github/workflows/ci.yml`

**Step 1: Add Makefile targets**

```makefile
test-qemu:
	go test ./tests/qemu/ -v -tags=qemu -timeout=300s -count=1

install-kernel:
	sudo apt-get install -y linux-image-generic
```

**Step 2: Add CI job** (optional, depends on CI runner having QEMU+KVM)

```yaml
qemu-test:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-go@v5
      with: { go-version: "1.24" }
    - run: sudo apt-get install -y qemu-system-x86 linux-image-generic
    - run: make test-qemu
```

**Step 3: Commit**

```bash
git commit -m "Add QEMU test Makefile targets and CI job"
```

---

### Task 12: Run all tests, lint, verify

**Step 1:** Run existing tests to ensure no regressions:
```bash
go test ./... -count=1
```

**Step 2:** Run linter:
```bash
go run github.com/golangci/golangci-lint/cmd/golangci-lint@latest run ./...
```

**Step 3:** Run QEMU tests (if kernel available):
```bash
go test ./tests/qemu/ -v -tags=qemu -timeout=300s -count=1
```
