package qemusock

import (
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/spdm/pkg/transport/pcidoe"
)

func TestBridge_DOERoundTrip(t *testing.T) {
	// Set up a net.Pipe: one end is used by the Bridge + pcidoe.Transport,
	// the other end is used by a raw Conn simulating spdm-emu.
	bridgeSide, emuSide := net.Pipe()
	defer bridgeSide.Close()
	defer emuSide.Close()

	bridge := NewBridge(bridgeSide, TransportPCIDOE)
	bridge.Start()
	defer bridge.Close()

	emu := NewConn(emuSide, TransportPCIDOE)
	doeTransport := pcidoe.New(bridge)
	ctx := context.Background()

	// emu sends a DOE-framed SPDM message to the bridge side.
	spdmPayload := []byte{0x10, 0x04, 0x00, 0x00} // example SPDM message

	totalBytes := 8 + len(spdmPayload)
	padded := (totalBytes + 3) &^ 3
	lengthDW := uint32(padded / 4)

	doeFrame := make([]byte, padded)
	binary.LittleEndian.PutUint16(doeFrame[0:2], pcidoe.DOEVendorIDPCISIG)
	doeFrame[2] = pcidoe.DOEDataObjectTypeSPDM
	doeFrame[3] = 0
	binary.LittleEndian.PutUint32(doeFrame[4:8], lengthDW)
	copy(doeFrame[8:], spdmPayload)

	errCh := make(chan error, 1)
	go func() {
		errCh <- emu.SendCommand(CommandNormal, doeFrame)
	}()

	_, got, err := doeTransport.ReceiveMessage(ctx)
	require.NoError(t, err)
	assert.Equal(t, spdmPayload, got)
	require.NoError(t, <-errCh)

	// Now send a response back through the bridge.
	spdmResponse := []byte{0x10, 0x64, 0x00, 0x00}
	go func() {
		errCh <- doeTransport.SendMessage(ctx, nil, spdmResponse)
	}()

	cmd, responseFrame, err := emu.RecvCommand()
	require.NoError(t, err)
	assert.Equal(t, uint32(CommandNormal), cmd)
	require.NoError(t, <-errCh)

	// Verify the DOE frame wrapping.
	require.True(t, len(responseFrame) >= 8+len(spdmResponse))
	vendorID := binary.LittleEndian.Uint16(responseFrame[0:2])
	assert.Equal(t, uint16(pcidoe.DOEVendorIDPCISIG), vendorID)
	assert.Equal(t, byte(pcidoe.DOEDataObjectTypeSPDM), responseFrame[2])
	gotResponse := responseFrame[8 : 8+len(spdmResponse)]
	assert.Equal(t, spdmResponse, gotResponse)
}

func TestBridge_TestCommandEcho(t *testing.T) {
	bridgeSide, emuSide := net.Pipe()
	defer bridgeSide.Close()
	defer emuSide.Close()

	bridge := NewBridge(bridgeSide, TransportNone)
	bridge.Start()
	defer bridge.Close()

	emu := NewConn(emuSide, TransportNone)

	// Send a TEST command; the bridge should echo it back.
	errCh := make(chan error, 1)
	go func() {
		errCh <- emu.SendCommand(CommandTest, nil)
	}()
	require.NoError(t, <-errCh)

	cmd, payload, err := emu.RecvCommand()
	require.NoError(t, err)
	assert.Equal(t, uint32(CommandTest), cmd)
	assert.Empty(t, payload)
}

func TestBridge_ShutdownStopsLoop(t *testing.T) {
	bridgeSide, emuSide := net.Pipe()
	defer bridgeSide.Close()
	defer emuSide.Close()

	bridge := NewBridge(bridgeSide, TransportNone)
	bridge.Start()
	defer bridge.Close()

	emu := NewConn(emuSide, TransportNone)

	// Send SHUTDOWN; the bridge receive loop should exit and subsequent
	// reads should return an error (pipe closed).
	require.NoError(t, emu.SendCommand(CommandShutdown, nil))

	buf := make([]byte, 1)
	_, err := bridge.Read(buf)
	require.Error(t, err)
}

func TestBridge_Conn(t *testing.T) {
	bridgeSide, _ := net.Pipe()
	defer bridgeSide.Close()

	bridge := NewBridge(bridgeSide, TransportMCTP)
	defer bridge.Close()
	assert.Equal(t, uint32(TransportMCTP), bridge.Conn().TransportType())
}

func TestBridge_WriteError(t *testing.T) {
	// Close the bridge side to force a write error.
	bridgeSide, emuSide := net.Pipe()
	emuSide.Close()

	bridge := NewBridge(bridgeSide, TransportNone)
	defer bridge.Close()

	_, err := bridge.Write([]byte("data"))
	require.Error(t, err)
}

func TestBridge_NormalEmptyPayloadSkipped(t *testing.T) {
	bridgeSide, emuSide := net.Pipe()
	defer bridgeSide.Close()
	defer emuSide.Close()

	bridge := NewBridge(bridgeSide, TransportNone)
	bridge.Start()
	defer bridge.Close()

	emu := NewConn(emuSide, TransportNone)

	// Send a normal command with empty payload (should be skipped),
	// then a normal command with actual data.
	errCh := make(chan error, 2)
	go func() {
		if err := emu.SendCommand(CommandNormal, nil); err != nil {
			errCh <- err
			return
		}
		errCh <- emu.SendCommand(CommandNormal, []byte{0x42})
	}()

	buf := make([]byte, 1)
	n, err := bridge.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, byte(0x42), buf[0])
	require.NoError(t, <-errCh)
}
