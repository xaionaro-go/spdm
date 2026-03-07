package qemusock

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/spdm/pkg/transport/pcidoe"
)

func TestServerLoop(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()

	client := NewConn(clientSide, TransportNone)
	errCh := make(chan error, 1)

	go func() {
		errCh <- ServerLoop(serverSide, TransportNone, func(request []byte) ([]byte, error) {
			// Echo the request reversed.
			resp := make([]byte, len(request))
			for i, b := range request {
				resp[len(request)-1-i] = b
			}
			return resp, nil
		})
	}()

	// Send a normal request.
	request := []byte{0x01, 0x02, 0x03}
	require.NoError(t, client.SendCommand(CommandNormal, request))

	cmd, response, err := client.RecvCommand()
	require.NoError(t, err)
	assert.Equal(t, uint32(CommandNormal), cmd)
	assert.Equal(t, []byte{0x03, 0x02, 0x01}, response)

	// Send shutdown to terminate the loop.
	require.NoError(t, client.SendCommand(CommandShutdown, nil))

	// Drain the shutdown echo the server sends back.
	cmd, _, err = client.RecvCommand()
	require.NoError(t, err)
	assert.Equal(t, uint32(CommandShutdown), cmd)

	require.NoError(t, <-errCh)
}

func TestServerLoop_TestCommand(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()

	client := NewConn(clientSide, TransportNone)
	errCh := make(chan error, 1)

	go func() {
		errCh <- ServerLoop(serverSide, TransportNone, func(request []byte) ([]byte, error) {
			return request, nil
		})
	}()

	// Send a TEST command; server should echo it back.
	require.NoError(t, client.SendCommand(CommandTest, nil))

	cmd, payload, err := client.RecvCommand()
	require.NoError(t, err)
	assert.Equal(t, uint32(CommandTest), cmd)
	assert.Empty(t, payload)

	// Shutdown.
	require.NoError(t, client.SendCommand(CommandShutdown, nil))
	cmd, _, err = client.RecvCommand()
	require.NoError(t, err)
	assert.Equal(t, uint32(CommandShutdown), cmd)
	require.NoError(t, <-errCh)
}

func TestServerLoopDOE(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()

	client := NewConn(clientSide, TransportPCIDOE)
	errCh := make(chan error, 1)

	go func() {
		errCh <- ServerLoopDOE(serverSide, func(request []byte) ([]byte, error) {
			// Echo the SPDM payload as-is.
			return request, nil
		})
	}()

	// Build a DOE-framed request.
	spdmPayload := []byte{0x10, 0x04, 0x00, 0x00}
	totalBytes := 8 + len(spdmPayload)
	padded := (totalBytes + 3) &^ 3
	lengthDW := uint32(padded / 4)

	doeRequest := make([]byte, padded)
	binary.LittleEndian.PutUint16(doeRequest[0:2], pcidoe.DOEVendorIDPCISIG)
	doeRequest[2] = pcidoe.DOEDataObjectTypeSPDM
	doeRequest[3] = 0
	binary.LittleEndian.PutUint32(doeRequest[4:8], lengthDW)
	copy(doeRequest[8:], spdmPayload)

	require.NoError(t, client.SendCommand(CommandNormal, doeRequest))

	cmd, responseFrame, err := client.RecvCommand()
	require.NoError(t, err)
	assert.Equal(t, uint32(CommandNormal), cmd)

	// Verify DOE framing of the response.
	require.True(t, len(responseFrame) >= 8+len(spdmPayload))
	vendorID := binary.LittleEndian.Uint16(responseFrame[0:2])
	assert.Equal(t, uint16(pcidoe.DOEVendorIDPCISIG), vendorID)
	assert.Equal(t, byte(pcidoe.DOEDataObjectTypeSPDM), responseFrame[2])
	respLenDW := binary.LittleEndian.Uint32(responseFrame[4:8])
	assert.Equal(t, lengthDW, respLenDW)
	gotSPDM := responseFrame[8 : 8+len(spdmPayload)]
	assert.Equal(t, spdmPayload, gotSPDM)

	// Shutdown.
	require.NoError(t, client.SendCommand(CommandShutdown, nil))
	cmd, _, err = client.RecvCommand()
	require.NoError(t, err)
	assert.Equal(t, uint32(CommandShutdown), cmd)
	require.NoError(t, <-errCh)
}

func TestServerLoop_UnexpectedCommand(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()

	client := NewConn(clientSide, TransportNone)
	errCh := make(chan error, 1)

	go func() {
		errCh <- ServerLoop(serverSide, TransportNone, func(request []byte) ([]byte, error) {
			return request, nil
		})
	}()

	// Send a command with an unknown command ID.
	require.NoError(t, client.SendCommand(0xBEEF, nil))

	err := <-errCh
	require.Error(t, err)
	assert.IsType(t, &ErrUnexpectedCommand{}, err)
}

func TestServerLoop_ProcessFnError(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()

	client := NewConn(clientSide, TransportNone)
	errCh := make(chan error, 1)
	processFnErr := fmt.Errorf("processing failed")

	go func() {
		errCh <- ServerLoop(serverSide, TransportNone, func(_ []byte) ([]byte, error) {
			return nil, processFnErr
		})
	}()

	require.NoError(t, client.SendCommand(CommandNormal, []byte{0x01}))

	err := <-errCh
	require.ErrorIs(t, err, processFnErr)
}

func TestServerLoopDOE_ShortPayload(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()

	client := NewConn(clientSide, TransportPCIDOE)
	errCh := make(chan error, 1)

	go func() {
		errCh <- ServerLoopDOE(serverSide, func(_ []byte) ([]byte, error) {
			return nil, nil
		})
	}()

	// Send a payload shorter than the DOE header (8 bytes).
	require.NoError(t, client.SendCommand(CommandNormal, []byte{0x01, 0x02}))

	err := <-errCh
	require.Error(t, err)
	assert.IsType(t, &ErrReadPayload{}, err)
}
