package pcidoe

import (
	"context"
	"encoding/binary"
	"io"
	"sync"
)

const headerSizeBytes = 8 // 2 DWORDs

// Transport implements transport.Transport for PCI DOE.
// It wraps messages with the 8-byte DOE header and uses the
// underlying connection for framing.
type Transport struct {
	conn io.ReadWriter
	mu   sync.Mutex
}

// New creates a new PCI DOE transport over the given connection.
func New(conn io.ReadWriter) *Transport {
	return &Transport{conn: conn}
}

func (t *Transport) SendMessage(_ context.Context, _ *uint32, msg []byte) error {
	// Total length in bytes: 8 (header) + payload, rounded up to 4-byte DWORD boundary.
	payloadLen := len(msg)
	totalBytes := headerSizeBytes + payloadLen
	padded := (totalBytes + 3) &^ 3 // round up to DWORD
	lengthDW := uint32(padded / 4)

	frame := make([]byte, padded)
	binary.LittleEndian.PutUint16(frame[0:2], DOEVendorIDPCISIG)
	frame[2] = DOEDataObjectTypeSPDM
	frame[3] = 0 // reserved
	binary.LittleEndian.PutUint32(frame[4:8], lengthDW)
	copy(frame[8:], msg)

	t.mu.Lock()
	defer t.mu.Unlock()
	_, err := t.conn.Write(frame)
	return err
}

func (t *Transport) ReceiveMessage(_ context.Context) (*uint32, []byte, error) {
	var hdr [headerSizeBytes]byte
	if _, err := io.ReadFull(t.conn, hdr[:]); err != nil {
		return nil, nil, &ErrReadHeader{Err: err}
	}

	lengthDW := binary.LittleEndian.Uint32(hdr[4:8])
	if lengthDW < 2 {
		return nil, nil, &ErrInvalidLength{LengthDW: lengthDW}
	}
	payloadBytes := int(lengthDW*4) - headerSizeBytes
	if payloadBytes < 0 {
		return nil, nil, &ErrNegativePayloadLength{}
	}

	payload := make([]byte, payloadBytes)
	if _, err := io.ReadFull(t.conn, payload); err != nil {
		return nil, nil, &ErrReadPayload{Err: err}
	}

	return nil, payload, nil
}

func (t *Transport) HeaderSize() int { return headerSizeBytes }
