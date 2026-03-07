package msgs

import "github.com/xaionaro-go/spdm/pkg/gen/codes"

// SetKeyPairInfo is the SPDM SET_KEY_PAIR_INFO request per DSP0274 Section 10.25.
type SetKeyPairInfo struct {
	Header                   MessageHeader
	KeyPairID                uint8
	Operation                uint8
	DesiredKeyUsage          uint16
	DesiredAsymAlgo          uint32
	DesiredAssocCertSlotMask uint8
	PublicKeyInfo            []byte
}

func (m *SetKeyPairInfo) RequestCode() codes.RequestCode { return codes.RequestSetKeyPairInfo }

func (m *SetKeyPairInfo) Marshal() ([]byte, error) {
	buf := make([]byte, 0, HeaderSize+10+len(m.PublicKeyInfo))
	hdr, _ := m.Header.Marshal()
	buf = append(buf, hdr...)
	buf = append(buf, m.KeyPairID, m.Operation)

	b := [6]byte{}
	le.PutUint16(b[0:], m.DesiredKeyUsage)
	le.PutUint32(b[2:], m.DesiredAsymAlgo)
	buf = append(buf, b[:]...)
	buf = append(buf, m.DesiredAssocCertSlotMask)

	pkiLen := [2]byte{}
	le.PutUint16(pkiLen[:], uint16(len(m.PublicKeyInfo)))
	buf = append(buf, pkiLen[:]...)
	buf = append(buf, m.PublicKeyInfo...)
	return buf, nil
}

func (m *SetKeyPairInfo) Unmarshal(data []byte) error {
	if len(data) < HeaderSize+11 {
		return ErrShortBuffer
	}
	if err := m.Header.Unmarshal(data); err != nil {
		return err
	}
	off := HeaderSize
	m.KeyPairID = data[off]
	m.Operation = data[off+1]
	m.DesiredKeyUsage = le.Uint16(data[off+2:])
	m.DesiredAsymAlgo = le.Uint32(data[off+4:])
	m.DesiredAssocCertSlotMask = data[off+8]
	pkiLen := int(le.Uint16(data[off+9:]))
	off += 11
	if off+pkiLen > len(data) {
		return ErrShortBuffer
	}
	if pkiLen > 0 {
		m.PublicKeyInfo = make([]byte, pkiLen)
		copy(m.PublicKeyInfo, data[off:off+pkiLen])
	}
	return nil
}

// SetKeyPairInfoAck is the SPDM SET_KEY_PAIR_INFO_ACK response per DSP0274 Section 10.25.
type SetKeyPairInfoAck struct {
	Header MessageHeader
}

func (m *SetKeyPairInfoAck) ResponseCode() codes.ResponseCode {
	return codes.ResponseSetKeyPairInfoAck
}

func (m *SetKeyPairInfoAck) Marshal() ([]byte, error)    { return m.Header.Marshal() }
func (m *SetKeyPairInfoAck) Unmarshal(data []byte) error { return m.Header.Unmarshal(data) }
