package requester

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"hash"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
	"github.com/xaionaro-go/spdm/pkg/session"
)

// KeyExchange per DSP0274 Section 10.12 performs the KEY_EXCHANGE handshake and establishes a session.
// It generates a DHE keypair, sends KEY_EXCHANGE, receives KEY_EXCHANGE_RSP,
// derives handshake keys, sends FINISH with verify data, and returns the session.
func (r *Requester) KeyExchange(ctx context.Context, slotID uint8, hashType uint8) (_ret *session.Session, _err error) {
	logger.Tracef(ctx, "KeyExchange: slotID=%d hashType=%d", slotID, hashType)
	defer func() { logger.Tracef(ctx, "/KeyExchange: session:%v; err:%v", _ret, _err) }()
	ver := uint8(r.conn.PeerVersion)

	// Generate DHE keypair.
	keyPair, err := r.cfg.Crypto.KeyAgreement.GenerateDHE(r.conn.DHEGroup)
	if err != nil {
		return nil, &ErrGenerateDHEKeypair{Err: err}
	}
	pubKey := keyPair.PublicKey()

	// Generate random data and request session ID.
	var randomData [msgs.RandomDataSize]byte
	if _, err := rand.Read(randomData[:]); err != nil {
		return nil, &ErrGenerateRandomData{Err: err}
	}

	var reqSessionIDBuf [2]byte
	if _, err := rand.Read(reqSessionIDBuf[:]); err != nil {
		return nil, &ErrGenerateSessionID{Err: err}
	}
	reqSessionID := binary.LittleEndian.Uint16(reqSessionIDBuf[:])

	// Build opaque data per DSP0277 Section 6.2: OpaqueDataFmt1 with SecuredMessageVersion.
	opaqueData := buildKeyExchangeOpaqueData()

	keReq := &msgs.KeyExchange{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.RequestKeyExchange),
			Param1:              hashType,
			Param2:              slotID,
		}},
		ReqSessionID: reqSessionID,
		RandomData:   randomData,
		ExchangeData: pubKey,
		OpaqueData:   opaqueData,
	}

	reqBytes, err := keReq.Marshal()
	if err != nil {
		return nil, &ErrMarshalKeyExchange{Err: err}
	}

	resp, err := r.sendReceive(ctx, keReq)
	if err != nil {
		return nil, err
	}

	keResp, err := r.parseKeyExchangeResponse(resp, len(pubKey), hashType)
	if err != nil {
		return nil, err
	}

	// Compute DHE shared secret.
	sharedSecret, err := keyPair.ComputeSharedSecret(keResp.ExchangeData)
	if err != nil {
		return nil, &ErrComputeDHESharedSecret{Err: err}
	}

	// Use negotiated hash algorithm.
	newHash := func() hash.Hash { return r.conn.HashAlgo.CryptoHash().New() }

	// Compute hash of peer's certificate chain for TH computation.
	certChainHasher := newHash()
	certChainHasher.Write(r.peerCertChain)
	certChainHash := certChainHasher.Sum(nil)

	// Build TH1 per DSP0274 Section 15:
	// TH1 = hash(message_a + hash(cert_chain) + message_k)
	// message_a = VCA transcript, message_k = KEY_EXCHANGE_req + KEY_EXCHANGE_RSP (up to verify data)
	th1Hasher := newHash()
	th1Hasher.Write(r.vcaTranscript)
	th1Hasher.Write(certChainHash)
	th1Hasher.Write(reqBytes)
	th1Hasher.Write(keResp.respForTH1)
	th1Hash := th1Hasher.Sum(nil)

	// Derive handshake secret and keys.
	hsSecret, err := session.DeriveHandshakeSecret(ctx, newHash, r.conn.PeerVersion, sharedSecret)
	if err != nil {
		return nil, &ErrDeriveHandshakeSecret{Err: err}
	}

	hsKeys, err := session.DeriveHandshakeKeys(ctx, newHash, r.conn.PeerVersion, r.conn.AEADSuite, hsSecret, th1Hash)
	if err != nil {
		return nil, &ErrDeriveHandshakeKeys{Err: err}
	}

	// Build session ID: upper 16 bits = rsp, lower 16 bits = req.
	combinedSessionID := session.SessionID(uint32(keResp.RspSessionID)<<16 | uint32(reqSessionID))

	sess := session.NewSession(
		combinedSessionID,
		r.conn.PeerVersion,
		r.conn.HashAlgo,
		r.conn.AEADSuite,
		true,
	)
	sess.HandshakeKeys = hsKeys
	sess.HandshakeSecret = hsSecret

	if err := r.sendFinishAndFinalizeSession(ctx, sess, newHash, ver, slotID, certChainHash, reqBytes, resp); err != nil {
		return nil, err
	}

	r.sessions[combinedSessionID] = sess
	return sess, nil
}

// keyExchangeResponseParsed holds the parsed KEY_EXCHANGE_RSP fields
// along with the response bytes needed for TH1 computation.
type keyExchangeResponseParsed struct {
	msgs.KeyExchangeResponse
	// respForTH1 is the response bytes up to (but not including) verify data,
	// used for TH1 computation per DSP0274 Section 15.
	respForTH1 []byte
}

// parseKeyExchangeResponse manually parses a KEY_EXCHANGE_RSP from raw bytes,
// since field sizes depend on DHE key size, hash type, and asymmetric algorithm.
func (r *Requester) parseKeyExchangeResponse(
	resp []byte,
	dheSize int,
	hashType uint8,
) (*keyExchangeResponseParsed, error) {
	var keResp keyExchangeResponseParsed
	if err := keResp.Header.Unmarshal(resp); err != nil {
		return nil, &ErrUnmarshalHeader{Err: err}
	}

	off := msgs.HeaderSize
	if off+4 > len(resp) {
		return nil, &ErrResponseTooShort{Field: "session fields"}
	}
	keResp.RspSessionID = binary.LittleEndian.Uint16(resp[off:])
	keResp.MutAuthRequested = resp[off+2]
	keResp.ReqSlotIDParam = resp[off+3]
	off += 4

	if off+msgs.RandomDataSize > len(resp) {
		return nil, &ErrResponseTooShort{Field: "random data"}
	}
	copy(keResp.RandomData[:], resp[off:off+msgs.RandomDataSize])
	off += msgs.RandomDataSize

	if off+dheSize > len(resp) {
		return nil, &ErrResponseTooShort{Field: "exchange data"}
	}
	keResp.ExchangeData = make([]byte, dheSize)
	copy(keResp.ExchangeData, resp[off:off+dheSize])
	off += dheSize

	// Measurement summary hash (size depends on hashType).
	measHashSize := 0
	if hashType != msgs.NoMeasurementSummaryHash {
		measHashSize = r.conn.HashAlgo.Size()
	}
	if measHashSize > 0 {
		if off+measHashSize > len(resp) {
			return nil, &ErrResponseTooShort{Field: "measurement summary hash"}
		}
		keResp.MeasurementSummaryHash = make([]byte, measHashSize)
		copy(keResp.MeasurementSummaryHash, resp[off:off+measHashSize])
		off += measHashSize
	}

	// Opaque data.
	if off+2 > len(resp) {
		return nil, &ErrResponseTooShort{Field: "opaque length"}
	}
	opaqueLen := int(binary.LittleEndian.Uint16(resp[off:]))
	off += 2
	if off+opaqueLen > len(resp) {
		return nil, &ErrResponseTooShort{Field: "opaque data"}
	}
	keResp.OpaqueData = make([]byte, opaqueLen)
	copy(keResp.OpaqueData, resp[off:off+opaqueLen])
	off += opaqueLen

	// Signature.
	sigSize := r.conn.AsymAlgo.SignatureSize()
	if off+sigSize > len(resp) {
		return nil, &ErrResponseTooShort{Field: "signature"}
	}
	keResp.Signature = make([]byte, sigSize)
	copy(keResp.Signature, resp[off:off+sigSize])
	off += sigSize

	// respForTH1 captures everything up to (but not including) verify data.
	keResp.respForTH1 = resp[:off]

	// Verify data (HMAC).
	hashSize := r.conn.HashAlgo.Size()
	if off+hashSize <= len(resp) {
		keResp.VerifyData = make([]byte, hashSize)
		copy(keResp.VerifyData, resp[off:off+hashSize])
	}

	return &keResp, nil
}

// sendFinishAndFinalizeSession builds and sends FINISH, then derives
// master secret and data keys to finalize the session.
func (r *Requester) sendFinishAndFinalizeSession(
	ctx context.Context,
	sess *session.Session,
	newHash func() hash.Hash,
	ver uint8,
	slotID uint8,
	certChainHash []byte,
	reqBytes []byte,
	resp []byte,
) error {
	// Build FINISH header first (without verify data) for TH computation.
	finishHeader := msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
		SPDMVersion:         ver,
		RequestResponseCode: uint8(codes.RequestFinish),
		Param1:              0, // no signature
		Param2:              slotID,
	}}
	finishHeaderBytes, _ := finishHeader.Marshal()

	// Compute TH for Finish verify data per DSP0274 Section 15:
	// TH = hash(message_a + hash(cert_chain) + message_k + message_f_partial)
	// message_k = full KEY_EXCHANGE_req + KEY_EXCHANGE_RSP
	// message_f_partial = FINISH header only (without signature or HMAC)
	thFinishHasher := newHash()
	thFinishHasher.Write(r.vcaTranscript)
	thFinishHasher.Write(certChainHash)
	thFinishHasher.Write(reqBytes)
	thFinishHasher.Write(resp)
	thFinishHasher.Write(finishHeaderBytes)
	thFinishHash := thFinishHasher.Sum(nil)

	// Generate FINISH verify data.
	verifyData := session.GenerateFinishedKey(ctx, newHash, sess.HandshakeKeys.RequestFinished, thFinishHash)

	// Send FINISH.
	finishReq := &msgs.Finish{
		Header:     finishHeader,
		VerifyData: verifyData,
	}

	finishResp, err := r.sendReceive(ctx, finishReq)
	if err != nil {
		return &ErrFinish{Err: err}
	}

	var fr msgs.FinishResponse
	if err := fr.Unmarshal(finishResp); err != nil {
		return &ErrUnmarshalFinishResponse{Err: err}
	}

	// Derive master secret and data keys.
	masterSecret, err := session.DeriveMasterSecret(ctx, newHash, r.conn.PeerVersion, sess.HandshakeSecret)
	if err != nil {
		return &ErrDeriveMasterSecret{Err: err}
	}
	sess.MasterSecret = masterSecret

	// TH2 per DSP0274 Section 15:
	// TH2 = hash(message_a + hash(cert_chain) + message_k + message_f)
	// message_f = FINISH_req + FINISH_RSP
	th2Hasher := newHash()
	th2Hasher.Write(r.vcaTranscript)
	th2Hasher.Write(certChainHash)
	th2Hasher.Write(reqBytes)
	th2Hasher.Write(resp)
	finishBytes, _ := finishReq.Marshal()
	th2Hasher.Write(finishBytes)
	th2Hasher.Write(finishResp)
	th2Hash := th2Hasher.Sum(nil)

	dataKeys, err := session.DeriveDataKeys(ctx, newHash, r.conn.PeerVersion, r.conn.AEADSuite, masterSecret, th2Hash)
	if err != nil {
		return &ErrDeriveDataKeys{Err: err}
	}
	sess.DataKeys = dataKeys
	sess.State = session.StateEstablished

	return nil
}

// buildKeyExchangeOpaqueData constructs opaque data for KEY_EXCHANGE per
// DSP0277 Section 6.2: OpaqueDataFmt1 with SUPPORTED_VERSION element.
//
// The format is:
//   - OpaqueDataGeneralHeader: TotalElements(1) + Reserved(3)
//   - OpaqueElementHeader: ID(1) + VendorLen(1) + OpaqueElementDataLen(2)
//   - OpaqueElementSupportedVersion: VersionCount(1) + Versions(N*4)
//
// Each version entry is: MajorVersion(1) + MinorVersion(1) + UpdateVersionNumber(1) + Alpha(1)
func buildKeyExchangeOpaqueData() []byte {
	// Per DSP0277 Section 6.2, SPDM 1.2 uses OpaqueDataFmt1:
	//   spdm_general_opaque_data_table_header_t:
	//     TotalElements(1) + Reserved(3)
	//   secured_message_opaque_element_table_header_t:
	//     ID(1) + VendorLen(1) + OpaqueElementDataLen(2)
	//   secured_message_opaque_element_supported_version_t:
	//     SMDataVersion(1) + SMDataID(1) + VersionCount(1)
	//   spdm_version_number_t[]:
	//     Each entry is 4 bytes (MajorMinor(2) + UpdateAlpha(2))

	// Opaque element data = SMDataVersion + SMDataID + VersionCount + version entries.
	// spdm_version_number_t is uint16_t: (version << 8) in LE.
	// Secured SPDM 1.1 = 0x11 << 8 = 0x1100 → LE bytes: 0x00, 0x11.
	elemData := []byte{
		0x01,       // SMDataVersion = 1
		0x01,       // SMDataID = SUPPORTED_VERSION
		0x01,       // VersionCount = 1
		0x00, 0x11, // SecuredSPDMVersion 1.1 (0x1100 LE)
	}

	// OpaqueElementHeader: ID(1) + VendorLen(1) + OpaqueElementDataLen(2)
	elemHeader := make([]byte, 4)
	elemHeader[0] = 0 // ID = SPDM_REGISTRY_ID_DMTF
	elemHeader[1] = 0 // VendorLen = 0
	binary.LittleEndian.PutUint16(elemHeader[2:], uint16(len(elemData)))

	// OpaqueDataGeneralHeader: TotalElements(1) + Reserved(3)
	generalHeader := []byte{1, 0, 0, 0}

	var buf []byte
	buf = append(buf, generalHeader...)
	buf = append(buf, elemHeader...)
	buf = append(buf, elemData...)

	// Per DSP0277/libspdm: opaque data must be 4-byte aligned, with zero padding.
	if pad := len(buf) % 4; pad != 0 {
		buf = append(buf, make([]byte, 4-pad)...)
	}
	return buf
}
