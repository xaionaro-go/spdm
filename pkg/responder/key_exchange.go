package responder

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"hash"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
	"github.com/xaionaro-go/spdm/pkg/session"
)

// pendingSession stores state between KEY_EXCHANGE_RSP and FINISH.
type pendingSession struct {
	sessionID     session.SessionID
	sess          *session.Session
	hsKeys        *session.HandshakeKeys
	hsSecret      []byte
	newHash       func() hash.Hash
	certChainHash []byte
	keReqBytes    []byte
	keRspBytes    []byte
	slotID        uint8
}

// buildMeasurementSummaryHash produces the measurement summary hash for the
// given hash type, or nil when no summary is requested.
func (r *Responder) buildMeasurementSummaryHash(
	ctx context.Context,
	hashType uint8,
) ([]byte, error) {
	if hashType == msgs.NoMeasurementSummaryHash {
		return nil, nil
	}

	if r.cfg.MeasProvider != nil {
		return r.cfg.MeasProvider.SummaryHash(ctx, hashType)
	}

	return make([]byte, r.hashAlgo.Size()), nil
}

// computeCertChainHash returns the hash of the certificate chain for the given
// slot, or an all-zero hash when no cert provider is configured.
func (r *Responder) computeCertChainHash(
	ctx context.Context,
	slotID uint8,
	newHash func() hash.Hash,
) []byte {
	if r.cfg.CertProvider != nil {
		chain, err := r.cfg.CertProvider.CertChain(ctx, slotID)
		if err == nil {
			h := newHash()
			h.Write(chain)
			return h.Sum(nil)
		}
	}

	return make([]byte, r.hashAlgo.Size())
}

// computeKeyExchangeSignature builds TH1, constructs the SPDM 1.2 signing
// prefix, and signs the digest. It returns the SPDM-formatted signature.
func (r *Responder) computeKeyExchangeSignature(
	vcaTranscript []byte,
	certChainHash []byte,
	request []byte,
	respPartial []byte,
	newHash func() hash.Hash,
) ([]byte, error) {
	th1Hasher := newHash()
	th1Hasher.Write(vcaTranscript) // VCA (message A)
	th1Hasher.Write(certChainHash) // hash(cert_chain)
	th1Hasher.Write(request)       // KEY_EXCHANGE request
	th1Hasher.Write(respPartial)   // KEY_EXCHANGE_RSP without signature/verify data
	th1ForSig := th1Hasher.Sum(nil)

	// Build signing data with SPDM 1.2 prefix.
	var prefix [msgs.SigningContextSize]byte
	versionStr := msgs.SigningPrefixContext12
	for i := 0; i < 4; i++ {
		copy(prefix[i*len(versionStr):], versionStr)
	}
	contextStr := []byte(msgs.KeyExchangeRspSignContext)
	zeroPad := msgs.SigningContextSize - 4*len(versionStr) - len(contextStr)
	copy(prefix[4*len(versionStr)+zeroPad:], contextStr)

	var signData []byte
	signData = append(signData, prefix[:]...)
	signData = append(signData, th1ForSig...)

	h := r.hashAlgo.CryptoHash()
	digest := h.New()
	digest.Write(signData)
	digestBytes := digest.Sum(nil)

	derSig, err := r.cfg.DeviceSigner.Sign(rand.Reader, digestBytes, crypto.SignerOpts(h))
	if err != nil {
		return nil, err
	}

	return toSPDMSignature(r.asymAlgo, derSig)
}

// setupPendingSession creates a new session, derives handshake keys, optionally
// attaches verify data, marshals the final response, and stores the pending
// session state on the responder. It returns the final KEY_EXCHANGE_RSP bytes.
func (r *Responder) setupPendingSession(
	ctx context.Context,
	resp *msgs.KeyExchangeResponse,
	req *msgs.KeyExchange,
	rspSessionID uint16,
	newHash func() hash.Hash,
	certChainHash []byte,
	request []byte,
	sharedSecret []byte,
	slotID uint8,
) ([]byte, error) {
	// Derive handshake secret.
	hsSecret, err := session.DeriveHandshakeSecret(ctx, newHash, r.version, sharedSecret)
	if err != nil {
		return nil, err
	}
	logger.Debugf(ctx, "handleKeyExchange: DHE sharedSecret=%x hsSecret=%x", sharedSecret, hsSecret)

	// TH_key includes the signature per DSP0274 Section 15:
	// TH_key = hash(A || hash(cert_chain) || KEY_EXCHANGE_req || KEY_EXCHANGE_RSP_through_sig)
	respWithSig, err := resp.Marshal() // has signature but no verify data
	if err != nil {
		return nil, err
	}

	thKeyHasher := newHash()
	thKeyHasher.Write(r.vcaTranscript)
	thKeyHasher.Write(certChainHash)
	thKeyHasher.Write(request)
	thKeyHasher.Write(respWithSig)
	thKeyHash := thKeyHasher.Sum(nil)

	hsKeys, err := session.DeriveHandshakeKeys(ctx, newHash, r.version, r.aeadSuite, hsSecret, thKeyHash)
	if err != nil {
		return nil, err
	}

	// When HANDSHAKE_IN_THE_CLEAR_CAP is set, VerifyData is NOT included
	// in KEY_EXCHANGE_RSP per DSP0274 Section 10.12.
	if !r.cfg.Caps.HasHandshakeInTheClearCap() {
		resp.VerifyData = session.GenerateFinishedKey(ctx, newHash, hsKeys.ResponseFinished, thKeyHash)
	}

	keRspBytes, err := resp.Marshal()
	if err != nil {
		return nil, err
	}

	// Build session ID: upper 16 bits = rsp, lower 16 bits = req.
	combinedSessionID := session.SessionID(uint32(rspSessionID)<<16 | uint32(req.ReqSessionID))

	sess := session.NewSession(
		combinedSessionID,
		r.version,
		r.hashAlgo,
		r.aeadSuite,
		true,
	)
	sess.HandshakeKeys = hsKeys
	sess.HandshakeSecret = hsSecret

	// Store pending session state for FINISH processing.
	r.pending = &pendingSession{
		sessionID:     combinedSessionID,
		sess:          sess,
		hsKeys:        hsKeys,
		hsSecret:      hsSecret,
		newHash:       newHash,
		certChainHash: certChainHash,
		keReqBytes:    request,
		keRspBytes:    keRspBytes,
		slotID:        slotID,
	}

	logger.Debugf(ctx, "handleKeyExchange: sessionID=0x%08X", combinedSessionID)
	return keRspBytes, nil
}

func (r *Responder) handleKeyExchange(ctx context.Context, request []byte) ([]byte, error) {
	if !r.negotiated {
		return r.buildError(codes.ErrorUnexpectedRequest, 0), nil
	}

	// Determine DHE public key size from negotiated group.
	dheSize := r.dheGroup.DHEPublicKeySize()
	if dheSize == 0 {
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}

	var req msgs.KeyExchange
	if err := req.UnmarshalWithDHESize(request, dheSize); err != nil {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	slotID := req.SlotID()
	hashType := req.HashType()

	logger.Debugf(ctx, "handleKeyExchange: slot=%d hashType=%d DHE=%s", slotID, hashType, r.dheGroup)

	// Generate responder DHE keypair.
	keyPair, err := r.cfg.Crypto.KeyAgreement.GenerateDHE(r.dheGroup)
	if err != nil {
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}
	pubKey := keyPair.PublicKey()

	// Compute shared secret from requester's public key.
	sharedSecret, err := keyPair.ComputeSharedSecret(req.ExchangeData)
	if err != nil {
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}

	// Generate responder random data and session ID.
	var randomData [msgs.RandomDataSize]byte
	if _, err := rand.Read(randomData[:]); err != nil {
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}

	var rspSessionIDBuf [2]byte
	if _, err := rand.Read(rspSessionIDBuf[:]); err != nil {
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}
	rspSessionID := binary.LittleEndian.Uint16(rspSessionIDBuf[:])

	measHash, err := r.buildMeasurementSummaryHash(ctx, hashType)
	if err != nil {
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}

	// Build opaque data for response (same format as requester).
	opaqueData := buildKeyExchangeOpaqueData()

	resp := &msgs.KeyExchangeResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(r.version),
			RequestResponseCode: uint8(codes.ResponseKeyExchangeRsp),
			Param1:              0, // HeartbeatPeriod
			Param2:              0, // Reserved
		}},
		RspSessionID:           rspSessionID,
		MutAuthRequested:       0, // no mutual auth
		ReqSlotIDParam:         0,
		ExchangeData:           pubKey,
		MeasurementSummaryHash: measHash,
		OpaqueData:             opaqueData,
	}
	copy(resp.RandomData[:], randomData[:])

	newHash := func() hash.Hash { return r.hashAlgo.CryptoHash().New() }
	certChainHash := r.computeCertChainHash(ctx, slotID, newHash)

	// Sign the response per DSP0274 Section 15.
	// TH1 = hash(VCA + hash(cert_chain) + KEY_EXCHANGE_req + KEY_EXCHANGE_RSP_without_sig_verify)
	resp.Signature = nil
	resp.VerifyData = nil
	respPartial, err := resp.Marshal()
	if err != nil {
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}

	resp.Signature, err = r.computeKeyExchangeSignature(r.vcaTranscript, certChainHash, request, respPartial, newHash)
	if err != nil {
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}

	keRspBytes, err := r.setupPendingSession(ctx, resp, &req, rspSessionID, newHash, certChainHash, request, sharedSecret, slotID)
	if err != nil {
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}

	return keRspBytes, nil
}

func (r *Responder) handleFinish(ctx context.Context, request []byte) ([]byte, error) {
	if r.pending == nil {
		return r.buildError(codes.ErrorUnexpectedRequest, 0), nil
	}
	p := r.pending

	hashSize := r.hashAlgo.Size()

	var req msgs.Finish
	if err := req.UnmarshalWithSizes(request, 0, hashSize); err != nil {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	// Verify the requester's HMAC (verify data).
	// TH for Finish = hash(VCA + hash(cert_chain) + KEY_EXCHANGE_req + KEY_EXCHANGE_RSP + FINISH_header)
	finishHeaderBytes := request[:msgs.HeaderSize]

	thFinishHasher := p.newHash()
	thFinishHasher.Write(r.vcaTranscript)
	thFinishHasher.Write(p.certChainHash)
	thFinishHasher.Write(p.keReqBytes)
	thFinishHasher.Write(p.keRspBytes)
	thFinishHasher.Write(finishHeaderBytes)
	thFinishHash := thFinishHasher.Sum(nil)

	expectedVerify := session.GenerateFinishedKey(ctx, p.newHash, p.hsKeys.RequestFinished, thFinishHash)

	if len(req.VerifyData) != len(expectedVerify) ||
		subtle.ConstantTimeCompare(req.VerifyData, expectedVerify) != 1 {
		logger.Debugf(ctx, "handleFinish: verify data mismatch")
		return r.buildError(codes.ErrorDecryptError, 0), nil
	}

	// Build FINISH_RSP.
	finishResp := &msgs.FinishResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(r.version),
			RequestResponseCode: uint8(codes.ResponseFinishRsp),
		}},
	}

	// When HANDSHAKE_IN_THE_CLEAR, FINISH_RSP must include responder verify data.
	handshakeInClear := r.cfg.Caps.HasHandshakeInTheClearCap()
	if handshakeInClear {
		// TH for FINISH_RSP HMAC = hash(VCA + cert_chain_hash + message_k + FINISH_req + FINISH_RSP_header)
		finishRspHeader, err := finishResp.Marshal() // header only, no verify data yet
		if err != nil {
			return r.buildError(codes.ErrorUnspecified, 0), nil
		}

		thRspHasher := p.newHash()
		thRspHasher.Write(r.vcaTranscript)
		thRspHasher.Write(p.certChainHash)
		thRspHasher.Write(p.keReqBytes)
		thRspHasher.Write(p.keRspBytes)
		thRspHasher.Write(request)
		thRspHasher.Write(finishRspHeader)
		thRspHash := thRspHasher.Sum(nil)

		finishResp.VerifyData = session.GenerateFinishedKey(ctx, p.newHash, p.hsKeys.ResponseFinished, thRspHash)
	}

	finishRspBytes, err := finishResp.Marshal()
	if err != nil {
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}

	// Derive master secret and data keys.
	masterSecret, err := session.DeriveMasterSecret(ctx, p.newHash, r.version, p.hsSecret)
	if err != nil {
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}
	p.sess.MasterSecret = masterSecret

	// TH2 = hash(VCA + hash(cert_chain) + KEY_EXCHANGE_req + KEY_EXCHANGE_RSP + FINISH_req + FINISH_RSP)
	th2Hasher := p.newHash()
	th2Hasher.Write(r.vcaTranscript)
	th2Hasher.Write(p.certChainHash)
	th2Hasher.Write(p.keReqBytes)
	th2Hasher.Write(p.keRspBytes)
	th2Hasher.Write(request)
	th2Hasher.Write(finishRspBytes)
	th2Hash := th2Hasher.Sum(nil)

	logger.Debugf(ctx, "handleFinish: th2Hash=%x masterSecret=%x", th2Hash, masterSecret)

	dataKeys, err := session.DeriveDataKeys(ctx, p.newHash, r.version, r.aeadSuite, masterSecret, th2Hash)
	if err != nil {
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}
	p.sess.DataKeys = dataKeys
	p.sess.State = session.StateEstablished

	logger.Debugf(ctx, "handleFinish: reqKey=%x reqIV=%x rspKey=%x rspIV=%x",
		dataKeys.RequestKey, dataKeys.RequestIV, dataKeys.ResponseKey, dataKeys.ResponseIV)

	r.sessions[p.sessionID] = p.sess
	r.pending = nil

	logger.Debugf(ctx, "handleFinish: session 0x%08X established", p.sessionID)
	return finishRspBytes, nil
}

// buildKeyExchangeOpaqueData constructs opaque data per DSP0277 Section 6.2.
func buildKeyExchangeOpaqueData() []byte {
	// SELECTED_VERSION element for responder's KEY_EXCHANGE_RSP per DSP0277.
	// SMDataID = 0x00 = VERSION_SELECTION (responder selects version).
	elemData := []byte{
		0x01,       // SMDataVersion = 1
		0x00,       // SMDataID = VERSION_SELECTION
		0x00, 0x11, // SecuredSPDMVersion 1.1 (0x1100 LE)
	}

	elemHeader := make([]byte, 4)
	elemHeader[0] = 0 // ID = SPDM_REGISTRY_ID_DMTF
	elemHeader[1] = 0 // VendorLen = 0
	binary.LittleEndian.PutUint16(elemHeader[2:], uint16(len(elemData)))

	generalHeader := []byte{1, 0, 0, 0}

	var buf []byte
	buf = append(buf, generalHeader...)
	buf = append(buf, elemHeader...)
	buf = append(buf, elemData...)

	if pad := len(buf) % 4; pad != 0 {
		buf = append(buf, make([]byte, 4-pad)...)
	}
	return buf
}
