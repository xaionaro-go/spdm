package responder

import (
	"context"
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

// pendingPSKSession stores state between PSK_EXCHANGE_RSP and PSK_FINISH.
type pendingPSKSession struct {
	sessionID   session.SessionID
	sess        *session.Session
	hsKeys      *session.HandshakeKeys
	hsSecret    []byte
	newHash     func() hash.Hash
	pskReqBytes []byte
	pskRspBytes []byte
}

func (r *Responder) handlePSKExchange(ctx context.Context, request []byte) ([]byte, error) {
	if !r.negotiated {
		return r.buildError(codes.ErrorUnexpectedRequest, 0), nil
	}

	if r.cfg.PSKProvider == nil {
		return r.buildError(codes.ErrorUnsupportedRequest, 0), nil
	}

	var req msgs.PSKExchange
	if err := req.Unmarshal(request); err != nil {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	logger.Debugf(ctx, "handlePSKExchange: hintLen=%d contextLen=%d", len(req.PSKHint), len(req.Context))

	// Look up PSK by hint.
	psk, err := r.cfg.PSKProvider.Lookup(ctx, req.PSKHint)
	if err != nil {
		logger.Debugf(ctx, "handlePSKExchange: PSK lookup failed: %v", err)
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}

	newHash := func() hash.Hash { return r.hashAlgo.CryptoHash().New() }
	hashSize := r.hashAlgo.Size()

	// Generate responder random context and session ID.
	rspContext := make([]byte, hashSize)
	if _, err := rand.Read(rspContext); err != nil {
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}

	var rspSessionIDBuf [2]byte
	if _, err := rand.Read(rspSessionIDBuf[:]); err != nil {
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}
	rspSessionID := binary.LittleEndian.Uint16(rspSessionIDBuf[:])

	// Build measurement summary hash.
	hashType := req.Header.Param1
	var measHash []byte
	if hashType != msgs.NoMeasurementSummaryHash {
		if r.cfg.MeasProvider != nil {
			measHash, err = r.cfg.MeasProvider.SummaryHash(ctx, hashType)
			if err != nil {
				return r.buildError(codes.ErrorUnspecified, 0), nil
			}
		} else {
			measHash = make([]byte, hashSize)
		}
	}

	// Build opaque data for response.
	opaqueData := buildKeyExchangeOpaqueData()

	resp := &msgs.PSKExchangeResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(r.version),
			RequestResponseCode: uint8(codes.ResponsePSKExchangeRsp),
			Param1:              0, // HeartbeatPeriod
			Param2:              0, // Reserved
		}},
		RspSessionID:           rspSessionID,
		MeasurementSummaryHash: measHash,
		Context:                rspContext,
		OpaqueData:             opaqueData,
	}

	// Derive handshake secret from PSK.
	hsSecret, err := session.DeriveHandshakeSecret(ctx, newHash, r.version, psk)
	if err != nil {
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}

	// TH1 for PSK = hash(VCA || PSK_EXCHANGE_req || PSK_EXCHANGE_RSP_without_verify_data)
	// Marshal response without verify data first.
	resp.VerifyData = nil
	respPartial, err := resp.Marshal()
	if err != nil {
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}

	th1Hasher := newHash()
	th1Hasher.Write(r.vcaTranscript)
	th1Hasher.Write(request)
	th1Hasher.Write(respPartial)
	th1Hash := th1Hasher.Sum(nil)

	// Derive handshake keys.
	hsKeys, err := session.DeriveHandshakeKeys(ctx, newHash, r.version, r.aeadSuite, hsSecret, th1Hash)
	if err != nil {
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}

	// Compute verify data for PSK_EXCHANGE_RSP.
	verifyData := session.GenerateFinishedKey(ctx, newHash, hsKeys.ResponseFinished, th1Hash)
	resp.VerifyData = verifyData

	pskRspBytes, err := resp.Marshal()
	if err != nil {
		return r.buildError(codes.ErrorUnspecified, 0), nil
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

	// Store pending PSK session state for PSK_FINISH processing.
	r.pendingPSK = &pendingPSKSession{
		sessionID:   combinedSessionID,
		sess:        sess,
		hsKeys:      hsKeys,
		hsSecret:    hsSecret,
		newHash:     newHash,
		pskReqBytes: request,
		pskRspBytes: pskRspBytes,
	}

	logger.Debugf(ctx, "handlePSKExchange: sessionID=0x%08X", combinedSessionID)
	return pskRspBytes, nil
}

func (r *Responder) handlePSKFinish(ctx context.Context, request []byte) ([]byte, error) {
	if r.pendingPSK == nil {
		return r.buildError(codes.ErrorUnexpectedRequest, 0), nil
	}
	p := r.pendingPSK

	hashSize := r.hashAlgo.Size()

	// PSK_FINISH = header(4) + verify_data(hashSize)
	if len(request) < msgs.HeaderSize+hashSize {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	var req msgs.PSKFinish
	if err := req.Unmarshal(request); err != nil {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}
	req.VerifyData = make([]byte, hashSize)
	copy(req.VerifyData, request[msgs.HeaderSize:msgs.HeaderSize+hashSize])

	// Verify the requester's HMAC.
	// TH for PSK_FINISH = hash(VCA || PSK_EXCHANGE_req || PSK_EXCHANGE_RSP || PSK_FINISH_header)
	finishHeaderBytes := request[:msgs.HeaderSize]

	thFinishHasher := p.newHash()
	thFinishHasher.Write(r.vcaTranscript)
	thFinishHasher.Write(p.pskReqBytes)
	thFinishHasher.Write(p.pskRspBytes)
	thFinishHasher.Write(finishHeaderBytes)
	thFinishHash := thFinishHasher.Sum(nil)

	expectedVerify := session.GenerateFinishedKey(ctx, p.newHash, p.hsKeys.RequestFinished, thFinishHash)

	if len(req.VerifyData) != len(expectedVerify) ||
		subtle.ConstantTimeCompare(req.VerifyData, expectedVerify) != 1 {
		logger.Debugf(ctx, "handlePSKFinish: verify data mismatch")
		return r.buildError(codes.ErrorDecryptError, 0), nil
	}

	// Build PSK_FINISH_RSP.
	finishResp := &msgs.PSKFinishResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(r.version),
			RequestResponseCode: uint8(codes.ResponsePSKFinishRsp),
		}},
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

	// TH2 for PSK = hash(VCA || PSK_EXCHANGE_req || PSK_EXCHANGE_RSP || PSK_FINISH_req || PSK_FINISH_RSP)
	th2Hasher := p.newHash()
	th2Hasher.Write(r.vcaTranscript)
	th2Hasher.Write(p.pskReqBytes)
	th2Hasher.Write(p.pskRspBytes)
	th2Hasher.Write(request)
	th2Hasher.Write(finishRspBytes)
	th2Hash := th2Hasher.Sum(nil)

	logger.Debugf(ctx, "handlePSKFinish: th2Hash=%x masterSecret=%x", th2Hash, masterSecret)

	dataKeys, err := session.DeriveDataKeys(ctx, p.newHash, r.version, r.aeadSuite, masterSecret, th2Hash)
	if err != nil {
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}
	p.sess.DataKeys = dataKeys
	p.sess.State = session.StateEstablished

	r.sessions[p.sessionID] = p.sess
	r.pendingPSK = nil

	logger.Debugf(ctx, "handlePSKFinish: session 0x%08X established", p.sessionID)
	return finishRspBytes, nil
}
