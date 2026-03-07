package requester

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

// PSKExchange performs the PSK_EXCHANGE handshake per DSP0274 Section 10.14
// and establishes a session using a pre-shared key identified by pskHint.
func (r *Requester) PSKExchange(ctx context.Context, pskHint []byte) (_ret *session.Session, _err error) {
	logger.Tracef(ctx, "PSKExchange: hint=%x", pskHint)
	defer func() { logger.Tracef(ctx, "/PSKExchange: session:%v; err:%v", _ret, _err) }()

	if r.cfg.PSKProvider == nil {
		return nil, &ErrPSKNotConfigured{}
	}

	psk, err := r.cfg.PSKProvider.Lookup(ctx, pskHint)
	if err != nil {
		return nil, &ErrPSKLookup{Err: err}
	}

	ver := uint8(r.conn.PeerVersion)
	newHash := func() hash.Hash { return r.conn.HashAlgo.CryptoHash().New() }
	hashSize := r.conn.HashAlgo.Size()

	// Generate random context (hash size bytes) and random requester session ID.
	reqContext := make([]byte, hashSize)
	if _, err := rand.Read(reqContext); err != nil {
		return nil, &ErrGenerateContext{Err: err}
	}

	var reqSessionIDBuf [2]byte
	if _, err := rand.Read(reqSessionIDBuf[:]); err != nil {
		return nil, &ErrGenerateSessionID{Err: err}
	}
	reqSessionID := binary.LittleEndian.Uint16(reqSessionIDBuf[:])

	// Build opaque data per DSP0277 Section 6.2.
	opaqueData := buildKeyExchangeOpaqueData()

	pskReq := &msgs.PSKExchange{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.RequestPSKExchange),
			Param1:              msgs.NoMeasurementSummaryHash,
			Param2:              0, // reserved
		}},
		ReqSessionID: reqSessionID,
		PSKHint:      pskHint,
		Context:      reqContext,
		OpaqueData:   opaqueData,
	}

	reqBytes, err := pskReq.Marshal()
	if err != nil {
		return nil, &ErrMarshalPSKExchange{Err: err}
	}

	resp, err := r.sendReceive(ctx, pskReq)
	if err != nil {
		return nil, err
	}

	// Parse PSK_EXCHANGE_RSP using UnmarshalWithSizes.
	measHashSize := 0
	if pskReq.Header.Param1 != msgs.NoMeasurementSummaryHash {
		measHashSize = hashSize
	}

	var pskResp msgs.PSKExchangeResponse
	if err := pskResp.UnmarshalWithSizes(resp, measHashSize, hashSize); err != nil {
		return nil, &ErrUnmarshalPSKExchangeResponse{Err: err}
	}

	// Compute the offset past all fields before VerifyData for TH1 computation.
	off := msgs.HeaderSize + 8 + measHashSize + int(pskResp.ContextLen) + int(pskResp.OpaqueLen)

	// Derive handshake secret from PSK (same derivation as DHE but with PSK as shared secret).
	hsSecret, err := session.DeriveHandshakeSecret(ctx, newHash, r.conn.PeerVersion, psk)
	if err != nil {
		return nil, &ErrDeriveHandshakeSecret{Err: err}
	}

	// Compute TH1 for PSK: hash(VCA || PSK_EXCHANGE_req || PSK_EXCHANGE_RSP_without_verify_data)
	// No cert chain hash in PSK TH.
	respForTH1 := resp[:off]
	th1Hasher := newHash()
	th1Hasher.Write(r.vcaTranscript)
	th1Hasher.Write(reqBytes)
	th1Hasher.Write(respForTH1)
	th1Hash := th1Hasher.Sum(nil)

	// Derive handshake keys.
	hsKeys, err := session.DeriveHandshakeKeys(ctx, newHash, r.conn.PeerVersion, r.conn.AEADSuite, hsSecret, th1Hash)
	if err != nil {
		return nil, &ErrDeriveHandshakeKeys{Err: err}
	}

	// Verify responder's HMAC verify data using ResponseFinished key.
	expectedVerify := session.GenerateFinishedKey(ctx, newHash, hsKeys.ResponseFinished, th1Hash)
	if len(pskResp.VerifyData) != len(expectedVerify) ||
		subtle.ConstantTimeCompare(pskResp.VerifyData, expectedVerify) != 1 {
		return nil, &ErrPSKVerifyDataMismatch{}
	}

	// Build session ID: upper 16 bits = rsp, lower 16 bits = req.
	combinedSessionID := session.SessionID(uint32(pskResp.RspSessionID)<<16 | uint32(reqSessionID))

	sess := session.NewSession(
		combinedSessionID,
		r.conn.PeerVersion,
		r.conn.HashAlgo,
		r.conn.AEADSuite,
		true,
	)
	sess.HandshakeKeys = hsKeys
	sess.HandshakeSecret = hsSecret

	if err := r.sendPSKFinish(ctx, sess, newHash, reqBytes, resp); err != nil {
		return nil, err
	}

	r.sessions[combinedSessionID] = sess
	logger.Debugf(ctx, "PSKExchange: session 0x%08X established", combinedSessionID)
	return sess, nil
}

// sendPSKFinish builds and sends PSK_FINISH, then derives master secret
// and data keys to finalize the session.
func (r *Requester) sendPSKFinish(
	ctx context.Context,
	sess *session.Session,
	newHash func() hash.Hash,
	reqBytes []byte,
	resp []byte,
) error {
	ver := uint8(r.conn.PeerVersion)

	// Build PSK_FINISH with requester verify data.
	pskFinishHeader := msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
		SPDMVersion:         ver,
		RequestResponseCode: uint8(codes.RequestPSKFinish),
		Param1:              0,
		Param2:              0,
	}}
	finishHeaderBytes, _ := pskFinishHeader.Marshal()

	// TH for PSK_FINISH = hash(VCA || PSK_EXCHANGE_req || PSK_EXCHANGE_RSP || PSK_FINISH_header)
	thFinishHasher := newHash()
	thFinishHasher.Write(r.vcaTranscript)
	thFinishHasher.Write(reqBytes)
	thFinishHasher.Write(resp)
	thFinishHasher.Write(finishHeaderBytes)
	thFinishHash := thFinishHasher.Sum(nil)

	verifyData := session.GenerateFinishedKey(ctx, newHash, sess.HandshakeKeys.RequestFinished, thFinishHash)

	pskFinish := &msgs.PSKFinish{
		Header:     pskFinishHeader,
		VerifyData: verifyData,
	}

	finishResp, err := r.sendReceive(ctx, pskFinish)
	if err != nil {
		return &ErrPSKFinish{Err: err}
	}

	var fr msgs.PSKFinishResponse
	if err := fr.Unmarshal(finishResp); err != nil {
		return &ErrUnmarshalPSKFinishResponse{Err: err}
	}

	// Derive master secret and data keys.
	masterSecret, err := session.DeriveMasterSecret(ctx, newHash, r.conn.PeerVersion, sess.HandshakeSecret)
	if err != nil {
		return &ErrDeriveMasterSecret{Err: err}
	}
	sess.MasterSecret = masterSecret

	// TH2 for PSK = hash(VCA || PSK_EXCHANGE_req || PSK_EXCHANGE_RSP || PSK_FINISH_req || PSK_FINISH_RSP)
	pskFinishBytes, _ := pskFinish.Marshal()
	th2Hasher := newHash()
	th2Hasher.Write(r.vcaTranscript)
	th2Hasher.Write(reqBytes)
	th2Hasher.Write(resp)
	th2Hasher.Write(pskFinishBytes)
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
