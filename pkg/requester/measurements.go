package requester

import (
	"context"
	"crypto/rand"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

// GetMeasurements per DSP0274 Section 10.11 sends GET_MEASUREMENTS and returns the response.
// When requestSignature is true, verifies the responder's signature over the accumulated
// measurement transcript per DSP0274 Section 15.
func (r *Requester) GetMeasurements(ctx context.Context, index uint8, requestSignature bool) (_ret *msgs.MeasurementsResponse, _err error) {
	logger.Tracef(ctx, "GetMeasurements: index=%d requestSignature=%v", index, requestSignature)
	defer func() { logger.Tracef(ctx, "/GetMeasurements: result:%v; err:%v", _ret, _err) }()
	ver := uint8(r.conn.PeerVersion)

	var attrs uint8
	if requestSignature {
		attrs |= msgs.MeasAttrGenerateSignature
	}

	req := &msgs.GetMeasurements{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.RequestGetMeasurements),
			Param1:              attrs,
			Param2:              index,
		}},
	}

	if requestSignature {
		if _, err := rand.Read(req.Nonce[:]); err != nil {
			return nil, &ErrGenerateNonce{Err: err}
		}
	}

	reqBytes, err := req.Marshal()
	if err != nil {
		return nil, &ErrMarshalRequest{Err: err}
	}

	resp, err := r.sendReceive(ctx, req)
	if err != nil {
		return nil, err
	}

	var mr msgs.MeasurementsResponse
	if err := mr.Unmarshal(resp); err != nil {
		return nil, &ErrUnmarshalResponse{Err: err}
	}

	// Build response-without-signature for transcript accumulation.
	// The responder marshals respNoSig without signature, then appends to measTranscript.
	// We need to match: strip the signature from the raw response bytes.
	respNoSig := resp
	if requestSignature {
		sigSize := r.conn.AsymAlgo.SignatureSize()
		if sigSize > 0 && len(resp) > sigSize {
			mr.Signature = make([]byte, sigSize)
			copy(mr.Signature, resp[len(resp)-sigSize:])
			respNoSig = resp[:len(resp)-sigSize]
		}
	}

	// Accumulate measurement transcript: GET_MEASUREMENTS request + response (without sig).
	r.measTranscript = append(r.measTranscript, reqBytes...)
	r.measTranscript = append(r.measTranscript, respNoSig...)

	// Verify signature when requested, a verifier is configured, and a cert chain is available.
	if requestSignature && r.cfg.Crypto.Verifier != nil && len(r.peerCertChain) > 0 {
		if err := r.verifyMeasurementsSignature(ctx, &mr); err != nil {
			// Reset measurement transcript on verification failure.
			r.measTranscript = nil
			return nil, &ErrSignatureVerification{Err: err}
		}

		// Reset measurement transcript after verified signed response per DSP0274.
		r.measTranscript = nil
	}

	return &mr, nil
}

// verifyMeasurementsSignature verifies the MEASUREMENTS signature per DSP0274 Section 15.
// L1 = VCA + accumulated message_m (all measurement exchanges).
func (r *Requester) verifyMeasurementsSignature(
	ctx context.Context,
	mr *msgs.MeasurementsResponse,
) error {
	pubKey, err := r.extractPeerPublicKey()
	if err != nil {
		return &ErrExtractPeerPublicKey{Err: err}
	}

	// L1 = VCA + accumulated message_m.
	var l1 []byte
	l1 = append(l1, r.vcaTranscript...)
	l1 = append(l1, r.measTranscript...)

	// Build signing data per DSP0274 Section 15.
	signData := buildSigningData(r.conn.HashAlgo.CryptoHash(), l1, msgs.MeasurementsSignContext)

	// Hash the signing data to produce the digest for verification.
	h := r.conn.HashAlgo.CryptoHash()
	digest := h.New()
	digest.Write(signData)

	if err := r.cfg.Crypto.Verifier.Verify(r.conn.AsymAlgo, pubKey, digest.Sum(nil), mr.Signature); err != nil {
		return &ErrVerify{Err: err}
	}

	logger.Debugf(ctx, "Measurements signature verified successfully")
	return nil
}
