package responder

import (
	"context"
	"crypto"
	"encoding/asn1"
	"math/big"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

func (r *Responder) handleChallenge(ctx context.Context, request []byte) ([]byte, error) {
	if !r.negotiated {
		return r.buildError(codes.ErrorUnexpectedRequest, 0), nil
	}

	var req msgs.Challenge
	if err := req.Unmarshal(request); err != nil {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	slotID := req.SlotID()

	// Build cert chain hash.
	var certChainHash []byte
	if r.cfg.CertProvider != nil {
		d, err := r.cfg.CertProvider.DigestForSlot(ctx, slotID)
		if err == nil {
			certChainHash = d
		}
	}
	if certChainHash == nil {
		certChainHash = make([]byte, r.hashAlgo.Size())
	}

	// Generate responder nonce.
	nonce, err := r.randomBytes(msgs.NonceSize)
	if err != nil {
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}

	// Measurement summary hash per DSP0274 Section 10.8.
	var measHash []byte
	hashType := req.HashType()
	if hashType != msgs.NoMeasurementSummaryHash {
		if r.cfg.MeasProvider != nil {
			var err error
			measHash, err = r.cfg.MeasProvider.SummaryHash(ctx, hashType)
			if err != nil {
				return r.buildError(codes.ErrorUnspecified, 0), nil
			}
		} else {
			measHash = make([]byte, r.hashAlgo.Size())
		}
	}

	resp := &msgs.ChallengeAuthResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(r.version),
			RequestResponseCode: uint8(codes.ResponseChallengeAuth),
			Param1:              slotID & 0x0F,
			Param2:              1 << slotID, // slot_mask
		}},
		CertChainHash:          certChainHash,
		MeasurementSummaryHash: measHash,
	}
	copy(resp.Nonce[:], nonce)

	logger.Debugf(ctx, "handleChallenge: slot=%d hashType=%d", slotID, hashType)

	// Sign the response per DSP0274 Section 15.
	if r.cfg.DeviceSigner != nil {
		// Marshal response without signature to build M1.
		resp.Signature = nil
		respNoSig, err := resp.Marshal()
		if err != nil {
			return r.buildError(codes.ErrorUnspecified, 0), nil
		}

		// Build C = CHALLENGE + CHALLENGE_AUTH(without sig).
		// Note: For SPDM 1.2, libspdm's message_c contains only C (the challenge pair).
		// The VCA (message A) and B (digest/cert) are managed separately by the libspdm
		// context via append_message_a/b/c calls. The signature verification function
		// internally concatenates A + B + C.
		// Our r.transcript has A+B. We add C here.
		var m1 []byte
		m1 = append(m1, r.transcript...)
		m1 = append(m1, request...)   // CHALLENGE request
		m1 = append(m1, respNoSig...) // CHALLENGE_AUTH without signature

		// Build signing data per DSP0274 Section 15 / libspdm format:
		// [0:64]  = 4 × "dmtf-spdm-v1.2.*" (16 bytes each)
		// [64:68] = 4 zero bytes (padding to align context string)
		// [68:100] = "responder-challenge_auth signing" (32 bytes)
		// [100:100+H] = hash(M1)
		var prefix [msgs.SigningContextSize]byte
		versionStr := msgs.SigningPrefixContext12
		for i := 0; i < 4; i++ {
			copy(prefix[i*len(versionStr):], versionStr)
		}
		// Context string goes at offset 64 with zero padding before it.
		contextStr := []byte(msgs.ChallengeAuthSignContext)
		zeroPad := msgs.SigningContextSize - 4*len(versionStr) - len(contextStr)
		copy(prefix[4*len(versionStr)+zeroPad:], contextStr)

		h := r.hashAlgo.CryptoHash()
		hasher := h.New()
		hasher.Write(m1)
		m1Hash := hasher.Sum(nil)

		var signData []byte
		signData = append(signData, prefix[:]...)
		signData = append(signData, m1Hash...)

		// Hash the signing data to produce the digest for ECDSA/RSA signing.
		digest := h.New()
		digest.Write(signData)

		derSig, err := r.cfg.DeviceSigner.Sign(nil, digest.Sum(nil), crypto.SignerOpts(h))
		if err != nil {
			return r.buildError(codes.ErrorUnspecified, 0), nil
		}

		// Convert signature to SPDM format (raw r||s for ECDSA, raw for RSA).
		resp.Signature, err = toSPDMSignature(r.asymAlgo, derSig)
		if err != nil {
			return r.buildError(codes.ErrorUnspecified, 0), nil
		}
	} else {
		// No signer: empty signature.
		resp.Signature = make([]byte, r.asymAlgo.SignatureSize())
	}

	return resp.Marshal()
}

// toSPDMSignature converts a Go crypto signature to SPDM wire format.
// For ECDSA, this converts DER-encoded ASN.1 to raw r||s concatenation.
// For RSA, the signature is already in the correct format.
func toSPDMSignature(asymAlgo algo.BaseAsymAlgo, sig []byte) ([]byte, error) {
	switch asymAlgo {
	case algo.AsymECDSAP256, algo.AsymECDSAP384, algo.AsymECDSAP521, algo.AsymSM2P256:
		return ecdsaDERToRaw(sig, asymAlgo.SignatureSize())
	default:
		// RSA/EdDSA signatures are already in the correct format.
		return sig, nil
	}
}

// ecdsaDERToRaw converts a DER-encoded ECDSA signature to raw r||s format.
func ecdsaDERToRaw(derSig []byte, totalSize int) ([]byte, error) {
	// Try ASN.1 parsing first.
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(derSig, &parsed); err != nil {
		// May already be in raw format if the signer returned raw.
		if len(derSig) == totalSize {
			return derSig, nil
		}
		return nil, err
	}
	return ecdsaRawSignature(parsed.R, parsed.S, totalSize), nil
}

// ecdsaRawSignature encodes r, s as fixed-size big-endian r||s.
func ecdsaRawSignature(r, s *big.Int, totalSize int) []byte {
	componentLen := totalSize / 2
	raw := make([]byte, totalSize)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(raw[componentLen-len(rBytes):componentLen], rBytes)
	copy(raw[totalSize-len(sBytes):totalSize], sBytes)
	return raw
}
