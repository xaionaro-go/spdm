package responder

import (
	"context"
	"crypto"
	"encoding/binary"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

// collectMeasurementBlocks returns the measurement blocks for the given
// operation code along with the total count of all available blocks.
// It returns a non-nil error response (as bytes) when the caller should
// short-circuit with an SPDM error.
func (r *Responder) collectMeasurementBlocks(
	ctx context.Context,
	measOp uint8,
) (blocks []msgs.MeasurementBlock, totalCount uint8, errResp []byte) {
	allBlocks, err := r.cfg.MeasProvider.Collect(ctx, msgs.MeasOpAllMeasurements)
	if err != nil {
		return nil, 0, r.buildError(codes.ErrorUnspecified, 0)
	}
	totalCount = uint8(len(allBlocks))

	switch measOp {
	case msgs.MeasOpTotalCount:
		// No blocks in the record; just return the count via Param1.
	case msgs.MeasOpAllMeasurements:
		blocks = allBlocks
	default:
		blocks, err = r.cfg.MeasProvider.Collect(ctx, measOp)
		if err != nil {
			return nil, 0, r.buildError(codes.ErrorUnspecified, 0)
		}
		if len(blocks) == 0 {
			// Per DSP0274 Section 10.11: unavailable index returns ERROR.
			// Reset measurement transcript on error per libspdm behavior.
			r.measTranscript = nil
			return nil, 0, r.buildError(codes.ErrorInvalidRequest, 0)
		}
	}

	return blocks, totalCount, nil
}

// signMeasurementResponse computes the SPDM 1.2 signature over the
// accumulated measurement transcript (L1 = VCA + message_m) and resets
// the transcript. It returns the SPDM-formatted signature bytes.
func (r *Responder) signMeasurementResponse() ([]byte, error) {
	// L1 = VCA + accumulated message_m (all measurement exchanges).
	var l1 []byte
	l1 = append(l1, r.vcaTranscript...)
	l1 = append(l1, r.measTranscript...)

	// Build signing prefix per DSP0274 Section 15.
	var prefix [msgs.SigningContextSize]byte
	versionStr := msgs.SigningPrefixContext12
	for i := 0; i < 4; i++ {
		copy(prefix[i*len(versionStr):], versionStr)
	}
	contextStr := []byte(msgs.MeasurementsSignContext)
	zeroPad := msgs.SigningContextSize - 4*len(versionStr) - len(contextStr)
	copy(prefix[4*len(versionStr)+zeroPad:], contextStr)

	h := r.hashAlgo.CryptoHash()
	hasher := h.New()
	hasher.Write(l1)
	l1Hash := hasher.Sum(nil)

	var signData []byte
	signData = append(signData, prefix[:]...)
	signData = append(signData, l1Hash...)

	digest := h.New()
	digest.Write(signData)

	derSig, err := r.cfg.DeviceSigner.Sign(nil, digest.Sum(nil), crypto.SignerOpts(h))
	if err != nil {
		return nil, err
	}

	sig, err := toSPDMSignature(r.asymAlgo, derSig)
	if err != nil {
		return nil, err
	}

	// Reset measurement transcript after signed response per DSP0274.
	r.measTranscript = nil
	return sig, nil
}

func (r *Responder) handleGetMeasurements(ctx context.Context, request []byte) ([]byte, error) {
	if !r.negotiated {
		return r.buildError(codes.ErrorUnexpectedRequest, 0), nil
	}
	if r.cfg.MeasProvider == nil {
		return r.buildError(codes.ErrorUnsupportedRequest, 0), nil
	}

	var req msgs.GetMeasurements
	if err := req.Unmarshal(request); err != nil {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	measOp := req.Header.Param2
	sigRequested := req.Header.Param1&msgs.MeasAttrGenerateSignature != 0

	blocks, totalCount, errResp := r.collectMeasurementBlocks(ctx, measOp)
	if errResp != nil {
		return errResp, nil
	}

	// Serialize measurement blocks into the record.
	var record []byte
	for _, b := range blocks {
		valueSize := len(b.Value)
		measSize := 3 + valueSize
		entry := make([]byte, 4+measSize)
		entry[0] = b.Index
		entry[1] = b.Spec
		binary.LittleEndian.PutUint16(entry[2:], uint16(measSize))
		entry[4] = b.ValueType
		binary.LittleEndian.PutUint16(entry[5:], uint16(valueSize))
		copy(entry[7:], b.Value)
		record = append(record, entry...)
	}

	// Per DSP0274 Table 45: Nonce is always present in SPDM 1.2.
	nonce, nonceErr := r.randomBytes(msgs.NonceSize)
	if nonceErr != nil {
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}

	resp := &msgs.MeasurementsResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(r.version),
			RequestResponseCode: uint8(codes.ResponseMeasurements),
			Param1:              totalCount,
		}},
		NumberOfBlocks:       uint8(len(blocks)),
		MeasurementRecordLen: uint32(len(record)),
		MeasurementRecord:    record,
	}
	copy(resp.Nonce[:], nonce)

	// Build response without signature for transcript accumulation.
	respNoSig, marshalErr := resp.Marshal()
	if marshalErr != nil {
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}

	// Accumulate message_m: all GET_MEASUREMENTS request/response pairs.
	// Per DSP0274 Section 15, L1 = VCA + message_m where message_m is cumulative.
	r.measTranscript = append(r.measTranscript, request...)
	r.measTranscript = append(r.measTranscript, respNoSig...)

	if sigRequested && r.cfg.DeviceSigner != nil {
		sig, err := r.signMeasurementResponse()
		if err != nil {
			return r.buildError(codes.ErrorUnspecified, 0), nil
		}
		resp.Signature = sig
	}

	logger.Debugf(ctx, "handleGetMeasurements: index=%d blocks=%d totalCount=%d sig=%v recordLen=%d",
		measOp, len(blocks), totalCount, sigRequested, len(record))
	return resp.Marshal()
}
