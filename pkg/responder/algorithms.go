package responder

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

const (
	// algCountFixed2Bytes encodes fixed_alg_byte_count=2, ext_alg_count=0
	// in the AlgCount field per DSP0274 Table 22.
	algCountFixed2Bytes = 0x20
	// opaqueDataFmt1 selects OPAQUE_DATA_FMT_1 per DSP0274 Table 21.
	opaqueDataFmt1 = 0x02
)

func (r *Responder) handleNegotiateAlgorithms(ctx context.Context, request []byte) ([]byte, error) {
	var req msgs.NegotiateAlgorithms
	if err := req.Unmarshal(request); err != nil {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	// Select base algorithms from the intersection.
	hashSel := selectAlgorithm(uint32(r.cfg.BaseHashAlgo), req.BaseHashAlgo)
	asymSel := selectAlgorithm(uint32(r.cfg.BaseAsymAlgo), req.BaseAsymAlgo)

	if hashSel == 0 || asymSel == 0 {
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}

	r.hashAlgo = algo.BaseHashAlgo(hashSel)
	r.asymAlgo = algo.BaseAsymAlgo(asymSel)

	// Process algorithm structure entries for DHE, AEAD, etc.
	var respAlgStructs []msgs.AlgStructTable
	for _, a := range req.AlgStructs {
		switch a.AlgType {
		case msgs.AlgTypeDHE:
			sel := selectAlgorithm16(uint16(r.cfg.DHEGroups), a.AlgSupported)
			r.dheGroup = algo.DHENamedGroup(sel)
			respAlgStructs = append(respAlgStructs, msgs.AlgStructTable{
				AlgType:      msgs.AlgTypeDHE,
				AlgCount:     algCountFixed2Bytes, // fixed_alg_byte_count=2, ext_count=0
				AlgSupported: sel,
			})
		case msgs.AlgTypeAEAD:
			sel := selectAlgorithm16(uint16(r.cfg.AEADSuites), a.AlgSupported)
			r.aeadSuite = algo.AEADCipherSuite(sel)
			respAlgStructs = append(respAlgStructs, msgs.AlgStructTable{
				AlgType:      msgs.AlgTypeAEAD,
				AlgCount:     algCountFixed2Bytes,
				AlgSupported: sel,
			})
		case msgs.AlgTypeReqBaseAsym:
			// REQ_BASE_ASYM_ALG for mutual authentication; echo the intersection.
			sel := selectAlgorithm16(uint16(r.cfg.BaseAsymAlgo), a.AlgSupported)
			respAlgStructs = append(respAlgStructs, msgs.AlgStructTable{
				AlgType:      msgs.AlgTypeReqBaseAsym,
				AlgCount:     algCountFixed2Bytes,
				AlgSupported: sel,
			})
		case msgs.AlgTypeKeySchedule:
			sel := selectAlgorithm16(uint16(algo.KeyScheduleSPDM), a.AlgSupported)
			respAlgStructs = append(respAlgStructs, msgs.AlgStructTable{
				AlgType:      msgs.AlgTypeKeySchedule,
				AlgCount:     algCountFixed2Bytes,
				AlgSupported: sel,
			})
		default:
			// Echo back with zero selection for unsupported types.
			respAlgStructs = append(respAlgStructs, msgs.AlgStructTable{
				AlgType:      a.AlgType,
				AlgCount:     algCountFixed2Bytes,
				AlgSupported: 0,
			})
		}
	}

	r.negotiated = true
	r.state = StateNegotiated

	// Map base hash algorithm to measurement hash algorithm bitmask.
	// BaseHashAlgo and MeasurementHashAlgo use different bit positions per DSP0274.
	measHashAlgo := baseHashToMeasHash(algo.BaseHashAlgo(hashSel))

	// OtherParamsSelection: select OPAQUE_DATA_FMT_1 if the requester supports it.
	var otherParamsSel uint8
	if req.OtherParamsSupport&opaqueDataFmt1 != 0 {
		otherParamsSel = opaqueDataFmt1
	}

	// If responder doesn't support measurements, set measHashAlgo to 0.
	if !r.cfg.Caps.HasMeasCap() {
		measHashAlgo = 0
	}

	resp := &msgs.AlgorithmsResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(r.version),
			RequestResponseCode: uint8(codes.ResponseAlgorithms),
			Param1:              uint8(len(respAlgStructs)),
		}},
		MeasurementSpecificationSel: req.MeasurementSpecification,
		OtherParamsSelection:        otherParamsSel,
		MeasurementHashAlgo:         measHashAlgo,
		BaseAsymSel:                 asymSel,
		BaseHashSel:                 hashSel,
		AlgStructs:                  respAlgStructs,
	}
	data, err := resp.Marshal()
	if err != nil {
		return nil, err
	}
	// Record VCA transcript: NEGOTIATE_ALGORITHMS request + ALGORITHMS response.
	r.transcript = append(r.transcript, request...)
	r.transcript = append(r.transcript, data...)
	// Snapshot VCA (message A) for KEY_EXCHANGE TH computation.
	r.vcaTranscript = make([]byte, len(r.transcript))
	copy(r.vcaTranscript, r.transcript)
	logger.Debugf(ctx, "handleNegotiateAlgorithms: hash=0x%08X asym=0x%08X DHE=0x%04X AEAD=0x%04X measHash=0x%08X",
		hashSel, asymSel, uint16(r.dheGroup), uint16(r.aeadSuite), measHashAlgo)
	return data, nil
}

// baseHashToMeasHash maps a BaseHashAlgo selection to the corresponding
// MeasurementHashAlgo bitmask per DSP0274 Tables 21 and 23.
func baseHashToMeasHash(h algo.BaseHashAlgo) uint32 {
	switch h {
	case algo.HashSHA256:
		return uint32(algo.MeasHashSHA256)
	case algo.HashSHA384:
		return uint32(algo.MeasHashSHA384)
	case algo.HashSHA512:
		return uint32(algo.MeasHashSHA512)
	case algo.HashSHA3_256:
		return uint32(algo.MeasHashSHA3_256)
	case algo.HashSHA3_384:
		return uint32(algo.MeasHashSHA3_384)
	case algo.HashSHA3_512:
		return uint32(algo.MeasHashSHA3_512)
	case algo.HashSM3_256:
		return uint32(algo.MeasHashSM3_256)
	default:
		return uint32(algo.MeasHashRawBitStream)
	}
}
