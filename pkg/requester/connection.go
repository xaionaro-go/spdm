package requester

import (
	"context"
	"fmt"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/caps"
	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
	"github.com/xaionaro-go/spdm/pkg/gen/status"
)

// InitConnection performs the 3-step SPDM connection per DSP0274 Section 9.1:
// GET_VERSION, GET_CAPABILITIES, NEGOTIATE_ALGORITHMS.
func (r *Requester) InitConnection(ctx context.Context) (_ret *ConnectionInfo, _err error) {
	logger.Tracef(ctx, "InitConnection")
	defer func() { logger.Tracef(ctx, "/InitConnection: result:%v; err:%v", _ret, _err) }()
	if err := r.getVersion(ctx); err != nil {
		return nil, &ErrGetVersion{Err: err}
	}
	if err := r.getCapabilities(ctx); err != nil {
		return nil, &ErrGetCapabilities{Err: err}
	}
	if err := r.negotiateAlgorithms(ctx); err != nil {
		return nil, &ErrNegotiateAlgorithms{Err: err}
	}
	return &r.conn, nil
}

// getVersion sends GET_VERSION and picks the highest common version.
func (r *Requester) getVersion(ctx context.Context) error {
	r.vcaTranscript = nil // reset on new connection
	req := &msgs.GetVersion{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x10,
			RequestResponseCode: uint8(codes.RequestGetVersion),
		}},
	}

	resp, err := r.sendReceiveVCA(ctx, req)
	if err != nil {
		return err
	}

	var vr msgs.VersionResponse
	if err := vr.Unmarshal(resp); err != nil {
		return &ErrUnmarshalResponse{Err: err}
	}

	// Per DSP0274 Section 10.3, VERSION response SPDMVersion must be 0x10.
	if vr.Header.SPDMVersion != 0x10 {
		return &ErrVersionResponseInvalid{SPDMVersion: vr.Header.SPDMVersion}
	}

	// Per DSP0274 Section 10.3, VERSION response must contain at least one entry.
	if len(vr.VersionEntries) == 0 {
		return &ErrVersionResponseEmpty{}
	}

	// Build set of our supported versions for lookup.
	supported := make(map[algo.Version]bool, len(r.cfg.Versions))
	for _, v := range r.cfg.Versions {
		supported[v] = true
	}

	// Pick the highest common version.
	var best algo.Version
	found := false
	for _, entry := range vr.VersionEntries {
		vn := algo.VersionNumber(entry)
		v := vn.Version()
		if supported[v] && v > best {
			best = v
			found = true
		}
	}
	if !found {
		return status.ErrNegotiationFail
	}

	r.conn.PeerVersion = best
	r.state = StateAfterVersion
	logger.Debugf(ctx, "negotiated version: %s", best)
	return nil
}

// getCapabilities sends GET_CAPABILITIES and stores peer capabilities.
func (r *Requester) getCapabilities(ctx context.Context) error {
	ver := uint8(r.conn.PeerVersion)

	// Per DSP0274 Section 10.4, if CHUNK_CAP is not set,
	// MaxSPDMmsgSize shall equal DataTransferSize.
	maxMsg := r.cfg.MaxSPDMmsgSize
	if !r.cfg.Caps.HasChunkCap() && maxMsg != r.cfg.DataTransferSize {
		maxMsg = r.cfg.DataTransferSize
	}

	req := &msgs.GetCapabilities{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.RequestGetCapabilities),
		}},
		CTExponent:       r.cfg.CTExponent,
		Flags:            uint32(r.cfg.Caps),
		DataTransferSize: r.cfg.DataTransferSize,
		MaxSPDMmsgSize:   maxMsg,
	}

	resp, err := r.sendReceiveVCA(ctx, req)
	if err != nil {
		return err
	}

	var cr msgs.CapabilitiesResponse
	if err := cr.Unmarshal(resp); err != nil {
		return &ErrUnmarshalResponse{Err: err}
	}

	r.conn.PeerCaps = caps.ResponderCaps(cr.Flags)

	// Per DSP0274 Section 10.4, validate peer capability flag dependencies.
	if err := caps.ValidateResponderCaps(r.conn.PeerCaps); err != nil {
		return &ErrInvalidPeerCapabilities{Err: err}
	}

	r.state = StateAfterCapabilities
	logger.Debugf(ctx, "peer capabilities: 0x%08X", uint32(r.conn.PeerCaps))
	return nil
}

// negotiateAlgorithms sends NEGOTIATE_ALGORITHMS and stores the selected algorithms.
func (r *Requester) negotiateAlgorithms(ctx context.Context) error {
	ver := uint8(r.conn.PeerVersion)
	algStructs := r.buildAlgStructs()

	req := &msgs.NegotiateAlgorithms{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.RequestNegotiateAlgorithms),
			Param1:              uint8(len(algStructs)),
		}},
		MeasurementSpecification: uint8(algo.MeasurementSpecDMTF),
		OtherParamsSupport:       0x02, // OPAQUE_DATA_FMT_1 per DSP0274 Table 21
		BaseAsymAlgo:             uint32(r.cfg.BaseAsymAlgo),
		BaseHashAlgo:             uint32(r.cfg.BaseHashAlgo),
		AlgStructs:               algStructs,
	}

	resp, err := r.sendReceiveVCA(ctx, req)
	if err != nil {
		return err
	}

	var ar msgs.AlgorithmsResponse
	if err := ar.Unmarshal(resp); err != nil {
		return &ErrUnmarshalResponse{Err: err}
	}

	if err := r.validateAlgorithmsResponse(&ar); err != nil {
		return err
	}

	r.conn.MeasHashAlgo = algo.MeasurementHashAlgo(ar.MeasurementHashAlgo)

	// Extract DHE and AEAD selections from algorithm structure table.
	for _, a := range ar.AlgStructs {
		switch a.AlgType {
		case msgs.AlgTypeDHE:
			r.conn.DHEGroup = algo.DHENamedGroup(a.AlgSupported)
		case msgs.AlgTypeAEAD:
			r.conn.AEADSuite = algo.AEADCipherSuite(a.AlgSupported)
		}
	}

	r.state = StateAfterAlgorithms
	logger.Debugf(ctx, "negotiated algorithms: hash=0x%08X asym=0x%08X DHE=0x%04X AEAD=0x%04X",
		uint32(r.conn.HashAlgo), uint32(r.conn.AsymAlgo), uint16(r.conn.DHEGroup), uint16(r.conn.AEADSuite))
	return nil
}

// buildAlgStructs builds the algorithm structure table entries for
// DHE, AEAD, ReqBaseAsym, and KeySchedule per DSP0274 Section 10.5.
func (r *Requester) buildAlgStructs() []msgs.AlgStructTable {
	var algStructs []msgs.AlgStructTable

	if r.cfg.DHEGroups != 0 {
		algStructs = append(algStructs, msgs.AlgStructTable{
			AlgType:      msgs.AlgTypeDHE,
			AlgCount:     0x20, // fixed_alg_byte_count=2, ext_alg_count=0
			AlgSupported: uint16(r.cfg.DHEGroups),
		})
	}

	if r.cfg.AEADSuites != 0 {
		algStructs = append(algStructs, msgs.AlgStructTable{
			AlgType:      msgs.AlgTypeAEAD,
			AlgCount:     0x20,
			AlgSupported: uint16(r.cfg.AEADSuites),
		})
	}

	// Per DSP0274 Section 10.5, MUT_AUTH_CAP requires ReqBaseAsym struct.
	if r.cfg.Caps.HasMutAuthCap() && r.cfg.BaseAsymAlgo != 0 {
		algStructs = append(algStructs, msgs.AlgStructTable{
			AlgType:      msgs.AlgTypeReqBaseAsym,
			AlgCount:     0x20,
			AlgSupported: uint16(r.cfg.BaseAsymAlgo),
		})
	}

	// Per DSP0274 Section 10.5, KEY_EX_CAP requires KeySchedule struct.
	if r.cfg.Caps.HasKeyExCap() {
		algStructs = append(algStructs, msgs.AlgStructTable{
			AlgType:      msgs.AlgTypeKeySchedule,
			AlgCount:     0x20,
			AlgSupported: uint16(algo.KeyScheduleSPDM),
		})
	}

	return algStructs
}

// validateAlgorithmsResponse validates the ALGORITHMS response per DSP0274 Section 10.5:
// single-bit checks on selection fields, subset checks against requested values.
// On success it stores the validated HashAlgo and AsymAlgo into r.conn.
func (r *Requester) validateAlgorithmsResponse(ar *msgs.AlgorithmsResponse) error {
	sel := algo.BaseHashAlgo(ar.BaseHashSel)
	if sel == 0 {
		return &ErrAlgorithmsNegotiationFail{
			Reason: "ALGORITHMS response has zero BaseHashSel",
			Err:    status.ErrNegotiationFail,
		}
	}

	// Per DSP0274 Section 10.5, each selection field must have exactly one bit set.
	if !isSingleBit(ar.BaseHashSel) {
		return &ErrAlgorithmsNegotiationFail{
			Reason: fmt.Sprintf("ALGORITHMS response BaseHashSel has multiple bits: 0x%08X", ar.BaseHashSel),
			Err:    status.ErrInvalidMsgField,
		}
	}
	if !isSingleBit(ar.BaseAsymSel) && ar.BaseAsymSel != 0 {
		return &ErrAlgorithmsNegotiationFail{
			Reason: fmt.Sprintf("ALGORITHMS response BaseAsymSel has multiple bits: 0x%08X", ar.BaseAsymSel),
			Err:    status.ErrInvalidMsgField,
		}
	}

	// Per DSP0274 Section 10.5, selected algorithms must be a subset of what was requested.
	if ar.BaseHashSel&uint32(r.cfg.BaseHashAlgo) != ar.BaseHashSel {
		return &ErrAlgorithmsNegotiationFail{
			Reason: fmt.Sprintf("ALGORITHMS BaseHashSel 0x%08X not subset of requested 0x%08X", ar.BaseHashSel, uint32(r.cfg.BaseHashAlgo)),
			Err:    status.ErrInvalidMsgField,
		}
	}
	if ar.BaseAsymSel != 0 && ar.BaseAsymSel&uint32(r.cfg.BaseAsymAlgo) != ar.BaseAsymSel {
		return &ErrAlgorithmsNegotiationFail{
			Reason: fmt.Sprintf("ALGORITHMS BaseAsymSel 0x%08X not subset of requested 0x%08X", ar.BaseAsymSel, uint32(r.cfg.BaseAsymAlgo)),
			Err:    status.ErrInvalidMsgField,
		}
	}

	r.conn.HashAlgo = sel
	r.conn.AsymAlgo = algo.BaseAsymAlgo(ar.BaseAsymSel)
	return nil
}

// isSingleBit returns true if exactly one bit is set in v.
func isSingleBit(v uint32) bool {
	return v != 0 && v&(v-1) == 0
}
