package responder

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

func (r *Responder) handleGetVersion(ctx context.Context, request []byte) ([]byte, error) {
	if len(r.cfg.Versions) == 0 {
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}

	// GET_VERSION resets the connection state per DSP0274 Section 10.3.
	r.version = 0
	r.negotiated = false
	r.peerCaps = 0
	r.prevCaps = nil
	r.state = StateAfterVersion
	r.transcript = nil
	r.vcaTranscript = nil
	r.measTranscript = nil

	entries := make([]uint16, len(r.cfg.Versions))
	for i, v := range r.cfg.Versions {
		// Convert Version (major<<4|minor) to VersionNumber (major<<12|minor<<8).
		entries[i] = uint16(v.Major())<<12 | uint16(v.Minor())<<8
	}

	resp := &msgs.VersionResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x10,
			RequestResponseCode: uint8(codes.ResponseVersion),
		}},
		VersionNumberEntryCount: uint8(len(entries)),
		VersionEntries:          entries,
	}
	data, err := resp.Marshal()
	if err != nil {
		return nil, err
	}
	// Record VCA transcript: GET_VERSION request + VERSION response.
	r.transcript = append(r.transcript, request...)
	r.transcript = append(r.transcript, data...)
	logger.Debugf(ctx, "handleGetVersion: offered %d versions", len(entries))
	return data, nil
}
