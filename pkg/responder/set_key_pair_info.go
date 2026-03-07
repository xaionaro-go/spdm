package responder

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

// handleSetKeyPairInfo handles SET_KEY_PAIR_INFO per DSP0274 Section 10.25.
func (r *Responder) handleSetKeyPairInfo(
	ctx context.Context,
	request []byte,
) (_ret []byte, _err error) {
	logger.Tracef(ctx, "handleSetKeyPairInfo")
	defer func() { logger.Tracef(ctx, "/handleSetKeyPairInfo: %v", _err) }()

	if !r.negotiated {
		return r.buildError(codes.ErrorUnexpectedRequest, 0), nil
	}

	if r.cfg.ProvisioningProvider == nil {
		return r.buildError(codes.ErrorUnsupportedRequest, 0), nil
	}

	var req msgs.SetKeyPairInfo
	if err := req.Unmarshal(request); err != nil {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	if err := r.cfg.ProvisioningProvider.SetKeyPairInfo(
		ctx,
		req.KeyPairID,
		req.Operation,
		req.DesiredKeyUsage,
		req.DesiredAsymAlgo,
		req.PublicKeyInfo,
	); err != nil {
		logger.Debugf(ctx, "handleSetKeyPairInfo: provider error: %v", err)
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}

	resp := &msgs.SetKeyPairInfoAck{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(r.version),
			RequestResponseCode: uint8(codes.ResponseSetKeyPairInfoAck),
		}},
	}

	logger.Debugf(ctx, "handleSetKeyPairInfo: keyPairID=%d operation=%d", req.KeyPairID, req.Operation)
	return resp.Marshal()
}
