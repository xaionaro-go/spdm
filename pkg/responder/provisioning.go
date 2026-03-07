package responder

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

// ProvisioningProvider handles certificate provisioning and key pair queries
// per DSP0274 Section 10.23 and 10.25.
type ProvisioningProvider interface {
	SetCertificate(ctx context.Context, slotID uint8, certChain []byte) error
	GetKeyPairInfo(ctx context.Context, keyPairID uint8) (*msgs.KeyPairInfoResponse, error)
	SetKeyPairInfo(ctx context.Context, keyPairID uint8, operation uint8, desiredKeyUsage uint16, desiredAsymAlgo uint32, publicKeyInfo []byte) error
}

func (r *Responder) handleSetCertificate(ctx context.Context, request []byte) ([]byte, error) {
	if !r.negotiated {
		return r.buildError(codes.ErrorUnexpectedRequest, 0), nil
	}
	if r.cfg.ProvisioningProvider == nil {
		return r.buildError(codes.ErrorUnsupportedRequest, 0), nil
	}

	var req msgs.SetCertificate
	if err := req.Unmarshal(request); err != nil {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	slotID := req.SlotID()
	if err := r.cfg.ProvisioningProvider.SetCertificate(ctx, slotID, req.CertChain); err != nil {
		logger.Debugf(ctx, "handleSetCertificate: provider error: %v", err)
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}

	resp := &msgs.SetCertificateResponse{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         uint8(r.version),
			RequestResponseCode: uint8(codes.ResponseSetCertificateRsp),
			Param1:              slotID,
		}},
	}

	logger.Debugf(ctx, "handleSetCertificate: slotID=%d", slotID)
	return resp.Marshal()
}

func (r *Responder) handleGetKeyPairInfo(ctx context.Context, request []byte) ([]byte, error) {
	if !r.negotiated {
		return r.buildError(codes.ErrorUnexpectedRequest, 0), nil
	}
	if r.cfg.ProvisioningProvider == nil {
		return r.buildError(codes.ErrorUnsupportedRequest, 0), nil
	}

	var req msgs.GetKeyPairInfo
	if err := req.Unmarshal(request); err != nil {
		return r.buildError(codes.ErrorInvalidRequest, 0), nil
	}

	info, err := r.cfg.ProvisioningProvider.GetKeyPairInfo(ctx, req.KeyPairID)
	if err != nil {
		logger.Debugf(ctx, "handleGetKeyPairInfo: provider error: %v", err)
		return r.buildError(codes.ErrorUnspecified, 0), nil
	}

	info.Header = msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
		SPDMVersion:         uint8(r.version),
		RequestResponseCode: uint8(codes.ResponseKeyPairInfo),
	}}

	logger.Debugf(ctx, "handleGetKeyPairInfo: keyPairID=%d", req.KeyPairID)
	return info.Marshal()
}
