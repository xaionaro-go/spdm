package requester

import (
	"context"

	"github.com/facebookincubator/go-belt/tool/logger"

	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
)

// SetCertificate sends SET_CERTIFICATE per DSP0274 Section 10.23.
func (r *Requester) SetCertificate(ctx context.Context, slotID uint8, certChain []byte) error {
	logger.Debugf(ctx, "SetCertificate: slotID=%d certChainLen=%d", slotID, len(certChain))

	ver := uint8(r.conn.PeerVersion)
	req := &msgs.SetCertificate{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.RequestSetCertificate),
			Param1:              slotID & 0x0F,
		}},
		CertChain: certChain,
	}

	resp, err := r.sendReceive(ctx, req)
	if err != nil {
		return &ErrSetCertificate{Err: err}
	}

	if resp[1] != uint8(codes.ResponseSetCertificateRsp) {
		return &ErrSetCertificateUnexpectedResponseCode{Code: resp[1]}
	}

	logger.Debugf(ctx, "SetCertificate: success")
	return nil
}

// SetKeyPairInfo sends SET_KEY_PAIR_INFO per DSP0274 Section 10.25.
func (r *Requester) SetKeyPairInfo(
	ctx context.Context,
	keyPairID uint8,
	operation uint8,
	desiredKeyUsage uint16,
	desiredAsymAlgo uint32,
	desiredAssocCertSlotMask uint8,
	publicKeyInfo []byte,
) error {
	logger.Debugf(ctx, "SetKeyPairInfo: keyPairID=%d operation=%d", keyPairID, operation)

	ver := uint8(r.conn.PeerVersion)
	req := &msgs.SetKeyPairInfo{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.RequestSetKeyPairInfo),
		}},
		KeyPairID:                keyPairID,
		Operation:                operation,
		DesiredKeyUsage:          desiredKeyUsage,
		DesiredAsymAlgo:          desiredAsymAlgo,
		DesiredAssocCertSlotMask: desiredAssocCertSlotMask,
		PublicKeyInfo:            publicKeyInfo,
	}

	resp, err := r.sendReceive(ctx, req)
	if err != nil {
		return &ErrSetKeyPairInfo{Err: err}
	}

	if resp[1] != uint8(codes.ResponseSetKeyPairInfoAck) {
		return &ErrSetKeyPairInfoUnexpectedResponseCode{Code: resp[1]}
	}

	logger.Debugf(ctx, "SetKeyPairInfo: success")
	return nil
}

// GetKeyPairInfo sends GET_KEY_PAIR_INFO per DSP0274 Section 10.25.
func (r *Requester) GetKeyPairInfo(ctx context.Context, keyPairID uint8) (*msgs.KeyPairInfoResponse, error) {
	logger.Debugf(ctx, "GetKeyPairInfo: keyPairID=%d", keyPairID)

	ver := uint8(r.conn.PeerVersion)
	req := &msgs.GetKeyPairInfo{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         ver,
			RequestResponseCode: uint8(codes.RequestGetKeyPairInfo),
		}},
		KeyPairID: keyPairID,
	}

	resp, err := r.sendReceive(ctx, req)
	if err != nil {
		return nil, &ErrGetKeyPairInfo{Err: err}
	}

	if resp[1] != uint8(codes.ResponseKeyPairInfo) {
		return nil, &ErrGetKeyPairInfoUnexpectedResponseCode{Code: resp[1]}
	}

	var kpr msgs.KeyPairInfoResponse
	if err := kpr.Unmarshal(resp); err != nil {
		return nil, &ErrGetKeyPairInfo{Err: err}
	}

	logger.Debugf(ctx, "GetKeyPairInfo: totalKeyPairs=%d", kpr.TotalKeyPairs)
	return &kpr, nil
}
