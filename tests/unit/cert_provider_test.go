package unit

import "context"

type staticCertProvider struct {
	chain  []byte
	digest []byte
}

func (p *staticCertProvider) CertChain(_ context.Context, slotID uint8) ([]byte, error) {
	if slotID != 0 {
		return nil, nil
	}
	return p.chain, nil
}

func (p *staticCertProvider) DigestForSlot(_ context.Context, slotID uint8) ([]byte, error) {
	if slotID != 0 {
		return nil, nil
	}
	return p.digest, nil
}
