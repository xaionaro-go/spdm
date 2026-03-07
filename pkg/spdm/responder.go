package spdm

import (
	"context"

	"github.com/xaionaro-go/spdm/pkg/responder"
)

// Responder is the consumer-facing SPDM responder.
type Responder struct {
	inner *responder.Responder
}

// NewResponder creates a new SPDM responder.
func NewResponder(cfg ResponderConfig) *Responder {
	return &Responder{
		inner: responder.New(responder.Config{
			Versions:             cfg.Versions,
			Transport:            cfg.Transport,
			Crypto:               cfg.Crypto,
			Caps:                 cfg.Caps,
			BaseAsymAlgo:         cfg.BaseAsymAlgo,
			BaseHashAlgo:         cfg.BaseHashAlgo,
			DHEGroups:            cfg.DHEGroups,
			AEADSuites:           cfg.AEADSuites,
			DataTransferSize:     cfg.DataTransferSize,
			MaxSPDMmsgSize:       cfg.MaxSPDMmsgSize,
			CertProvider:         cfg.CertProvider,
			MeasProvider:         cfg.MeasProvider,
			DeviceSigner:         cfg.Crypto.Signer,
			PSKProvider:          cfg.PSKProvider,
			CSRProvider:          cfg.CSRProvider,
			ProvisioningProvider: cfg.ProvisioningProvider,
			EndpointInfoProvider: cfg.EndpointInfoProvider,
			MELProvider:          cfg.MELProvider,
		}),
	}
}

// ProcessMessage handles a single SPDM request and returns the response.
func (r *Responder) ProcessMessage(ctx context.Context, request []byte) ([]byte, error) {
	return r.inner.ProcessMessage(ctx, request)
}

// Serve continuously reads requests and writes responses.
func (r *Responder) Serve(ctx context.Context) error {
	return r.inner.Serve(ctx)
}
