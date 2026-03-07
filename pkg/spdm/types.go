// Package spdm provides the consumer-facing API for the spdm library per DSP0274.
package spdm

import (
	"github.com/xaionaro-go/spdm/pkg/crypto"
	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/caps"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/responder"
	"github.com/xaionaro-go/spdm/pkg/transport"
)

// RequesterConfig contains protocol configuration for a requester.
type RequesterConfig struct {
	Versions         []algo.Version
	Transport        transport.Transport
	Crypto           crypto.Suite
	Caps             caps.RequesterCaps
	BaseAsymAlgo     algo.BaseAsymAlgo
	BaseHashAlgo     algo.BaseHashAlgo
	DHEGroups        algo.DHENamedGroup
	AEADSuites       algo.AEADCipherSuite
	DataTransferSize uint32
	MaxSPDMmsgSize   uint32
	PSKProvider      crypto.PSKProvider
}

// ResponderConfig contains protocol configuration for a responder.
type ResponderConfig struct {
	Versions             []algo.Version
	Transport            transport.Transport
	Crypto               crypto.Suite
	Caps                 caps.ResponderCaps
	BaseAsymAlgo         algo.BaseAsymAlgo
	BaseHashAlgo         algo.BaseHashAlgo
	DHEGroups            algo.DHENamedGroup
	AEADSuites           algo.AEADCipherSuite
	DataTransferSize     uint32
	MaxSPDMmsgSize       uint32
	CertProvider         CertProvider
	MeasProvider         MeasurementProvider
	PSKProvider          crypto.PSKProvider
	CSRProvider          CSRProvider
	ProvisioningProvider ProvisioningProvider
	EndpointInfoProvider EndpointInfoProvider
	MELProvider          MELProvider
}

// CertProvider supplies certificate chains and digests.
type CertProvider = responder.CertProvider

// MeasurementProvider supplies device measurements.
type MeasurementProvider = responder.MeasurementProvider

// CSRProvider generates Certificate Signing Requests per DSP0274 Section 10.22.
type CSRProvider = responder.CSRProvider

// ProvisioningProvider handles certificate provisioning and key pair queries
// per DSP0274 Section 10.23 and 10.25.
type ProvisioningProvider = responder.ProvisioningProvider

// EndpointInfoProvider supplies endpoint information per DSP0274 Section 10.26.
type EndpointInfoProvider = responder.EndpointInfoProvider

// MELProvider supplies Measurement Extension Log data per DSP0274 Section 10.24.
type MELProvider = responder.MELProvider

// ConnectionInfo holds negotiated connection parameters.
type ConnectionInfo struct {
	Version      algo.Version
	PeerCaps     caps.ResponderCaps
	HashAlgo     algo.BaseHashAlgo
	AsymAlgo     algo.BaseAsymAlgo
	DHEGroup     algo.DHENamedGroup
	AEADSuite    algo.AEADCipherSuite
	MeasHashAlgo algo.MeasurementHashAlgo
}

// Digests holds certificate digests from the responder.
type Digests struct {
	SlotMask uint8
	Digests  [][]byte
}

// CertificateChain holds a retrieved certificate chain.
type CertificateChain struct {
	SlotID uint8
	Chain  []byte
}

// ChallengeResult holds the result of a CHALLENGE operation.
type ChallengeResult struct {
	SlotID                 uint8
	CertChainHash          []byte
	MeasurementSummaryHash []byte
}

// MeasurementOpts configures a GET_MEASUREMENTS request.
type MeasurementOpts struct {
	Index            uint8
	RequestSignature bool
	SlotID           uint8
	RawBitStream     bool
}

// Measurements holds measurement results.
type Measurements struct {
	NumberOfBlocks uint8
	Blocks         []msgs.MeasurementBlock
	Signature      []byte
}

// KeyExchangeOpts configures a KEY_EXCHANGE request.
type KeyExchangeOpts struct {
	SlotID   uint8
	HashType uint8
}

// KeyUpdateOp represents key update operations.
type KeyUpdateOp uint8

const (
	KeyUpdateUpdateKey     KeyUpdateOp = 1
	KeyUpdateUpdateAllKeys KeyUpdateOp = 2
	KeyUpdateVerifyNewKey  KeyUpdateOp = 3
)

// VendorRequest is a vendor-defined request.
type VendorRequest struct {
	StandardID uint16
	VendorID   []byte
	Payload    []byte
}

// VendorResponse is a vendor-defined response.
type VendorResponse struct {
	StandardID uint16
	VendorID   []byte
	Payload    []byte
}
