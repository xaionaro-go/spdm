//go:build reference

package interop

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/spdm/pkg/crypto/stdlib"
	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/caps"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/responder"
	"github.com/xaionaro-go/spdm/pkg/transport/qemusock"
)

// staticMeasProvider implements responder.MeasurementProvider with static blocks.
type staticMeasProvider struct {
	blocks []msgs.MeasurementBlock
}

func (p *staticMeasProvider) Collect(_ context.Context, index uint8) ([]msgs.MeasurementBlock, error) {
	if index == msgs.MeasOpAllMeasurements {
		return p.blocks, nil
	}
	if index == msgs.MeasOpTotalCount {
		return nil, nil // count is returned via Param1
	}
	for _, b := range p.blocks {
		if b.Index == index {
			return []msgs.MeasurementBlock{b}, nil
		}
	}
	return nil, nil
}

func (p *staticMeasProvider) SummaryHash(_ context.Context, hashType uint8) ([]byte, error) {
	if hashType == msgs.NoMeasurementSummaryHash {
		return nil, nil
	}
	// Return a hash over all measurement values.
	h := sha256.New()
	for _, b := range p.blocks {
		h.Write(b.Value)
	}
	return h.Sum(nil), nil
}

// goResponderConfig holds the parameters for starting a Go SPDM responder.
type goResponderConfig struct {
	rspCaps      caps.ResponderCaps
	asymAlgo     algo.BaseAsymAlgo
	hashAlgo     algo.BaseHashAlgo
	dheGroups    algo.DHENamedGroup
	aeadSuites   algo.AEADCipherSuite
	measProvider responder.MeasurementProvider
}

// buildCertChain generates a root+leaf certificate chain and builds the
// SPDM CertChain structure per DSP0274 Section 10.7.1.
// If curve is nil, defaults to P-256.
func buildCertChain(t *testing.T, curve elliptic.Curve, hashSize int) (certChain []byte, digest []byte, leafKey crypto.Signer) {
	if curve == nil {
		curve = elliptic.P256()
	}
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)

	lk, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &lk.PublicKey, rootKey)
	require.NoError(t, err)

	certsData := append(rootDER, leafDER...)
	chainLen := msgs.CertChainHeaderSize + hashSize + len(certsData)
	certChain = make([]byte, chainLen)
	binary.LittleEndian.PutUint16(certChain[0:], uint16(chainLen))
	binary.LittleEndian.PutUint16(certChain[2:], 0)

	var rootHash []byte
	switch hashSize {
	case 48:
		h := sha512.Sum384(rootDER)
		rootHash = h[:]
	default:
		h := sha256.Sum256(rootDER)
		rootHash = h[:]
	}
	copy(certChain[msgs.CertChainHeaderSize:], rootHash)
	copy(certChain[msgs.CertChainHeaderSize+hashSize:], certsData)

	switch hashSize {
	case 48:
		h := sha512.Sum384(certChain)
		digest = h[:]
	default:
		h := sha256.Sum256(certChain)
		digest = h[:]
	}

	return certChain, digest, lk
}

// buildCertChainWithRoot is like buildCertChain but also returns the raw root CA DER.
func buildCertChainWithRoot(t *testing.T, curve elliptic.Curve, hashSize int) (certChain []byte, digest []byte, rootDER []byte, leafKey crypto.Signer) {
	if curve == nil {
		curve = elliptic.P256()
	}
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
	}
	rootDER, err = x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)

	lk, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &lk.PublicKey, rootKey)
	require.NoError(t, err)

	certsData := append(rootDER, leafDER...)
	chainLen := msgs.CertChainHeaderSize + hashSize + len(certsData)
	certChain = make([]byte, chainLen)
	binary.LittleEndian.PutUint16(certChain[0:], uint16(chainLen))
	binary.LittleEndian.PutUint16(certChain[2:], 0)

	var rootHash []byte
	switch hashSize {
	case 48:
		h := sha512.Sum384(rootDER)
		rootHash = h[:]
	default:
		h := sha256.Sum256(rootDER)
		rootHash = h[:]
	}
	copy(certChain[msgs.CertChainHeaderSize:], rootHash)
	copy(certChain[msgs.CertChainHeaderSize+hashSize:], certsData)

	switch hashSize {
	case 48:
		h := sha512.Sum384(certChain)
		digest = h[:]
	default:
		h := sha256.Sum256(certChain)
		digest = h[:]
	}

	return certChain, digest, rootDER, lk
}

// startGoResponderFull starts a Go responder with the given configuration on port 2323.
func startGoResponderFull(t *testing.T, cfg goResponderConfig) chan error {
	t.Helper()

	var curve elliptic.Curve
	var hashSize int
	switch cfg.hashAlgo {
	case algo.HashSHA384:
		curve = elliptic.P384()
		hashSize = 48
	default:
		curve = elliptic.P256()
		hashSize = 32
	}

	certChain, digest, leafKey := buildCertChain(t, curve, hashSize)
	cryptoSuite := stdlib.NewSuite(leafKey, nil)

	listener, err := net.Listen("tcp", "127.0.0.1:2323")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	rspCfg := responder.Config{
		Versions:         []algo.Version{algo.Version12},
		Crypto:           *cryptoSuite,
		Caps:             cfg.rspCaps,
		BaseAsymAlgo:     cfg.asymAlgo,
		BaseHashAlgo:     cfg.hashAlgo,
		DHEGroups:        cfg.dheGroups,
		AEADSuites:       cfg.aeadSuites,
		DataTransferSize: 4096,
		MaxSPDMmsgSize:   4096,
		CertProvider:     &staticCertProvider{chain: certChain, digest: digest},
		DeviceSigner:     leafKey,
	}
	if cfg.measProvider != nil {
		rspCfg.MeasProvider = cfg.measProvider
	}

	goRsp := responder.New(rspCfg)
	return runResponderServerLoop(t, listener, goRsp)
}

// runResponderServerLoop runs the Go responder on the listener, handling the
// spdm-emu platform port protocol.
func runResponderServerLoop(t *testing.T, listener net.Listener, goRsp *responder.Responder) chan error {
	t.Helper()
	serverErr := make(chan error, 1)
	ready := make(chan struct{})
	go func() {
		close(ready)
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- fmt.Errorf("accept: %w", err)
			return
		}
		defer conn.Close()

		et := NewEmuTransport(conn, qemusock.TransportNone)
		for {
			cmd, request, err := et.Conn().RecvCommand()
			if err != nil {
				serverErr <- fmt.Errorf("recv: %w", err)
				return
			}
			switch cmd {
			case qemusock.CommandTest:
				if err := et.Conn().SendCommand(qemusock.CommandTest, nil); err != nil {
					serverErr <- fmt.Errorf("send test ack: %w", err)
					return
				}
				continue
			case qemusock.CommandShutdown:
				_ = et.Conn().SendCommand(qemusock.CommandShutdown, nil)
				serverErr <- nil
				return
			case qemusock.CommandNormal:
			default:
				serverErr <- fmt.Errorf("unknown command: 0x%04x", cmd)
				return
			}
			if len(request) == 0 {
				continue
			}
			resp, err := goRsp.ProcessMessage(context.Background(), request)
			if err != nil {
				serverErr <- fmt.Errorf("process: %w", err)
				return
			}
			if err := et.Conn().SendCommand(qemusock.CommandNormal, resp); err != nil {
				serverErr <- fmt.Errorf("send: %w", err)
				return
			}
		}
	}()
	<-ready
	return serverErr
}
