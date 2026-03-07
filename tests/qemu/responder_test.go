//go:build qemu

package qemu

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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
	"github.com/xaionaro-go/spdm/pkg/spdm"
	"github.com/xaionaro-go/spdm/pkg/transport"
	"github.com/xaionaro-go/spdm/pkg/transport/pcidoe"
	"github.com/xaionaro-go/spdm/pkg/transport/qemusock"
)

// startGoResponder starts a Go SPDM responder listening on a free TCP port.
// It accepts a single connection, sets up qemusock + PCI DOE transport, and
// serves SPDM. Returns the port and a cleanup function.
func startGoResponder(
	t *testing.T,
) (int, func()) {
	t.Helper()

	port := findFreePort(t)
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	require.NoError(t, err, "listening on port %d", port)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			// Listener was closed during cleanup; that is expected.
			return
		}

		bridge := qemusock.NewBridge(conn, qemusock.TransportPCIDOE)
		bridge.Start()
		doeTransport := pcidoe.New(bridge)

		rsp := createTestResponder(doeTransport)
		_ = rsp.Serve(ctx)

		bridge.Close()
		conn.Close()
	}()

	cleanup := func() {
		cancel()
		ln.Close()
	}

	return port, cleanup
}

// createTestResponder creates an SPDM responder with an ephemeral ECDSA cert
// and static measurements, suitable for E2E testing.
func createTestResponder(
	spdmTransport transport.Transport,
) *spdm.Responder {
	key, certChainBytes, certPool := generateTestCert()

	suite := stdlib.NewSuite(key, certPool)

	return spdm.NewResponder(spdm.ResponderConfig{
		Versions:         []algo.Version{algo.Version12},
		Transport:        spdmTransport,
		Crypto:           *suite,
		Caps:             caps.RspCertCap | caps.RspChalCap | caps.RspMeasCapNoSig,
		BaseAsymAlgo:     algo.AsymECDSAP256,
		BaseHashAlgo:     algo.HashSHA256,
		DHEGroups:        algo.DHESECP256R1,
		AEADSuites:       algo.AEADAES128GCM,
		DataTransferSize: 4096,
		MaxSPDMmsgSize:   65536,
		CertProvider:     &testCertProvider{chain: certChainBytes, digest: computeTestDigest(certChainBytes)},
		MeasProvider:     &testMeasurementProvider{},
	})
}

// generateTestCert creates an ephemeral ECDSA P-256 key and self-signed
// certificate. Returns the private key, the SPDM certificate chain bytes
// (per DSP0274 Section 10.6.1), and a CertPool for validation.
func generateTestCert() (*ecdsa.PrivateKey, []byte, *x509.CertPool) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("generating ECDSA key: " + err.Error())
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "spdm-test-responder"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic("creating certificate: " + err.Error())
	}

	// SPDM certificate chain format per DSP0274 Section 10.6.1:
	// [2-byte total length] [2-byte reserved (0)] [root_cert_hash (32 bytes for SHA-256)] [cert chain DER...]
	rootHash := sha256.Sum256(certDER)

	chainPayload := make([]byte, 0, 4+len(rootHash)+len(certDER))
	totalLen := uint16(4 + len(rootHash) + len(certDER))
	chainPayload = binary.LittleEndian.AppendUint16(chainPayload, totalLen)
	chainPayload = binary.LittleEndian.AppendUint16(chainPayload, 0) // reserved
	chainPayload = append(chainPayload, rootHash[:]...)
	chainPayload = append(chainPayload, certDER...)

	pool := x509.NewCertPool()
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		panic("parsing certificate: " + err.Error())
	}
	pool.AddCert(cert)

	return key, chainPayload, pool
}

func computeTestDigest(certChain []byte) []byte {
	h := sha256.Sum256(certChain)
	return h[:]
}

// testCertProvider provides a single certificate chain in slot 0.
type testCertProvider struct {
	chain  []byte
	digest []byte
}

func (p *testCertProvider) CertChain(
	_ context.Context,
	slotID uint8,
) ([]byte, error) {
	if slotID != 0 {
		return nil, fmt.Errorf("slot %d not available", slotID)
	}
	return p.chain, nil
}

func (p *testCertProvider) DigestForSlot(
	_ context.Context,
	slotID uint8,
) ([]byte, error) {
	if slotID != 0 {
		return nil, fmt.Errorf("slot %d not available", slotID)
	}
	return p.digest, nil
}

// testMeasurementProvider provides a single dummy measurement block.
type testMeasurementProvider struct{}

func (p *testMeasurementProvider) Collect(
	_ context.Context,
	_ uint8,
) ([]msgs.MeasurementBlock, error) {
	return []msgs.MeasurementBlock{
		{
			Index:     1,
			Spec:      0x01, // DMTF
			ValueType: 0x00, // immutable ROM
			Value:     []byte("spdm-test-measurement-v1"),
		},
	}, nil
}

func (p *testMeasurementProvider) SummaryHash(
	_ context.Context,
	_ uint8,
) ([]byte, error) {
	return make([]byte, 32), nil
}

// findFreePort binds to :0 to obtain an ephemeral port from the OS,
// then immediately closes the listener and returns the port number.
func findFreePort(
	t *testing.T,
) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "binding to ephemeral port")

	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close(), "closing ephemeral listener")

	return port
}
