//go:build reference

package interop

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/spdm/internal/testutil"
	"github.com/xaionaro-go/spdm/pkg/crypto/stdlib"
	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/caps"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/spdm"
	"github.com/xaionaro-go/spdm/pkg/transport/qemusock"
)

// TestInterop_GoRequester_LibspdmResponder_HighLevelAPI verifies the
// spdm.NewRequester consumer-facing API against libspdm.
func TestInterop_GoRequester_LibspdmResponder_HighLevelAPI(t *testing.T) {
	proc := startEmuResponder(t,
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
		"--meas_hash", "SHA_256",
	)

	transport, err := proc.Connect()
	require.NoError(t, err)
	defer transport.Close()

	_, _, leafKey := testutil.TestCerts(t, "ecdsa-p256")
	cryptoSuite := stdlib.NewSuite(leafKey, nil)

	reqCaps := caps.ReqCertCap | caps.ReqChalCap |
		caps.ReqEncryptCap | caps.ReqMACCap | caps.ReqKeyExCap |
		caps.ReqHBeatCap | caps.ReqKeyUpdCap | caps.ReqHandshakeInTheClearCap

	req := spdm.NewRequester(spdm.RequesterConfig{
		Versions:         []algo.Version{algo.Version12},
		Transport:        transport,
		Crypto:           *cryptoSuite,
		Caps:             reqCaps,
		BaseAsymAlgo:     algo.AsymECDSAP256,
		BaseHashAlgo:     algo.HashSHA256,
		DHEGroups:        algo.DHESECP256R1,
		AEADSuites:       algo.AEADAES256GCM,
		DataTransferSize: 4096,
		MaxSPDMmsgSize:   4096,
	})

	ctx := context.Background()

	ci, err := req.InitConnection(ctx)
	require.NoError(t, err)
	assert.Equal(t, algo.Version12, ci.Version)

	digests, err := req.GetDigests(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, digests.Digests)

	cert, err := req.GetCertificate(ctx, 0)
	require.NoError(t, err)
	require.NotEmpty(t, cert.Chain)

	result, err := req.Challenge(ctx, 0)
	require.NoError(t, err)
	assert.Equal(t, uint8(0), result.SlotID)

	meas, err := req.GetMeasurements(ctx, spdm.MeasurementOpts{Index: 0})
	require.NoError(t, err)
	t.Logf("High-level API: measurements=%d blocks", meas.NumberOfBlocks)
}

// TestInterop_LibspdmRequester_GoResponder_Measurements verifies our Go
// responder handles GET_MEASUREMENTS from the libspdm requester.
func TestInterop_LibspdmRequester_GoResponder_Measurements(t *testing.T) {
	skipIfNoEmu(t)

	rspCaps := caps.RspCertCap | caps.RspChalCap | caps.RspMeasCapSig |
		caps.RspEncryptCap | caps.RspMACCap | caps.RspKeyExCap |
		caps.RspHBeatCap | caps.RspKeyUpdCap | caps.RspHandshakeInTheClearCap

	measBlocks := []msgs.MeasurementBlock{
		{Index: 1, Spec: 0x01, ValueType: msgs.MeasTypeImmutableROM, Value: []byte("firmware-v1.0")},
		{Index: 2, Spec: 0x01, ValueType: msgs.MeasTypeMutableFirmware, Value: []byte("config-hash-abc")},
	}

	serverErr := startGoResponderFull(t, goResponderConfig{
		rspCaps:      rspCaps,
		asymAlgo:     algo.AsymECDSAP256,
		hashAlgo:     algo.HashSHA256,
		dheGroups:    algo.DHESECP256R1,
		aeadSuites:   algo.AEADAES256GCM,
		measProvider: &staticMeasProvider{blocks: measBlocks},
	})

	output, err := runLibspdmRequester(t,
		"--trans", "NONE",
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
		"--meas_hash", "SHA_256",
		"--exe_conn", "DIGEST,CERT,CHAL,MEAS",
	)
	t.Logf("requester output:\n%s", output)

	assert.Equal(t, nil, err)
	select {
	case srvErr := <-serverErr:
		assert.Equal(t, nil, srvErr)
	default:
	}
}

// TestInterop_LibspdmRequester_GoResponder_SHA384 verifies our Go responder
// handles SHA-384/ECDSA-P384 negotiation from the libspdm requester.
func TestInterop_LibspdmRequester_GoResponder_SHA384(t *testing.T) {
	skipIfNoEmu(t)

	rspCaps := caps.RspCertCap | caps.RspChalCap | caps.RspMeasCapSig |
		caps.RspEncryptCap | caps.RspMACCap | caps.RspKeyExCap |
		caps.RspHBeatCap | caps.RspKeyUpdCap | caps.RspHandshakeInTheClearCap

	serverErr := startGoResponderFull(t, goResponderConfig{
		rspCaps:    rspCaps,
		asymAlgo:   algo.AsymECDSAP384,
		hashAlgo:   algo.HashSHA384,
		dheGroups:  algo.DHESECP384R1,
		aeadSuites: algo.AEADAES256GCM,
	})

	output, err := runLibspdmRequester(t,
		"--trans", "NONE",
		"--ver", "1.2",
		"--hash", "SHA_384",
		"--asym", "ECDSA_P384",
		"--exe_conn", "DIGEST,CERT,CHAL",
	)
	t.Logf("requester output:\n%s", output)

	assert.Equal(t, nil, err)
	select {
	case srvErr := <-serverErr:
		assert.Equal(t, nil, srvErr)
	default:
	}
}

// TestInterop_LibspdmRequester_GoResponder_HighLevelAPI verifies the
// spdm.NewResponder consumer-facing API against the libspdm requester.
func TestInterop_LibspdmRequester_GoResponder_HighLevelAPI(t *testing.T) {
	skipIfNoEmu(t)

	rspCaps := caps.RspCertCap | caps.RspChalCap | caps.RspMeasCapSig |
		caps.RspEncryptCap | caps.RspMACCap | caps.RspKeyExCap |
		caps.RspHBeatCap | caps.RspKeyUpdCap | caps.RspHandshakeInTheClearCap

	certChain, digest, leafKey := buildCertChain(t, nil, 32)
	cryptoSuite := stdlib.NewSuite(leafKey, nil)

	measBlocks := []msgs.MeasurementBlock{
		{Index: 1, Spec: 0x01, ValueType: msgs.MeasTypeImmutableROM, Value: []byte("test-firmware")},
	}

	goRsp := spdm.NewResponder(spdm.ResponderConfig{
		Versions:         []algo.Version{algo.Version12},
		Crypto:           *cryptoSuite,
		Caps:             rspCaps,
		BaseAsymAlgo:     algo.AsymECDSAP256,
		BaseHashAlgo:     algo.HashSHA256,
		DHEGroups:        algo.DHESECP256R1,
		AEADSuites:       algo.AEADAES256GCM,
		DataTransferSize: 4096,
		MaxSPDMmsgSize:   4096,
		CertProvider: &spdmCertProvider{
			chain:  certChain,
			digest: digest,
		},
		MeasProvider: &spdmMeasProvider{blocks: measBlocks},
	})

	listener, err := net.Listen("tcp", "127.0.0.1:2323")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

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

	output, err2 := runLibspdmRequester(t,
		"--trans", "NONE",
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
		"--meas_hash", "SHA_256",
		"--exe_conn", "DIGEST,CERT,CHAL,MEAS",
	)
	t.Logf("requester output:\n%s", output)

	assert.Equal(t, nil, err2)
	select {
	case srvErr := <-serverErr:
		assert.Equal(t, nil, srvErr)
	default:
	}
}

// spdmCertProvider implements spdm.CertProvider.
type spdmCertProvider struct {
	chain  []byte
	digest []byte
}

func (p *spdmCertProvider) CertChain(_ context.Context, slotID uint8) ([]byte, error) {
	if slotID == 0 {
		return p.chain, nil
	}
	return nil, fmt.Errorf("slot %d not provisioned", slotID)
}

func (p *spdmCertProvider) DigestForSlot(_ context.Context, slotID uint8) ([]byte, error) {
	if slotID == 0 {
		return p.digest, nil
	}
	return nil, fmt.Errorf("slot %d not provisioned", slotID)
}

// spdmMeasProvider implements spdm.MeasurementProvider.
type spdmMeasProvider struct {
	blocks []msgs.MeasurementBlock
}

func (p *spdmMeasProvider) Collect(_ context.Context, index uint8) ([]msgs.MeasurementBlock, error) {
	if index == msgs.MeasOpAllMeasurements {
		return p.blocks, nil
	}
	for _, b := range p.blocks {
		if b.Index == index {
			return []msgs.MeasurementBlock{b}, nil
		}
	}
	return nil, nil
}

func (p *spdmMeasProvider) SummaryHash(_ context.Context, _ uint8) ([]byte, error) {
	return make([]byte, 32), nil
}
