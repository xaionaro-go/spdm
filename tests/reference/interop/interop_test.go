//go:build reference

package interop

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"testing"

	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/spdm/internal/testutil"
	"github.com/xaionaro-go/spdm/pkg/crypto/stdlib"
	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/caps"
	"github.com/xaionaro-go/spdm/pkg/gen/codes"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/gen/raw"
	"github.com/xaionaro-go/spdm/pkg/requester"
	"github.com/xaionaro-go/spdm/pkg/responder"
	"github.com/xaionaro-go/spdm/pkg/session"
	"github.com/xaionaro-go/spdm/pkg/transport/qemusock"
)

var (
	spdmEmuBin = flag.String("spdm-emu-bin", "", "Path to spdm-emu bin directory")
	spdmPort   = flag.Int("spdm-port", 2323, "Port for spdm-emu responder")
)

func skipIfNoEmu(t *testing.T) {
	t.Helper()
	if *spdmEmuBin == "" {
		t.Skip("skipping: -spdm-emu-bin not specified")
	}
	if _, err := os.Stat(*spdmEmuBin + "/spdm_responder_emu"); err != nil {
		t.Skipf("skipping: spdm_responder_emu not found: %v", err)
	}
}

func startEmuResponder(t *testing.T, extraArgs ...string) *EmuProcess {
	t.Helper()
	skipIfNoEmu(t)

	proc, err := StartResponder(*spdmEmuBin, *spdmPort, extraArgs...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = proc.Stop() })
	return proc
}

// newRequesterConfig returns a standard requester config for interop tests.
func newRequesterConfig(t *testing.T, transport *EmuTransport, hashAlgo algo.BaseHashAlgo, asymAlgo algo.BaseAsymAlgo, keyType string) requester.Config {
	t.Helper()
	_, _, leafKey := testutil.TestCerts(t, keyType)
	cryptoSuite := stdlib.NewSuite(leafKey, nil)

	// Per DSP0274 Section 10.4, ENCRYPT/MAC require KEY_EX or PSK.
	// HANDSHAKE_IN_CLEAR requires KEY_EX. We omit MUT_AUTH since we
	// don't do mutual authentication in these tests.
	reqCaps := caps.ReqCertCap | caps.ReqChalCap |
		caps.ReqEncryptCap | caps.ReqMACCap | caps.ReqKeyExCap |
		caps.ReqHBeatCap | caps.ReqKeyUpdCap | caps.ReqHandshakeInTheClearCap

	return requester.Config{
		Versions:         []algo.Version{algo.Version12},
		Transport:        transport,
		Crypto:           *cryptoSuite,
		Caps:             reqCaps,
		CTExponent:       12, // 2^12 = 4096 microseconds
		BaseAsymAlgo:     asymAlgo,
		BaseHashAlgo:     hashAlgo,
		DHEGroups:        algo.DHESECP256R1,
		AEADSuites:       algo.AEADAES256GCM,
		DataTransferSize: 4096,
		MaxSPDMmsgSize:   4096, // must equal DataTransferSize without CHUNK_CAP
	}
}

// --- Tests: Go requester against libspdm responder ---

// TestInterop_GoRequester_LibspdmResponder_GetVersion verifies basic
// connectivity with GET_VERSION per DSP0274 Section 10.3.
func TestInterop_GoRequester_LibspdmResponder_GetVersion(t *testing.T) {
	proc := startEmuResponder(t, "--ver", "1.2")

	transport, err := proc.Connect()
	require.NoError(t, err)
	defer transport.Close()

	getVer := &msgs.GetVersion{
		Header: msgs.MessageHeader{SPDMMessageHeader: raw.SPDMMessageHeader{
			SPDMVersion:         0x10,
			RequestResponseCode: uint8(codes.RequestGetVersion),
		}},
	}
	data, err := getVer.Marshal()
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, transport.SendMessage(ctx, nil, data))

	_, resp, err := transport.ReceiveMessage(ctx)
	require.NoError(t, err)

	require.GreaterOrEqual(t, len(resp), msgs.HeaderSize)
	require.Equal(t, uint8(codes.ResponseVersion), resp[1])

	var vr msgs.VersionResponse
	require.NoError(t, vr.Unmarshal(resp))
	require.NotZero(t, vr.VersionNumberEntryCount, "no version entries")
	t.Logf("libspdm responder supports %d version(s)", vr.VersionNumberEntryCount)
	for _, e := range vr.VersionEntries {
		vn := algo.VersionNumber(e)
		t.Logf("  version: %v", vn.Version())
	}
}

// TestInterop_GoRequester_LibspdmResponder_InitConnection verifies full
// 3-step connection setup per DSP0274 Section 9.1.
func TestInterop_GoRequester_LibspdmResponder_InitConnection(t *testing.T) {
	proc := startEmuResponder(t,
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
		"--dhe", "SECP_256_R1",
		"--aead", "AES_256_GCM",
	)

	transport, err := proc.Connect()
	require.NoError(t, err)
	defer transport.Close()

	cfg := newRequesterConfig(t, transport, algo.HashSHA256, algo.AsymECDSAP256, "ecdsa-p256")
	req := requester.New(cfg)

	ctx := context.Background()
	ci, err := req.InitConnection(ctx)
	require.NoError(t, err)

	t.Logf("Negotiated version: %v", ci.PeerVersion)
	t.Logf("Hash algo: %v", ci.HashAlgo)
	t.Logf("Asym algo: %v", ci.AsymAlgo)

	assert.NotEqual(t, 0, ci.HashAlgo, "no hash algorithm selected")
	assert.NotEqual(t, 0, ci.AsymAlgo, "no asymmetric algorithm selected")
}

// TestInterop_GoRequester_LibspdmResponder_GetDigests verifies
// GET_DIGESTS per DSP0274 Section 10.6.
func TestInterop_GoRequester_LibspdmResponder_GetDigests(t *testing.T) {
	proc := startEmuResponder(t,
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
	)

	transport, err := proc.Connect()
	require.NoError(t, err)
	defer transport.Close()

	cfg := newRequesterConfig(t, transport, algo.HashSHA256, algo.AsymECDSAP256, "ecdsa-p256")
	req := requester.New(cfg)

	ctx := context.Background()
	_, err = req.InitConnection(ctx)
	require.NoError(t, err)

	digests, err := req.GetDigests(ctx)
	require.NoError(t, err)

	t.Logf("Got %d digest(s)", len(digests))
	assert.NotEqual(t, 0, len(digests), "expected at least one digest from libspdm")
}

// TestInterop_GoRequester_LibspdmResponder_GetCertificate verifies
// GET_CERTIFICATE per DSP0274 Section 10.7.
func TestInterop_GoRequester_LibspdmResponder_GetCertificate(t *testing.T) {
	proc := startEmuResponder(t,
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
	)

	transport, err := proc.Connect()
	require.NoError(t, err)
	defer transport.Close()

	cfg := newRequesterConfig(t, transport, algo.HashSHA256, algo.AsymECDSAP256, "ecdsa-p256")
	req := requester.New(cfg)

	ctx := context.Background()
	_, err = req.InitConnection(ctx)
	require.NoError(t, err)

	chain, err := req.GetCertificate(ctx, 0)
	require.NoError(t, err)

	t.Logf("Certificate chain: %d bytes", len(chain))
	assert.NotEqual(t, 0, len(chain), "expected non-empty certificate chain")
}

// TestInterop_GoRequester_LibspdmResponder_Challenge verifies
// CHALLENGE per DSP0274 Section 10.8.
func TestInterop_GoRequester_LibspdmResponder_Challenge(t *testing.T) {
	proc := startEmuResponder(t,
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
	)

	transport, err := proc.Connect()
	require.NoError(t, err)
	defer transport.Close()

	cfg := newRequesterConfig(t, transport, algo.HashSHA256, algo.AsymECDSAP256, "ecdsa-p256")
	req := requester.New(cfg)

	ctx := context.Background()
	_, err = req.InitConnection(ctx)
	require.NoError(t, err)

	require.NoError(t, req.Challenge(ctx, 0, msgs.NoMeasurementSummaryHash))

	t.Log("Challenge authentication succeeded against libspdm")
}

// TestInterop_GoRequester_LibspdmResponder_GetMeasurements verifies
// GET_MEASUREMENTS per DSP0274 Section 10.11.
func TestInterop_GoRequester_LibspdmResponder_GetMeasurements(t *testing.T) {
	proc := startEmuResponder(t,
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
		"--meas_hash", "SHA_256",
	)

	transport, err := proc.Connect()
	require.NoError(t, err)
	defer transport.Close()

	cfg := newRequesterConfig(t, transport, algo.HashSHA256, algo.AsymECDSAP256, "ecdsa-p256")
	req := requester.New(cfg)

	ctx := context.Background()
	_, err = req.InitConnection(ctx)
	require.NoError(t, err)

	resp, err := req.GetMeasurements(ctx, 0, false)
	require.NoError(t, err)

	t.Logf("Measurement blocks: %d", resp.NumberOfBlocks)
}

// TestInterop_GoRequester_LibspdmResponder_SHA384 verifies negotiation
// with SHA-384/ECDSA-P384 per DSP0274 Section 10.5.
func TestInterop_GoRequester_LibspdmResponder_SHA384(t *testing.T) {
	proc := startEmuResponder(t,
		"--ver", "1.2",
		"--hash", "SHA_384",
		"--asym", "ECDSA_P384",
		"--dhe", "SECP_384_R1",
		"--aead", "AES_256_GCM",
	)

	transport, err := proc.Connect()
	require.NoError(t, err)
	defer transport.Close()

	cfg := newRequesterConfig(t, transport, algo.HashSHA384, algo.AsymECDSAP384, "ecdsa-p384")
	cfg.DHEGroups = algo.DHESECP384R1
	req := requester.New(cfg)

	ctx := context.Background()
	ci, err := req.InitConnection(ctx)
	require.NoError(t, err)

	assert.Equal(t, algo.HashSHA384, ci.HashAlgo)
	t.Log("SHA-384/ECDSA-P384 negotiation succeeded against libspdm")
}

// TestInterop_GoRequester_LibspdmResponder_KeyExchange verifies session
// establishment via KEY_EXCHANGE per DSP0274 Section 10.12.
func TestInterop_GoRequester_LibspdmResponder_KeyExchange(t *testing.T) {
	proc := startEmuResponder(t,
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
		"--dhe", "SECP_256_R1",
		"--aead", "AES_256_GCM",
	)

	transport, err := proc.Connect()
	require.NoError(t, err)
	defer transport.Close()

	cfg := newRequesterConfig(t, transport, algo.HashSHA256, algo.AsymECDSAP256, "ecdsa-p256")
	req := requester.New(cfg)

	ctx := context.Background()
	_, err = req.InitConnection(ctx)
	require.NoError(t, err)

	// Per DSP0274, KEY_EXCHANGE can proceed after VCA+DIGESTS+CERT.
	// Challenge is not required before KEY_EXCHANGE.
	_, err = req.GetDigests(ctx)
	require.NoError(t, err)
	_, err = req.GetCertificate(ctx, 0)
	require.NoError(t, err)

	sess, err := req.KeyExchange(ctx, 0, msgs.NoMeasurementSummaryHash)
	require.NoError(t, err)

	require.NotNil(t, sess, "expected non-nil session")
	assert.Equal(t, session.StateEstablished, sess.State)
	t.Logf("Session established: ID=0x%08X, state=%v", sess.ID, sess.State)
}

// TestInterop_GoRequester_LibspdmResponder_ChallengeWithMeasSummary verifies
// CHALLENGE with TCB component measurement summary hash per DSP0274 Section 10.8.
func TestInterop_GoRequester_LibspdmResponder_ChallengeWithMeasSummary(t *testing.T) {
	proc := startEmuResponder(t,
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
		"--meas_hash", "SHA_256",
	)

	transport, err := proc.Connect()
	require.NoError(t, err)
	defer transport.Close()

	cfg := newRequesterConfig(t, transport, algo.HashSHA256, algo.AsymECDSAP256, "ecdsa-p256")
	req := requester.New(cfg)

	ctx := context.Background()
	_, err = req.InitConnection(ctx)
	require.NoError(t, err)

	require.NoError(t, req.Challenge(ctx, 0, msgs.TCBComponentMeasurementHash))

	t.Log("Challenge with TCB measurement summary hash succeeded against libspdm")
}

// TestInterop_GoRequester_LibspdmResponder_RSA2048 verifies negotiation
// with RSA-2048/SHA-256 per DSP0274 Section 10.5.
func TestInterop_GoRequester_LibspdmResponder_RSA2048(t *testing.T) {
	proc := startEmuResponder(t,
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "RSASSA_2048",
	)

	transport, err := proc.Connect()
	require.NoError(t, err)
	defer transport.Close()

	cfg := newRequesterConfig(t, transport, algo.HashSHA256, algo.AsymRSASSA2048, "rsa-2048")
	req := requester.New(cfg)

	ctx := context.Background()
	ci, err := req.InitConnection(ctx)
	require.NoError(t, err)

	assert.Equal(t, algo.AsymRSASSA2048, ci.AsymAlgo)
	t.Log("RSA-2048/SHA-256 negotiation succeeded against libspdm")
}

// --- Tests: Go responder against libspdm requester ---

// TestInterop_LibspdmRequester_GoResponder_VCA verifies that our Go responder
// can handle VCA (Version, Capabilities, Algorithms) from the libspdm requester.
func TestInterop_LibspdmRequester_GoResponder_VCA(t *testing.T) {
	skipIfNoEmu(t)
	rspCaps := caps.RspCertCap | caps.RspChalCap | caps.RspMeasCapSig |
		caps.RspEncryptCap | caps.RspMACCap | caps.RspKeyExCap |
		caps.RspHBeatCap | caps.RspKeyUpdCap | caps.RspHandshakeInTheClearCap

	serverErr := startGoResponder(t, rspCaps)

	output, err := runLibspdmRequester(t,
		"--trans", "NONE",
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
		"--exe_conn", "VCA",
	)
	t.Logf("requester output:\n%s", output)

	assert.Equal(t, nil, err)
	select {
	case srvErr := <-serverErr:
		assert.Equal(t, nil, srvErr)
	default:
	}
}

// TestInterop_LibspdmRequester_GoResponder_Digest verifies our responder
// handles GET_DIGESTS from the libspdm requester per DSP0274 Section 10.6.
func TestInterop_LibspdmRequester_GoResponder_Digest(t *testing.T) {
	skipIfNoEmu(t)
	rspCaps := caps.RspCertCap | caps.RspChalCap | caps.RspMeasCapSig |
		caps.RspEncryptCap | caps.RspMACCap | caps.RspKeyExCap |
		caps.RspHBeatCap | caps.RspKeyUpdCap | caps.RspHandshakeInTheClearCap

	serverErr := startGoResponder(t, rspCaps)

	output, err := runLibspdmRequester(t,
		"--trans", "NONE",
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
		"--exe_conn", "DIGEST",
	)
	t.Logf("requester output:\n%s", output)

	assert.Equal(t, nil, err)
	select {
	case srvErr := <-serverErr:
		assert.Equal(t, nil, srvErr)
	default:
	}
}

// TestInterop_LibspdmRequester_GoResponder_Cert verifies our responder
// handles GET_CERTIFICATE from the libspdm requester per DSP0274 Section 10.7.
func TestInterop_LibspdmRequester_GoResponder_Cert(t *testing.T) {
	skipIfNoEmu(t)
	rspCaps := caps.RspCertCap | caps.RspChalCap | caps.RspMeasCapSig |
		caps.RspEncryptCap | caps.RspMACCap | caps.RspKeyExCap |
		caps.RspHBeatCap | caps.RspKeyUpdCap | caps.RspHandshakeInTheClearCap

	serverErr := startGoResponder(t, rspCaps)

	output, err := runLibspdmRequester(t,
		"--trans", "NONE",
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
		"--exe_conn", "DIGEST,CERT",
	)
	t.Logf("requester output:\n%s", output)

	assert.Equal(t, nil, err)
	select {
	case srvErr := <-serverErr:
		assert.Equal(t, nil, srvErr)
	default:
	}
}

// TestInterop_LibspdmRequester_GoResponder_Challenge verifies our responder
// handles CHALLENGE from the libspdm requester per DSP0274 Section 10.8.
// This validates the full transcript-based signature (M1/M2).
func TestInterop_LibspdmRequester_GoResponder_Challenge(t *testing.T) {
	skipIfNoEmu(t)
	rspCaps := caps.RspCertCap | caps.RspChalCap | caps.RspMeasCapSig |
		caps.RspEncryptCap | caps.RspMACCap | caps.RspKeyExCap |
		caps.RspHBeatCap | caps.RspKeyUpdCap | caps.RspHandshakeInTheClearCap

	serverErr := startGoResponder(t, rspCaps)

	output, err := runLibspdmRequester(t,
		"--trans", "NONE",
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
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

// startGoResponder sets up a Go responder on port 2323 and returns the server error channel.
// The caller must start the libspdm requester after calling this.
func startGoResponder(t *testing.T, rspCaps caps.ResponderCaps) chan error {
	t.Helper()

	// Generate a root CA and leaf cert for the responder.
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)

	// Build SPDM cert chain per DSP0274 Section 10.7.1.
	hashSize := 32 // SHA-256
	certsData := append(rootDER, leafDER...)
	chainLen := msgs.CertChainHeaderSize + hashSize + len(certsData)
	certChain := make([]byte, chainLen)
	binary.LittleEndian.PutUint16(certChain[0:], uint16(chainLen))
	binary.LittleEndian.PutUint16(certChain[2:], 0)
	rootHash := sha256.Sum256(rootDER)
	copy(certChain[msgs.CertChainHeaderSize:], rootHash[:])
	copy(certChain[msgs.CertChainHeaderSize+hashSize:], certsData)

	chainHash := sha256.Sum256(certChain)
	digest := chainHash[:]

	cryptoSuite := stdlib.NewSuite(leafKey, nil)

	listener, err2 := net.Listen("tcp", "127.0.0.1:2323")
	require.NoError(t, err2)
	t.Cleanup(func() { listener.Close() })

	goRsp := responder.New(responder.Config{
		Versions:         []algo.Version{algo.Version12},
		Crypto:           *cryptoSuite,
		Caps:             rspCaps,
		BaseAsymAlgo:     algo.AsymECDSAP256,
		BaseHashAlgo:     algo.HashSHA256,
		DHEGroups:        algo.DHESECP256R1,
		AEADSuites:       algo.AEADAES256GCM,
		DataTransferSize: 4096,
		MaxSPDMmsgSize:   4096,
		CertProvider:     &staticCertProvider{chain: certChain, digest: digest},
		DeviceSigner:     leafKey,
	})

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

// runLibspdmRequester runs the libspdm spdm_requester_emu with the given args and returns output.
func runLibspdmRequester(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	requesterBin := *spdmEmuBin + "/spdm_requester_emu"
	if _, err := os.Stat(requesterBin); err != nil {
		t.Skipf("requester binary not found: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, requesterBin, args...)
	cmd.Dir = *spdmEmuBin
	return cmd.CombinedOutput()
}

type staticCertProvider struct {
	chain  []byte
	digest []byte
}

func (p *staticCertProvider) CertChain(_ context.Context, slotID uint8) ([]byte, error) {
	if slotID == 0 {
		return p.chain, nil
	}
	return nil, fmt.Errorf("slot %d not provisioned", slotID)
}

func (p *staticCertProvider) DigestForSlot(_ context.Context, slotID uint8) ([]byte, error) {
	if slotID == 0 {
		return p.digest, nil
	}
	return nil, fmt.Errorf("slot %d not provisioned", slotID)
}
