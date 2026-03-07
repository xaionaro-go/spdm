//go:build reference

package interop

import (
	"context"
	"crypto"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	spdmcrypto "github.com/xaionaro-go/spdm/pkg/crypto"
	"github.com/xaionaro-go/spdm/pkg/crypto/stdlib"
	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/caps"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/responder"
	"github.com/xaionaro-go/spdm/pkg/session"
	"github.com/xaionaro-go/spdm/pkg/transport/mctp"
	"github.com/xaionaro-go/spdm/pkg/transport/qemusock"
)

var le = binary.LittleEndian

// TestInterop_LibspdmRequester_GoResponder_KeyExchange verifies that our Go
// responder handles KEY_EXCHANGE + FINISH from the libspdm requester.
func TestInterop_LibspdmRequester_GoResponder_KeyExchange(t *testing.T) {
	skipIfNoEmu(t)

	serverErr := startGoResponderWithSession(t, defaultSessionConfig())

	output, err := runLibspdmRequester(t,
		"--trans", "MCTP",
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
		"--dhe", "SECP_256_R1",
		"--aead", "AES_256_GCM",
		"--exe_conn", "DIGEST,CERT",
		"--exe_session", "KEY_EX",
	)
	t.Logf("requester output:\n%s", output)

	// Check server error first (may explain requester SIGPIPE).
	select {
	case srvErr := <-serverErr:
		if srvErr != nil {
			t.Logf("server error: %v", srvErr)
		}
		require.NoError(t, srvErr, "Go responder server failed")
	default:
	}
	require.NoError(t, err, "libspdm requester failed")
}

// TestInterop_LibspdmRequester_GoResponder_SessionHeartbeat verifies
// HEARTBEAT over a secured session.
func TestInterop_LibspdmRequester_GoResponder_SessionHeartbeat(t *testing.T) {
	skipIfNoEmu(t)

	serverErr := startGoResponderWithSession(t, defaultSessionConfig())

	output, err := runLibspdmRequester(t,
		"--trans", "MCTP",
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
		"--dhe", "SECP_256_R1",
		"--aead", "AES_256_GCM",
		"--exe_conn", "DIGEST,CERT",
		"--exe_session", "KEY_EX,HEARTBEAT",
	)
	t.Logf("requester output:\n%s", output)

	require.NoError(t, err, "libspdm requester failed")
	select {
	case srvErr := <-serverErr:
		require.NoError(t, srvErr)
	default:
	}
}

// TestInterop_LibspdmRequester_GoResponder_SessionKeyUpdate verifies
// KEY_UPDATE over a secured session.
func TestInterop_LibspdmRequester_GoResponder_SessionKeyUpdate(t *testing.T) {
	skipIfNoEmu(t)
	serverErr := startGoResponderWithSession(t, defaultSessionConfig())

	output, err := runLibspdmRequester(t,
		"--trans", "MCTP",
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
		"--dhe", "SECP_256_R1",
		"--aead", "AES_256_GCM",
		"--exe_conn", "DIGEST,CERT",
		"--exe_session", "KEY_EX,KEY_UPDATE",
	)
	t.Logf("requester output:\n%s", output)

	// Check server error first to get a useful diagnostic if the server crashed.
	select {
	case srvErr := <-serverErr:
		require.NoError(t, srvErr, "go responder error")
	default:
	}
	require.NoError(t, err, "libspdm requester failed")
}

// TestInterop_LibspdmRequester_GoResponder_SessionMeasurements verifies
// GET_MEASUREMENTS over a secured session.
func TestInterop_LibspdmRequester_GoResponder_SessionMeasurements(t *testing.T) {
	skipIfNoEmu(t)

	cfg := defaultSessionConfig()
	cfg.measProvider = &staticMeasProvider{
		blocks: []msgs.MeasurementBlock{
			{Index: 1, Spec: 0x01, ValueType: msgs.MeasTypeImmutableROM, Value: []byte("firmware-v1.0")},
			{Index: 2, Spec: 0x01, ValueType: msgs.MeasTypeMutableFirmware, Value: []byte("config-hash-abc")},
		},
	}

	serverErr := startGoResponderWithSession(t, cfg)

	output, err := runLibspdmRequester(t,
		"--trans", "MCTP",
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
		"--dhe", "SECP_256_R1",
		"--aead", "AES_256_GCM",
		"--meas_hash", "SHA_256",
		"--exe_conn", "DIGEST,CERT",
		"--exe_session", "KEY_EX,MEAS",
	)
	t.Logf("requester output:\n%s", output)

	require.NoError(t, err, "libspdm requester failed")
	select {
	case srvErr := <-serverErr:
		require.NoError(t, srvErr)
	default:
	}
}

// TestInterop_LibspdmRequester_GoResponder_ServeLoop verifies using
// Responder.Serve() instead of a manual ProcessMessage loop.
func TestInterop_LibspdmRequester_GoResponder_ServeLoop(t *testing.T) {
	skipIfNoEmu(t)

	certChain, digest, leafKey := buildCertChain(t, nil, 32)

	rspCaps := caps.RspCertCap | caps.RspChalCap | caps.RspMeasCapSig |
		caps.RspEncryptCap | caps.RspMACCap | caps.RspKeyExCap |
		caps.RspHBeatCap | caps.RspKeyUpdCap | caps.RspHandshakeInTheClearCap

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
		// Use the emu-protocol-aware receive for Serve().
		emuAware := &emuProtocolTransport{et: et}
		goRsp := responder.New(responder.Config{
			Versions:         []algo.Version{algo.Version12},
			Crypto:           *newCryptoSuite(leafKey),
			Caps:             rspCaps,
			BaseAsymAlgo:     algo.AsymECDSAP256,
			BaseHashAlgo:     algo.HashSHA256,
			DHEGroups:        algo.DHESECP256R1,
			AEADSuites:       algo.AEADAES256GCM,
			DataTransferSize: 4096,
			MaxSPDMmsgSize:   4096,
			CertProvider:     &staticCertProvider{chain: certChain, digest: digest},
			DeviceSigner:     leafKey,
			Transport:        emuAware,
		})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		serveErr := goRsp.Serve(ctx)
		serverErr <- serveErr
	}()
	<-ready

	output, err2 := runLibspdmRequester(t,
		"--trans", "NONE",
		"--ver", "1.2",
		"--hash", "SHA_256",
		"--asym", "ECDSA_P256",
		"--exe_conn", "DIGEST,CERT,CHAL",
	)
	t.Logf("requester output:\n%s", output)

	// Serve() returns an error when the connection closes; we just check
	// that the libspdm requester itself succeeded.
	assert.NoError(t, err2, "libspdm requester should succeed")
}

func defaultSessionConfig() goResponderConfig {
	return goResponderConfig{
		rspCaps: caps.RspCertCap | caps.RspChalCap | caps.RspMeasCapSig |
			caps.RspEncryptCap | caps.RspMACCap | caps.RspKeyExCap |
			caps.RspHBeatCap | caps.RspKeyUpdCap | caps.RspHandshakeInTheClearCap,
		asymAlgo:   algo.AsymECDSAP256,
		hashAlgo:   algo.HashSHA256,
		dheGroups:  algo.DHESECP256R1,
		aeadSuites: algo.AEADAES256GCM,
	}
}

// startGoResponderWithSession starts a Go responder that handles secured
// messages for session operations. It provisions the root CA cert so that
// spdm_requester_emu can verify the cert chain for KEY_EXCHANGE.
func startGoResponderWithSession(t *testing.T, cfg goResponderConfig) chan error {
	t.Helper()

	var hashSize int
	switch cfg.hashAlgo {
	case algo.HashSHA384:
		hashSize = 48
	default:
		hashSize = 32
	}

	certChain, digest, rootDER, leafKey := buildCertChainWithRoot(t, nil, hashSize)

	// Provision our root CA cert so spdm_requester_emu can verify the chain.
	provisionRootCert(t, rootDER)

	listener, err := net.Listen("tcp", "127.0.0.1:2323")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	rspCfg := responder.Config{
		Versions:         []algo.Version{algo.Version12},
		Crypto:           *newCryptoSuite(leafKey),
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
	return runSessionResponderLoop(t, listener, goRsp)
}

// provisionRootCert writes the root CA DER to the spdm-emu bin directory
// so that spdm_requester_emu can verify the responder's cert chain.
func provisionRootCert(t *testing.T, rootDER []byte) {
	t.Helper()
	certPath := *spdmEmuBin + "/ecp256/ca.cert.der"
	// Back up original cert if it exists.
	origData, err := os.ReadFile(certPath)
	if err == nil {
		t.Cleanup(func() { _ = os.WriteFile(certPath, origData, 0644) })
	}
	require.NoError(t, os.WriteFile(certPath, rootDER, 0644))
}

// runSessionResponderLoop handles the spdm-emu protocol including secured
// message decryption/encryption for session operations.
// It accepts multiple connections because spdm_requester_emu disconnects
// after VCA and reconnects for the session phase.
func runSessionResponderLoop(t *testing.T, listener net.Listener, goRsp *responder.Responder) chan error {
	t.Helper()
	serverErr := make(chan error, 1)
	ready := make(chan struct{})
	go func() {
		close(ready)
		for {
			conn, err := listener.Accept()
			if err != nil {
				serverErr <- fmt.Errorf("accept: %w", err)
				return
			}

			shutdown, srvErr := handleSessionConnection(conn, goRsp)
			conn.Close()
			if srvErr != nil {
				serverErr <- srvErr
				return
			}
			if shutdown {
				serverErr <- nil
				return
			}
			// spdm_requester_emu disconnected; accept next connection.
		}
	}()
	<-ready
	return serverErr
}

// handleSecuredMessage decrypts an incoming secured SPDM message, processes it
// via the responder, encrypts the response, and sends it back.
func handleSecuredMessage(
	et *EmuTransport,
	goRsp *responder.Responder,
	spdmData []byte,
) error {
	if len(spdmData) < 8 {
		return fmt.Errorf("secured message too short: %d", len(spdmData))
	}
	sessID := session.SessionID(le.Uint32(spdmData[:4]))

	sess := goRsp.GetSession(sessID)
	if sess == nil {
		return fmt.Errorf("session 0x%08X not found", sessID)
	}

	// Set the active session so handlers (e.g. KEY_UPDATE) can access it.
	goRsp.SetActiveSession(sessID)

	reqSeq, err := sess.NextReqSeqNum()
	if err != nil {
		return fmt.Errorf("seq num: %w", err)
	}

	_, plaintext, err := session.DecodeSecuredMessage(
		sess.AEAD,
		sess.DataKeys.RequestKey,
		sess.DataKeys.RequestIV,
		reqSeq,
		true, // encryptionRequired
		spdmData,
		2, // MCTP seqNumSize
	)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	// The decrypted payload is [MCTPtype][SPDM data]; strip the MCTP type byte.
	if len(plaintext) < 2 {
		return fmt.Errorf("decrypted payload too short: %d", len(plaintext))
	}
	resp, err := goRsp.ProcessMessage(context.Background(), plaintext[1:])
	if err != nil {
		return fmt.Errorf("process: %w", err)
	}

	if err := sendSecuredResponse(et, sess, resp); err != nil {
		return err
	}

	// Complete deferred response key update after sending the ACK.
	if sess.PendingResponseKeyUpdate {
		sess.PendingResponseKeyUpdate = false
		newHash := func() hash.Hash { return sess.HashAlgo.CryptoHash().New() }
		if err := sess.UpdateResponseKeys(newHash); err != nil {
			return fmt.Errorf("deferred response key update: %w", err)
		}
	}
	return nil
}

// sendSecuredResponse encrypts and sends a response over a secured session.
func sendSecuredResponse(
	et *EmuTransport,
	sess *session.Session,
	resp []byte,
) error {
	rspSeqNum, err := sess.NextRspSeqNum()
	if err != nil {
		return fmt.Errorf("rsp seq num: %w", err)
	}

	// Prepend SPDM MCTP type byte to app message before encryption.
	appMsg := append([]byte{mctp.MCTPMessageTypeSPDM}, resp...)
	secured, err := session.EncodeSecuredMessage(
		sess.AEAD,
		sess.DataKeys.ResponseKey,
		sess.DataKeys.ResponseIV,
		rspSeqNum,
		uint32(sess.ID),
		appMsg,
		true, // encryptionRequired
		2,    // MCTP seqNumSize
	)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	// Prepend secured SPDM MCTP type byte.
	mctpResp := append([]byte{mctp.MCTPMessageTypeSecuredSPDM}, secured...)
	if err := et.Conn().SendCommand(qemusock.CommandNormal, mctpResp); err != nil {
		return fmt.Errorf("send secured: %w", err)
	}
	return nil
}

// handlePlainMessage processes a plain SPDM message and sends the response.
func handlePlainMessage(
	et *EmuTransport,
	goRsp *responder.Responder,
	spdmData []byte,
) error {
	resp, err := goRsp.ProcessMessage(context.Background(), spdmData)
	if err != nil {
		return fmt.Errorf("process: %w", err)
	}
	mctpResp := append([]byte{mctp.MCTPMessageTypeSPDM}, resp...)
	if err := et.Conn().SendCommand(qemusock.CommandNormal, mctpResp); err != nil {
		return fmt.Errorf("send: %w", err)
	}
	return nil
}

// handleSessionConnection processes one spdm-emu MCTP connection, returning
// whether SHUTDOWN was received and any error.
// With MCTP transport, the socket payload is [MCTP_type][SPDM_data] where
// MCTP_type 0x05 = plain SPDM, 0x06 = secured SPDM.
func handleSessionConnection(conn net.Conn, goRsp *responder.Responder) (shutdown bool, err error) {
	et := NewEmuTransport(conn, qemusock.TransportMCTP)
	for {
		cmd, payload, err := et.Conn().RecvCommand()
		if err != nil {
			// EOF means the requester disconnected gracefully (e.g., after VCA
			// before reconnecting for session phase). Not an error.
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return false, nil
			}
			return false, fmt.Errorf("recv: %w", err)
		}
		switch cmd {
		case qemusock.CommandTest:
			if err := et.Conn().SendCommand(qemusock.CommandTest, nil); err != nil {
				return false, fmt.Errorf("send test ack: %w", err)
			}
			continue
		case qemusock.CommandShutdown:
			_ = et.Conn().SendCommand(qemusock.CommandShutdown, nil)
			return true, nil
		case qemusock.CommandNormal:
		default:
			return false, fmt.Errorf("unknown command: 0x%04x", cmd)
		}
		if len(payload) < 2 {
			continue
		}

		mctpType := payload[0]
		spdmData := payload[1:]

		var msgErr error
		if mctpType == mctp.MCTPMessageTypeSecuredSPDM {
			msgErr = handleSecuredMessage(et, goRsp, spdmData)
		} else {
			msgErr = handlePlainMessage(et, goRsp, spdmData)
		}
		if msgErr != nil {
			return false, msgErr
		}
	}
}

// emuProtocolTransport wraps EmuTransport to handle spdm-emu TEST/SHUTDOWN
// commands transparently, making it suitable for use with Responder.Serve().
type emuProtocolTransport struct {
	et *EmuTransport
}

func (t *emuProtocolTransport) SendMessage(ctx context.Context, sessionID *uint32, msg []byte) error {
	return t.et.SendMessage(ctx, sessionID, msg)
}

func (t *emuProtocolTransport) ReceiveMessage(ctx context.Context) (*uint32, []byte, error) {
	return t.et.ReceiveMessageHandlingEmuProtocol(ctx)
}

func (t *emuProtocolTransport) HeaderSize() int { return t.et.HeaderSize() }

// newCryptoSuite creates a crypto.Suite from a signer.
func newCryptoSuite(signer crypto.Signer) *spdmcrypto.Suite {
	return stdlib.NewSuite(signer, nil)
}
