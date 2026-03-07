package main

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
	"log"
	"math/big"
	"net"
	"strings"
	"time"

	beltlogger "github.com/facebookincubator/go-belt/tool/logger"
	loggerstdlib "github.com/facebookincubator/go-belt/tool/logger/implementation/stdlib"
	"github.com/facebookincubator/go-belt/tool/logger/types"
	"github.com/xaionaro-go/spdm/pkg/crypto/stdlib"
	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/caps"
	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
	"github.com/xaionaro-go/spdm/pkg/spdm"
	"github.com/xaionaro-go/spdm/pkg/transport"
	"github.com/xaionaro-go/spdm/pkg/transport/pcidoe"
	"github.com/xaionaro-go/spdm/pkg/transport/qemusock"
	"github.com/xaionaro-go/spdm/pkg/transport/tcp"
)

func main() {
	transportFlag := flag.String("transport", "tcp", "transport type: tcp, qemusock")
	listen := flag.String("listen", "127.0.0.1:2323", "listen address")
	version := flag.String("version", "1.2", "SPDM version: 1.2 or 1.3")
	hashAlg := flag.String("hash", "sha256", "hash algorithm")
	asymAlg := flag.String("asym", "ecdsa-p256", "asymmetric algorithm")
	dheGroup := flag.String("dhe", "secp256r1", "DHE group")
	aeadSuite := flag.String("aead", "aes-128-gcm", "AEAD suite")
	verbose := flag.Bool("v", false, "verbose logging")
	flag.Parse()

	ctx := context.Background()
	if *verbose {
		l := loggerstdlib.New(log.Default(), types.LevelTrace)
		ctx = beltlogger.CtxWithLogger(ctx, l)
	}

	switch *transportFlag {
	case "tcp", "qemusock":
	default:
		log.Fatalf("transport %q is not supported; supported: tcp, qemusock", *transportFlag)
	}

	ver := parseVersion(*version)
	hash := parseHash(*hashAlg)
	asym := parseAsym(*asymAlg)
	dhe := parseDHE(*dheGroup)
	aead := parseAEAD(*aeadSuite)

	key, certChainBytes, certPool := generateEphemeralCert()

	suite := stdlib.NewSuite(key, certPool)
	certProv := &staticCertProvider{
		chain:  certChainBytes,
		digest: computeDigest(certChainBytes),
	}
	measProv := &staticMeasurementProvider{}

	rspCaps := caps.RspCertCap | caps.RspChalCap | caps.RspMeasCapNoSig

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", *listen, err)
	}
	defer ln.Close()
	fmt.Printf("SPDM responder listening on %s (transport %s, version %s)\n", *listen, *transportFlag, ver)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		fmt.Printf("Accepted connection from %s\n", conn.RemoteAddr())

		var spdmTransport transport.Transport
		var bridge *qemusock.Bridge
		switch *transportFlag {
		case "tcp":
			spdmTransport = tcp.New(conn)
		case "qemusock":
			bridge = qemusock.NewBridge(conn, qemusock.TransportPCIDOE)
			bridge.Start()
			spdmTransport = pcidoe.New(bridge)
		}

		rsp := spdm.NewResponder(spdm.ResponderConfig{
			Versions:         []algo.Version{ver},
			Transport:        spdmTransport,
			Crypto:           *suite,
			Caps:             rspCaps,
			BaseAsymAlgo:     asym,
			BaseHashAlgo:     hash,
			DHEGroups:        dhe,
			AEADSuites:       aead,
			DataTransferSize: 4096,
			MaxSPDMmsgSize:   65536,
			CertProvider:     certProv,
			MeasProvider:     measProv,
		})

		err = rsp.Serve(ctx)
		if err != nil {
			fmt.Printf("Serve finished: %v\n", err)
		}
		if bridge != nil {
			bridge.Close()
		}
		conn.Close()
	}
}

// generateEphemeralCert creates an ephemeral ECDSA P-256 key and self-signed certificate.
// Returns the private key, the SPDM certificate chain bytes (per DSP0274 Section 10.6.1),
// and a CertPool containing the certificate for validation.
func generateEphemeralCert() (*ecdsa.PrivateKey, []byte, *x509.CertPool) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate ECDSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "spdm-responder-ephemeral"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		log.Fatalf("failed to create certificate: %v", err)
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
		log.Fatalf("failed to parse certificate: %v", err)
	}
	pool.AddCert(cert)

	return key, chainPayload, pool
}

func computeDigest(certChain []byte) []byte {
	h := sha256.Sum256(certChain)
	return h[:]
}

// staticCertProvider provides a single certificate chain in slot 0.
type staticCertProvider struct {
	chain  []byte
	digest []byte
}

func (p *staticCertProvider) CertChain(_ context.Context, slotID uint8) ([]byte, error) {
	if slotID != 0 {
		return nil, fmt.Errorf("slot %d not available", slotID)
	}
	return p.chain, nil
}

func (p *staticCertProvider) DigestForSlot(_ context.Context, slotID uint8) ([]byte, error) {
	if slotID != 0 {
		return nil, fmt.Errorf("slot %d not available", slotID)
	}
	return p.digest, nil
}

// staticMeasurementProvider provides a single dummy measurement block.
type staticMeasurementProvider struct{}

func (p *staticMeasurementProvider) Collect(_ context.Context, index uint8) ([]msgs.MeasurementBlock, error) {
	return []msgs.MeasurementBlock{
		{
			Index:     1,
			Spec:      0x01, // DMTF
			ValueType: 0x00, // immutable ROM
			Value:     []byte("spdm-responder-measurement-v1"),
		},
	}, nil
}

func (p *staticMeasurementProvider) SummaryHash(_ context.Context, _ uint8) ([]byte, error) {
	return make([]byte, 32), nil
}

func parseVersion(s string) algo.Version {
	switch s {
	case "1.2":
		return algo.Version12
	case "1.3":
		return algo.Version13
	default:
		log.Fatalf("unsupported SPDM version: %s (supported: 1.2, 1.3)", s)
		return 0
	}
}

func parseHash(s string) algo.BaseHashAlgo {
	switch strings.ToLower(s) {
	case "sha256", "sha-256":
		return algo.HashSHA256
	case "sha384", "sha-384":
		return algo.HashSHA384
	case "sha512", "sha-512":
		return algo.HashSHA512
	case "sha3-256":
		return algo.HashSHA3_256
	case "sha3-384":
		return algo.HashSHA3_384
	case "sha3-512":
		return algo.HashSHA3_512
	default:
		log.Fatalf("unsupported hash algorithm: %s", s)
		return 0
	}
}

func parseAsym(s string) algo.BaseAsymAlgo {
	switch strings.ToLower(s) {
	case "ecdsa-p256":
		return algo.AsymECDSAP256
	case "ecdsa-p384":
		return algo.AsymECDSAP384
	case "ecdsa-p521":
		return algo.AsymECDSAP521
	case "rsassa-2048":
		return algo.AsymRSASSA2048
	case "rsapss-2048":
		return algo.AsymRSAPSS2048
	case "rsassa-3072":
		return algo.AsymRSASSA3072
	case "rsapss-3072":
		return algo.AsymRSAPSS3072
	case "rsassa-4096":
		return algo.AsymRSASSA4096
	case "rsapss-4096":
		return algo.AsymRSAPSS4096
	case "eddsa-ed25519", "ed25519":
		return algo.AsymEdDSAEd25519
	case "eddsa-ed448", "ed448":
		return algo.AsymEdDSAEd448
	default:
		log.Fatalf("unsupported asymmetric algorithm: %s", s)
		return 0
	}
}

func parseDHE(s string) algo.DHENamedGroup {
	switch strings.ToLower(s) {
	case "secp256r1":
		return algo.DHESECP256R1
	case "secp384r1":
		return algo.DHESECP384R1
	case "secp521r1":
		return algo.DHESECP521R1
	case "ffdhe2048":
		return algo.DHEFFDHE2048
	case "ffdhe3072":
		return algo.DHEFFDHE3072
	case "ffdhe4096":
		return algo.DHEFFDHE4096
	default:
		log.Fatalf("unsupported DHE group: %s", s)
		return 0
	}
}

func parseAEAD(s string) algo.AEADCipherSuite {
	switch strings.ToLower(s) {
	case "aes-128-gcm":
		return algo.AEADAES128GCM
	case "aes-256-gcm":
		return algo.AEADAES256GCM
	case "chacha20-poly1305":
		return algo.AEADChaCha20Poly1305
	default:
		log.Fatalf("unsupported AEAD suite: %s", s)
		return 0
	}
}
