package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"syscall"

	beltlogger "github.com/facebookincubator/go-belt/tool/logger"
	loggerstdlib "github.com/facebookincubator/go-belt/tool/logger/implementation/stdlib"
	"github.com/facebookincubator/go-belt/tool/logger/types"
	"github.com/xaionaro-go/spdm/pkg/crypto/stdlib"
	"github.com/xaionaro-go/spdm/pkg/gen/algo"
	"github.com/xaionaro-go/spdm/pkg/gen/caps"
	"github.com/xaionaro-go/spdm/pkg/spdm"
	"github.com/xaionaro-go/spdm/pkg/transport"
	"github.com/xaionaro-go/spdm/pkg/transport/pcidoe"
	"github.com/xaionaro-go/spdm/pkg/transport/qemusock"
	"github.com/xaionaro-go/spdm/pkg/transport/tcp"
)

// setupInitEnvironment prepares the environment when running as PID 1
// (init process inside a QEMU guest). It mounts essential filesystems
// required for PCI device discovery and registers a deferred poweroff.
func setupInitEnvironment() {
	if os.Getpid() != 1 {
		return
	}

	mounts := []struct {
		source string
		target string
		fstype string
	}{
		{"proc", "/proc", "proc"},
		{"sysfs", "/sys", "sysfs"},
		{"devtmpfs", "/dev", "devtmpfs"},
	}

	for _, m := range mounts {
		if err := os.MkdirAll(m.target, 0o755); err != nil {
			log.Printf("warning: mkdir %s: %v", m.target, err)
			continue
		}
		if err := syscall.Mount(m.source, m.target, m.fstype, 0, ""); err != nil {
			log.Printf("warning: mount %s on %s: %v", m.fstype, m.target, err)
		}
	}
}

// powerOffIfInit powers off the VM when running as PID 1.
func powerOffIfInit() {
	if os.Getpid() != 1 {
		return
	}
	_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
}

// createTransport creates the appropriate transport based on the transport
// type flag. It returns the transport, an io.Closer for cleanup, and any error.
func createTransport(
	transportType string,
	addr string,
	pciAddr string,
) (transport.Transport, io.Closer, error) {
	switch transportType {
	case "tcp":
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to connect to %s: %w", addr, err)
		}
		return tcp.New(conn), conn, nil

	case "qemusock":
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to connect to %s: %w", addr, err)
		}
		bridge := qemusock.NewBridge(conn, qemusock.TransportPCIDOE)
		bridge.Start()
		return pcidoe.New(bridge), closerFunc(func() error {
			bridge.Close()
			return conn.Close()
		}), nil

	case "pcidoe":
		var (
			configPath string
			capOffset  int
		)
		if pciAddr == "auto" {
			var err error
			configPath, capOffset, err = pcidoe.FindDOEDevice()
			if err != nil {
				return nil, nil, fmt.Errorf("auto-discover DOE device: %w", err)
			}
			fmt.Printf("Discovered DOE device: %s (capability offset 0x%X)\n", configPath, capOffset)
		} else {
			configPath = fmt.Sprintf("/sys/bus/pci/devices/%s/config", pciAddr)
			f, err := os.OpenFile(configPath, os.O_RDWR, 0)
			if err != nil {
				return nil, nil, fmt.Errorf("open PCI config space %s: %w", configPath, err)
			}
			offset, err := pcidoe.FindDOECapability(f)
			if err != nil {
				f.Close()
				return nil, nil, fmt.Errorf("find DOE capability in %s: %w", configPath, err)
			}
			capOffset = offset
			f.Close()
		}

		f, err := os.OpenFile(configPath, os.O_RDWR, 0)
		if err != nil {
			return nil, nil, fmt.Errorf("open PCI config space %s: %w", configPath, err)
		}
		mailboxConn := pcidoe.NewMailboxConn(f, uint32(capOffset))
		return pcidoe.New(mailboxConn), f, nil

	default:
		return nil, nil, fmt.Errorf("unsupported transport type: %s (supported: tcp, qemusock, pcidoe)", transportType)
	}
}

// closerFunc adapts a function into an io.Closer.
type closerFunc func() error

func (f closerFunc) Close() error { return f() }

func main() {
	setupInitEnvironment()
	defer powerOffIfInit()

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcommand := os.Args[1]
	fs := flag.NewFlagSet(subcommand, flag.ExitOnError)

	transportType := fs.String("transport", "tcp", "transport type: tcp, qemusock, pcidoe")
	addr := fs.String("addr", "127.0.0.1:2323", "remote address (for tcp and qemusock)")
	pciAddr := fs.String("pci-addr", "auto", "PCI BDF address (e.g. 0000:00:05.0) or \"auto\" to discover")
	version := fs.String("version", "1.2", "SPDM version: 1.2 or 1.3")
	hashAlg := fs.String("hash", "sha256", "hash algorithm")
	asymAlg := fs.String("asym", "ecdsa-p256", "asymmetric algorithm")
	dheGroup := fs.String("dhe", "secp256r1", "DHE group")
	aeadSuite := fs.String("aead", "aes-128-gcm", "AEAD suite")
	verbose := fs.Bool("v", false, "verbose logging")

	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	if *verbose {
		l := loggerstdlib.New(log.Default(), types.LevelTrace)
		ctx = beltlogger.CtxWithLogger(ctx, l)
	}

	ver := parseVersion(*version)
	hash := parseHash(*hashAlg)
	asym := parseAsym(*asymAlg)
	dhe := parseDHE(*dheGroup)
	aead := parseAEAD(*aeadSuite)

	t, closer, err := createTransport(*transportType, *addr, *pciAddr)
	if err != nil {
		log.Fatalf("failed to create transport: %v", err)
	}
	defer closer.Close()

	suite := stdlib.NewSuite(nil, nil)

	reqCfg := spdm.RequesterConfig{
		Versions:         []algo.Version{ver},
		Transport:        t,
		Crypto:           *suite,
		Caps:             caps.ReqCertCap | caps.ReqChalCap,
		BaseAsymAlgo:     asym,
		BaseHashAlgo:     hash,
		DHEGroups:        dhe,
		AEADSuites:       aead,
		DataTransferSize: 4096,
		MaxSPDMmsgSize:   65536,
	}

	req := spdm.NewRequester(reqCfg)

	switch subcommand {
	case "connect":
		runConnect(ctx, req)
	case "get-digests":
		runGetDigests(ctx, req)
	case "get-cert":
		runGetCert(ctx, req)
	case "challenge":
		runChallenge(ctx, req)
	case "get-meas":
		runGetMeasurements(ctx, req)
	default:
		log.Fatalf("unknown subcommand: %s", subcommand)
	}

	if *transportType == "pcidoe" {
		fmt.Println("SPDM_DOE_TEST: PASS")
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: spdm-requester <subcommand> [flags]\n\n")
	fmt.Fprintf(os.Stderr, "Subcommands:\n")
	fmt.Fprintf(os.Stderr, "  connect      Perform VCA negotiation, print negotiated params\n")
	fmt.Fprintf(os.Stderr, "  get-digests  Connect + get digests, print slot info\n")
	fmt.Fprintf(os.Stderr, "  get-cert     Connect + get certificate chain from slot 0\n")
	fmt.Fprintf(os.Stderr, "  challenge    Connect + get-digests + get-cert + challenge\n")
	fmt.Fprintf(os.Stderr, "  get-meas     Connect + get measurements\n")
}

func runConnect(ctx context.Context, req *spdm.Requester) {
	ci, err := req.InitConnection(ctx)
	if err != nil {
		log.Fatalf("InitConnection failed: %v", err)
	}

	fmt.Println("Connection established:")
	fmt.Printf("  Version:   %s\n", ci.Version)
	fmt.Printf("  Hash:      %s\n", ci.HashAlgo)
	fmt.Printf("  Asymmetric: %s\n", ci.AsymAlgo)
	fmt.Printf("  DHE:       %s\n", ci.DHEGroup)
	fmt.Printf("  AEAD:      %s\n", ci.AEADSuite)
	fmt.Printf("  Peer caps: %s\n", ci.PeerCaps)
}

func runGetDigests(ctx context.Context, req *spdm.Requester) {
	ci, err := req.InitConnection(ctx)
	if err != nil {
		log.Fatalf("InitConnection failed: %v", err)
	}
	fmt.Printf("Connected (version %s)\n", ci.Version)

	digests, err := req.GetDigests(ctx)
	if err != nil {
		log.Fatalf("GetDigests failed: %v", err)
	}

	fmt.Printf("Digests (slot mask: 0x%02X):\n", digests.SlotMask)
	for i, d := range digests.Digests {
		fmt.Printf("  Slot %d: %s\n", i, hex.EncodeToString(d))
	}
}

func runGetCert(ctx context.Context, req *spdm.Requester) {
	ci, err := req.InitConnection(ctx)
	if err != nil {
		log.Fatalf("InitConnection failed: %v", err)
	}
	fmt.Printf("Connected (version %s)\n", ci.Version)

	cert, err := req.GetCertificate(ctx, 0)
	if err != nil {
		log.Fatalf("GetCertificate failed: %v", err)
	}

	fmt.Printf("Certificate chain from slot %d (%d bytes):\n", cert.SlotID, len(cert.Chain))
	fmt.Println(hex.Dump(cert.Chain))
}

func runChallenge(ctx context.Context, req *spdm.Requester) {
	ci, err := req.InitConnection(ctx)
	if err != nil {
		log.Fatalf("InitConnection failed: %v", err)
	}
	fmt.Printf("Connected (version %s)\n", ci.Version)

	digests, err := req.GetDigests(ctx)
	if err != nil {
		log.Fatalf("GetDigests failed: %v", err)
	}
	fmt.Printf("Got digests (slot mask: 0x%02X)\n", digests.SlotMask)

	cert, err := req.GetCertificate(ctx, 0)
	if err != nil {
		log.Fatalf("GetCertificate failed: %v", err)
	}
	fmt.Printf("Got certificate chain from slot %d (%d bytes)\n", cert.SlotID, len(cert.Chain))

	result, err := req.Challenge(ctx, 0)
	if err != nil {
		log.Fatalf("Challenge failed: %v", err)
	}
	fmt.Printf("Challenge succeeded for slot %d\n", result.SlotID)
}

func runGetMeasurements(ctx context.Context, req *spdm.Requester) {
	ci, err := req.InitConnection(ctx)
	if err != nil {
		log.Fatalf("InitConnection failed: %v", err)
	}
	fmt.Printf("Connected (version %s)\n", ci.Version)

	meas, err := req.GetMeasurements(ctx, spdm.MeasurementOpts{
		Index:            0xFF, // all measurements
		RequestSignature: false,
	})
	if err != nil {
		log.Fatalf("GetMeasurements failed: %v", err)
	}

	fmt.Printf("Measurements: %d block(s)\n", meas.NumberOfBlocks)
	for i, b := range meas.Blocks {
		fmt.Printf("  Block %d: index=%d, spec=0x%02X, valueType=0x%02X, size=%d\n",
			i, b.Index, b.Spec, b.ValueType, len(b.Value))
	}
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
