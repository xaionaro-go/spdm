//go:build reference

package interop

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/xaionaro-go/spdm/pkg/transport/qemusock"
)

// EmuProcess manages a spdm-emu responder process.
type EmuProcess struct {
	cmd    *exec.Cmd
	binDir string
	port   int
}

// StartResponder starts spdm_responder_emu with the given configuration.
// The emu responder accepts exactly one client connection, so we must not
// probe the port — doing so consumes the single accept slot.
func StartResponder(binDir string, port int, args ...string) (*EmuProcess, error) {
	responderBin := filepath.Join(binDir, "spdm_responder_emu")
	if _, err := os.Stat(responderBin); err != nil {
		return nil, fmt.Errorf("responder binary not found at %s: %w", responderBin, err)
	}

	defaultArgs := []string{
		"--trans", "NONE",
	}
	allArgs := append(defaultArgs, args...)

	cmd := exec.Command(responderBin, allArgs...)
	cmd.Dir = binDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start responder: %w", err)
	}

	ep := &EmuProcess{
		cmd:    cmd,
		binDir: binDir,
		port:   port,
	}

	return ep, nil
}

// Connect dials the spdm-emu responder with retries, returning an EmuTransport.
// This replaces the separate waitForReady + Connect pattern to avoid consuming
// the server's single accept slot with a probe connection.
func (ep *EmuProcess) Connect() (*EmuTransport, error) {
	conn, err := ep.dialWithRetry()
	if err != nil {
		return nil, err
	}
	return NewEmuTransport(conn, qemusock.TransportNone), nil
}

// ConnectRaw dials the spdm-emu responder with retries, returning the raw
// net.Conn for use with transport bridges.
func (ep *EmuProcess) ConnectRaw() (net.Conn, error) {
	return ep.dialWithRetry()
}

func (ep *EmuProcess) dialWithRetry() (net.Conn, error) {
	deadline := time.Now().Add(10 * time.Second)
	addr := fmt.Sprintf("127.0.0.1:%d", ep.port)

	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			return conn, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("timeout connecting to responder on %s", addr)
}

// Stop kills the process and waits for it to exit.
func (ep *EmuProcess) Stop() error {
	if ep.cmd.Process != nil {
		_ = ep.cmd.Process.Kill()
		_ = ep.cmd.Wait()
	}
	return nil
}
