//go:build qemu

package qemu

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// emuProcess manages a spdm-emu responder process started for QEMU E2E tests.
type emuProcess struct {
	cmd *exec.Cmd
}

// startEmuResponder starts spdm_responder_emu with --trans PCI_DOE on the
// given port (via the SPDM_PORT environment variable). It returns a handle
// that the caller must Stop() when done.
//
// The function waits briefly for the responder to begin listening before
// returning, but does not probe the port (spdm-emu accepts a single
// connection, so probing would consume that slot).
func startEmuResponder(
	t *testing.T,
	emuBin string,
	port int,
) *emuProcess {
	t.Helper()

	responderBin := filepath.Join(emuBin, "spdm_responder_emu")
	if _, err := os.Stat(responderBin); err != nil {
		t.Fatalf("spdm_responder_emu not found at %s: %v", responderBin, err)
	}

	cmd := exec.Command(responderBin,
		"--trans", "PCI_DOE",
	)
	cmd.Dir = emuBin
	cmd.Env = append(os.Environ(), fmt.Sprintf("SPDM_PORT=%d", port))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("starting spdm_responder_emu: %v", err)
	}

	// Give the responder a moment to bind its listening socket.
	// We cannot dial-probe because spdm-emu accepts only a single connection.
	time.Sleep(500 * time.Millisecond)

	return &emuProcess{cmd: cmd}
}

// Stop kills the spdm-emu process and waits for it to exit.
func (p *emuProcess) Stop() {
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		_ = p.cmd.Wait()
	}
}
