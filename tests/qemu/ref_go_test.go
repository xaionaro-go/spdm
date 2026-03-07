//go:build qemu

package qemu

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestQEMU_RefRequester_GoResponder runs the DMTF spdm-emu reference
// requester against our Go SPDM responder via the QEMU socket protocol
// with PCI DOE transport framing.
//
// The test is skipped unless the SPDM_EMU_BIN environment variable
// points to the directory containing spdm_requester_emu.
func TestQEMU_RefRequester_GoResponder(t *testing.T) {
	emuBin := os.Getenv("SPDM_EMU_BIN")
	if emuBin == "" {
		t.Skip("SPDM_EMU_BIN not set; skipping reference requester test")
	}

	requesterPath := filepath.Join(emuBin, "spdm_requester_emu")
	if _, err := os.Stat(requesterPath); err != nil {
		t.Skipf("spdm_requester_emu not found at %s", requesterPath)
	}

	port, cleanup := startGoResponder(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, requesterPath,
		"--trans", "PCI_DOE",
		"--exe_conn", "NONE",
		"--pcap", "null",
	)
	cmd.Dir = emuBin
	cmd.Env = append(os.Environ(), fmt.Sprintf("SPDM_PORT=%d", port))

	output, err := cmd.CombinedOutput()
	t.Logf("spdm_requester_emu output:\n%s", string(output))
	require.NoError(t, err, "spdm_requester_emu failed")
}
