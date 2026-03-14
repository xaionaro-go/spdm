//go:build qemu

package qemu

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestQEMU_GoRequester_RefResponder boots a QEMU VM with an NVMe device
// that has SPDM DOE support. The Go spdm-requester runs as the guest's
// init process and talks PCI DOE through the emulated NVMe's DOE mailbox.
// On the host side, the DMTF spdm-emu reference responder handles the
// requests via the shared SPDM socket protocol.
//
// The test is skipped unless SPDM_EMU_BIN points to the directory
// containing spdm_responder_emu.
func TestQEMU_GoRequester_RefResponder(t *testing.T) {
	skipIfNoQEMU(t)
	skipIfNoKernel(t)
	skipIfNoSPDMSupport(t)

	emuBin := os.Getenv("SPDM_EMU_BIN")
	if emuBin == "" {
		t.Skip("SPDM_EMU_BIN not set; skipping reference responder test")
	}

	responderPath := filepath.Join(emuBin, "spdm_responder_emu")
	if _, err := os.Stat(responderPath); err != nil {
		t.Skipf("spdm_responder_emu not found at %s", responderPath)
	}

	port := findFreePort(t)
	proc := startEmuResponder(t, emuBin, port)
	defer proc.Stop()

	guestBin := buildGuestBinary(t)
	initramfs := buildInitramfs(t, guestBin)
	nvmeImg := createNVMeImage(t)

	kernelPath, err := findKernel()
	require.NoError(t, err)

	output, err := launchQEMU(t, QEMUConfig{
		Kernel:    kernelPath,
		Initramfs: initramfs,
		NVMeImage: nvmeImg,
		SPDMPort:  port,
		InitArgs:  "connect -transport pcidoe -v",
	})
	t.Logf("QEMU output:\n%s", output)
	require.NoError(t, err)

	assert.Contains(t, output, "SPDM_DOE_TEST: PASS")
}
