//go:build qemu

package qemu

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestQEMU_GoRequester_GoResponder boots a QEMU VM with an NVMe device
// that has SPDM DOE support. The Go spdm-requester runs as the guest's
// init process, talks PCI DOE through the emulated NVMe's DOE mailbox.
// On the host side, a Go SPDM responder handles the requests via the
// QEMU socket protocol.
func TestQEMU_GoRequester_GoResponder(t *testing.T) {
	skipIfNoQEMU(t)
	skipIfNoKernel(t)
	skipIfNoSPDMSupport(t)

	guestBin := buildGuestBinary(t)
	initramfs := buildInitramfs(t, guestBin)

	port, cleanup := startGoResponder(t)
	defer cleanup()

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
