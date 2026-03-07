//go:build qemu

package qemu

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHarnessSmoke verifies that the harness infrastructure compiles and
// the basic non-QEMU pieces work: free port finding, NVMe image creation,
// module root resolution, and responder start/stop. The QEMU and kernel
// lookup functions are exercised but allowed to fail (they just report
// availability).
func TestHarnessSmoke(t *testing.T) {
	t.Run("findFreePort", func(t *testing.T) {
		port := findFreePort(t)
		assert.Greater(t, port, 0, "port must be positive")
	})

	t.Run("createNVMeImage", func(t *testing.T) {
		img := createNVMeImage(t)
		require.FileExists(t, img)
	})

	t.Run("moduleRoot", func(t *testing.T) {
		root := moduleRoot(t)
		require.DirExists(t, root)
	})

	t.Run("findQEMU", func(t *testing.T) {
		path, err := findQEMU()
		if err != nil {
			t.Logf("QEMU not available: %v", err)
		} else {
			t.Logf("QEMU found at: %s", path)
		}
	})

	t.Run("findKernel", func(t *testing.T) {
		path, err := findKernel()
		if err != nil {
			t.Logf("kernel not available: %v", err)
		} else {
			t.Logf("kernel found at: %s", path)
		}
	})

	t.Run("startGoResponder", func(t *testing.T) {
		port, cleanup := startGoResponder(t)
		defer cleanup()
		assert.Greater(t, port, 0, "responder port must be positive")
	})

	t.Run("skipIfNoQEMU", func(t *testing.T) {
		// Just verify it does not panic; it may skip the test.
		skipIfNoQEMU(t)
	})

	t.Run("skipIfNoKernel", func(t *testing.T) {
		// Just verify it does not panic; it may skip the test.
		skipIfNoKernel(t)
	})

	t.Run("launchQEMU_signature", func(t *testing.T) {
		// Verify launchQEMU compiles. Actual invocation requires QEMU,
		// kernel, and initramfs, so it is left to the full E2E tests.
		fn := launchQEMU
		_ = fn
	})
}

// TestBuildGuestBinary verifies that the guest binary can be cross-compiled.
// This is separated because it takes a few seconds.
func TestBuildGuestBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping guest binary build in short mode")
	}

	bin := buildGuestBinary(t)
	require.FileExists(t, bin)
}

// TestBuildInitramfs verifies that an initramfs can be created from a
// dummy binary. It does not require building the real guest binary.
func TestBuildInitramfs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping initramfs build in short mode")
	}

	dummyBin := createDummyBinary(t)
	initramfs := buildInitramfs(t, dummyBin)
	require.FileExists(t, initramfs)
}

// createDummyBinary creates a small shell script as a stand-in for testing
// the initramfs builder without needing to compile the full guest binary.
func createDummyBinary(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "dummy-init")
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\necho ok\n"), 0o755))
	return path
}
