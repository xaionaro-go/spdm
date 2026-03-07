//go:build qemu

package qemu

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// buildInitramfs creates a cpio.gz initramfs archive containing the given
// binary as /init (mode 0755) plus empty /sys, /proc, /dev directories.
// It shells out to cpio(1) and gzip(1); the test is skipped if cpio is
// not available.
func buildInitramfs(
	t *testing.T,
	binaryPath string,
) string {
	t.Helper()

	if _, err := exec.LookPath("cpio"); err != nil {
		t.Skip("cpio not found in PATH; skipping initramfs build")
	}

	tmpDir := t.TempDir()
	initDir := filepath.Join(tmpDir, "initdir")

	for _, dir := range []string{"sys", "proc", "dev"} {
		require.NoError(t, os.MkdirAll(filepath.Join(initDir, dir), 0o755))
	}

	initPath := filepath.Join(initDir, "init")
	srcData, err := os.ReadFile(binaryPath)
	require.NoError(t, err, "reading guest binary")
	require.NoError(t, os.WriteFile(initPath, srcData, 0o755), "writing init binary")

	outPath := filepath.Join(tmpDir, "initramfs.cpio.gz")

	// Use a shell pipeline: find . | cpio -o -H newc | gzip > outPath
	cmd := exec.Command(
		"sh", "-c",
		"cd "+initDir+" && find . | cpio -o --quiet -H newc | gzip > "+outPath,
	)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "building initramfs: %s", string(output))

	info, err := os.Stat(outPath)
	require.NoError(t, err, "stat initramfs")
	require.Greater(t, info.Size(), int64(0), "initramfs must not be empty")

	t.Logf("built initramfs: %s (%d bytes)", outPath, info.Size())
	return outPath
}
