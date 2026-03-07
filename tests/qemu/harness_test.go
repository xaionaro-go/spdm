//go:build qemu

package qemu

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// QEMUConfig holds the parameters for launching a QEMU instance.
type QEMUConfig struct {
	Kernel    string
	Initramfs string
	NVMeImage string
	SPDMPort  int
	Timeout   time.Duration
	InitArgs  string // extra arguments passed to /init via kernel command line (after --)
}

// launchQEMU starts a QEMU process with the given configuration and waits
// for it to finish (or timeout). It returns the combined serial output.
func launchQEMU(
	t *testing.T,
	cfg QEMUConfig,
) (string, error) {
	t.Helper()

	qemuBin, err := findQEMU()
	if err != nil {
		return "", fmt.Errorf("finding QEMU: %w", err)
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}

	args := []string{
		"-M", "q35",
		"-nographic",
		"-no-reboot",
		"-kernel", cfg.Kernel,
		"-initrd", cfg.Initramfs,
		"-append", buildAppendString(cfg),
		"-drive", fmt.Sprintf("file=%s,if=none,id=nvme0,format=raw", cfg.NVMeImage),
		"-device", fmt.Sprintf("nvme,drive=nvme0,serial=test,spdm_port=%d", cfg.SPDMPort),
		"-m", "256",
	}

	if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err == nil {
		f.Close()
		args = append(args, "-enable-kvm")
	}

	t.Logf("launching QEMU: %s %s", qemuBin, strings.Join(args, " "))

	cmd := exec.Command(qemuBin, args...)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("starting QEMU: %w", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		serial := output.String()
		if err != nil {
			return serial, fmt.Errorf("QEMU exited with error: %w\noutput:\n%s", err, serial)
		}
		return serial, nil
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		return output.String(), fmt.Errorf("QEMU timed out after %s", timeout)
	}
}

// buildAppendString constructs the kernel -append value. If cfg.InitArgs
// is set, the arguments are appended after the "--" separator so the kernel
// passes them to /init.
func buildAppendString(cfg QEMUConfig) string {
	s := "console=ttyS0 panic=-1"
	if cfg.InitArgs != "" {
		s += " -- " + cfg.InitArgs
	}
	return s
}

// findQEMU locates the QEMU binary. It checks the QEMU_PATH environment
// variable first, then looks for qemu-system-x86_64 in PATH.
func findQEMU() (string, error) {
	if p := os.Getenv("QEMU_PATH"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
		return "", fmt.Errorf("QEMU_PATH=%q does not exist", p)
	}

	p, err := exec.LookPath("qemu-system-x86_64")
	if err != nil {
		return "", fmt.Errorf("qemu-system-x86_64 not found in PATH: %w", err)
	}
	return p, nil
}

// findKernel locates a Linux kernel image for booting QEMU. It checks the
// QEMU_TEST_KERNEL environment variable first, then scans /boot/vmlinuz-*.
func findKernel() (string, error) {
	if p := os.Getenv("QEMU_TEST_KERNEL"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
		return "", fmt.Errorf("QEMU_TEST_KERNEL=%q does not exist", p)
	}

	matches, err := filepath.Glob("/boot/vmlinuz-*")
	if err != nil {
		return "", fmt.Errorf("globbing /boot/vmlinuz-*: %w", err)
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("no /boot/vmlinuz-* kernel images found")
	}

	// Sort lexicographically and pick the last one (typically the latest version).
	sort.Strings(matches)
	return matches[len(matches)-1], nil
}

// createNVMeImage creates a 1MB empty file for use as NVMe backing storage.
func createNVMeImage(
	t *testing.T,
) string {
	t.Helper()

	imgPath := filepath.Join(t.TempDir(), "nvme.img")
	f, err := os.Create(imgPath)
	require.NoError(t, err, "creating NVMe image")

	require.NoError(t, f.Truncate(1<<20), "truncating NVMe image to 1MB")
	require.NoError(t, f.Close(), "closing NVMe image")

	return imgPath
}

// skipIfNoQEMU skips the test if QEMU is not available.
func skipIfNoQEMU(t *testing.T) {
	t.Helper()

	if _, err := findQEMU(); err != nil {
		t.Skipf("QEMU not available: %v", err)
	}
}

// skipIfNoKernel skips the test if no kernel image is available.
func skipIfNoKernel(t *testing.T) {
	t.Helper()

	if _, err := findKernel(); err != nil {
		t.Skipf("kernel not available: %v", err)
	}
}
