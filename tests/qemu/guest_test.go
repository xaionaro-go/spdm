//go:build qemu

package qemu

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// buildGuestBinary builds cmd/spdm-requester as a static Linux amd64 binary
// and returns the path to the resulting executable.
func buildGuestBinary(
	t *testing.T,
) string {
	t.Helper()

	outDir := t.TempDir()
	outPath := filepath.Join(outDir, "init")

	cmd := exec.Command(
		"go", "build",
		"-o", outPath,
		"./cmd/spdm-requester",
	)
	cmd.Env = append(cmd.Environ(),
		"CGO_ENABLED=0",
		"GOOS=linux",
		"GOARCH=amd64",
	)
	// Build from the module root so Go can find go.mod.
	cmd.Dir = moduleRoot(t)

	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "building guest binary: %s", string(output))

	t.Logf("built guest binary: %s", outPath)
	return outPath
}

// moduleRoot returns the module root directory by running `go env GOMOD`
// and returning the directory containing go.mod.
func moduleRoot(
	t *testing.T,
) string {
	t.Helper()

	cmd := exec.Command("go", "env", "GOMOD")
	output, err := cmd.Output()
	require.NoError(t, err, "running go env GOMOD")

	gomod := filepath.Dir(strings.TrimSpace(string(output)))
	require.NotEmpty(t, gomod, "go.mod not found")

	return gomod
}
