package testutil

import (
	"testing"

	"github.com/xaionaro-go/spdm/pkg/gen/msgs"
)

// MustMarshal marshals m and fails the test on error.
func MustMarshal(t *testing.T, m msgs.Message) []byte {
	t.Helper()
	data, err := m.Marshal()
	if err != nil {
		t.Fatalf("MustMarshal: %v", err)
	}
	return data
}

// MustUnmarshal unmarshals data into m and fails the test on error.
func MustUnmarshal(t *testing.T, data []byte, m msgs.Message) {
	t.Helper()
	if err := m.Unmarshal(data); err != nil {
		t.Fatalf("MustUnmarshal: %v", err)
	}
}
