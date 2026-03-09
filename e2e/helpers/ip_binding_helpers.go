//go:build e2e

package helpers

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// --- IP Binding Policy Helpers ---

var ipBindingRe = regexp.MustCompile(`ip_binding_policy\s*=\s*"[^"]*"`)

// SetIPBindingPolicy modifies all 3 node configs to use the given policy,
// restarts the cluster, and waits for it to become healthy.
func SetIPBindingPolicy(t *testing.T, policy string) {
	t.Helper()
	replacement := fmt.Sprintf(`ip_binding_policy = "%s"`, policy)
	configsDir := filepath.Join(E2EDir(), "configs")

	for i := 1; i <= 3; i++ {
		cfgPath := filepath.Join(configsDir, fmt.Sprintf("node%d.hcl", i))
		data, err := os.ReadFile(cfgPath)
		if err != nil {
			t.Fatalf("failed to read %s: %v", cfgPath, err)
		}
		updated := ipBindingRe.ReplaceAll(data, []byte(replacement))
		if err := os.WriteFile(cfgPath, updated, 0o644); err != nil {
			t.Fatalf("failed to write %s: %v", cfgPath, err)
		}
	}

	// Restart all nodes with new config
	for i := 1; i <= 3; i++ {
		KillNode(t, i, "TERM")
	}
	time.Sleep(2 * time.Second)
	for i := 1; i <= 3; i++ {
		RestartNode(t, i)
	}
	WaitForCluster(t, 30, 2*time.Second)
}

// RestoreIPBindingPolicy resets all node configs to "disabled" and restarts.
func RestoreIPBindingPolicy(t *testing.T) {
	t.Helper()
	SetIPBindingPolicy(t, "disabled")
}
