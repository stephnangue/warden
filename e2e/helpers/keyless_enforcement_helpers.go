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

// --- Keyless Enforcement Level Helpers ---

var keylessEnforcementRe = regexp.MustCompile(`keyless_enforcement_level\s*=\s*"[^"]*"`)

// SetKeylessEnforcementLevel rewrites keyless_enforcement_level in all 3 node
// configs, restarts the cluster, and waits for it to become healthy. The level
// is read once at startup, so a restart is the only way to change it.
func SetKeylessEnforcementLevel(t *testing.T, level string) {
	t.Helper()
	replacement := fmt.Sprintf(`keyless_enforcement_level = "%s"`, level)
	configsDir := filepath.Join(E2EDir(), "configs")

	for i := 1; i <= 3; i++ {
		cfgPath := filepath.Join(configsDir, fmt.Sprintf("node%d.hcl", i))
		data, err := os.ReadFile(cfgPath)
		if err != nil {
			t.Fatalf("failed to read %s: %v", cfgPath, err)
		}
		if !keylessEnforcementRe.Match(data) {
			t.Fatalf("%s has no keyless_enforcement_level line to rewrite", cfgPath)
		}
		updated := keylessEnforcementRe.ReplaceAll(data, []byte(replacement))
		if err := os.WriteFile(cfgPath, updated, 0o644); err != nil {
			t.Fatalf("failed to write %s: %v", cfgPath, err)
		}
	}

	for i := 1; i <= 3; i++ {
		KillNode(t, i, "TERM")
	}
	time.Sleep(2 * time.Second)
	for i := 1; i <= 3; i++ {
		RestartNode(t, i)
	}
	WaitForCluster(t, 30, 2*time.Second)
}

// RestoreKeylessEnforcementLevel resets all node configs to the shared default,
// "warn", and restarts.
func RestoreKeylessEnforcementLevel(t *testing.T) {
	t.Helper()
	SetKeylessEnforcementLevel(t, "warn")
}
