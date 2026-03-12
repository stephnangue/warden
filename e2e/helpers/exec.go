//go:build e2e

package helpers

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

// ConcurrentRequests fires count concurrent GET requests to path on the given port
// and returns the number of successes (HTTP 200 or 429).
func ConcurrentRequests(count int, method, path string, port int) int {
	var mu sync.Mutex
	var success int
	var wg sync.WaitGroup

	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			url := NodeURL(port) + "/v1/" + path
			req, err := exec.Command("curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-X", method, url).Output()
			if err != nil {
				return
			}
			code := string(req)
			if code == "200" || code == "429" {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return success
}

// ConcurrentDo runs fn(i) for i in [0,count) concurrently and returns success count.
func ConcurrentDo(count int, fn func(i int) bool) int {
	var mu sync.Mutex
	var success int
	var wg sync.WaitGroup

	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if fn(idx) {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	return success
}

// runScript executes a bash script with arguments and returns output.
func runScript(script string, args ...string) (string, error) {
	allArgs := append([]string{script}, args...)
	cmd := exec.Command("bash", allArgs...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// WardenBin returns the absolute path to the warden binary built by setup.sh.
func WardenBin() string {
	return filepath.Join(E2EDir(), ".bin", "warden")
}

// WardenCLI runs the warden CLI binary with the given args and environment variables.
// Returns combined stdout+stderr output and any error.
func WardenCLI(t *testing.T, env map[string]string, args ...string) (string, error) {
	t.Helper()
	bin := WardenBin()
	cmd := exec.Command(bin, args...)

	// Build env: inherit current env, then overlay custom vars
	cmd.Env = append(cmd.Environ(), "WARDEN_SKIP_VERIFY=true")
	for k, v := range env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	out, err := cmd.CombinedOutput()
	return string(out), err
}

// WardenCLIWithPort runs the warden CLI binary pointing at a specific node.
// Sets WARDEN_ADDR automatically and merges additional env vars.
func WardenCLIWithPort(t *testing.T, port int, env map[string]string, args ...string) (string, error) {
	t.Helper()
	if env == nil {
		env = make(map[string]string)
	}
	env["WARDEN_ADDR"] = NodeURL(port)
	return WardenCLI(t, env, args...)
}
