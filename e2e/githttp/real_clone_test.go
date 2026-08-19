//go:build e2e

package githttp

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRealGitClone drives an actual git client through the mount against a real
// bare repository served by git-http-backend.
//
// Every other test in this package shapes the HTTP itself, which pins what
// Warden does but cannot show that git accepts the exchange. This one covers the
// part only a real client can: that it reads the challenge, retries with the
// credential in the Basic slots, and completes the transfer. That is precisely
// the step that regressed, and it was found by hand rather than by CI because
// nothing here drove git.
//
// The agent rides X-Warden-Agent-Token rather than a certificate: mTLS to the
// node would need the agent cert to chain to the listener's configured client
// CA, which is a different fixture, and the challenge-and-retry cycle under test
// is identical on both agent channels.
func TestRealGitClone(t *testing.T) {
	ensureEnv(t)

	// Skipping is right on a machine without git, but in CI it would quietly
	// drop the only coverage of a real client acting on the challenge — the
	// blind spot that let the regression ship. Fail there instead.
	unavailable := func(reason string) {
		t.Helper()
		if os.Getenv("CI") != "" {
			t.Fatalf("%s — CI must not lose real-client coverage", reason)
		}
		t.Skip(reason)
	}

	if _, err := exec.LookPath("git"); err != nil {
		unavailable("git is not installed")
	}
	realUpstream := h.StartRealGitUpstream(t)
	if realUpstream == "" {
		unavailable("git-http-backend is unavailable")
	}

	defer restoreEnv(t)
	h.SetGitAgentPath(t, leaderPort, realUpstream, "auth/jwt/", h.GitUserAuthMount, "")

	dest := filepath.Join(t.TempDir(), "clone")
	cloneURL := fmt.Sprintf("%s/v1/%s/gateway/%s.git",
		h.NodeURL(leaderPort), h.GitMount, h.GitRepo)

	// The credential goes in the URL only because a test cannot answer a
	// prompt. Real users should not: git writes the remote verbatim into
	// .git/config, which is why the provider help says to let git ask.
	withCreds := strings.Replace(cloneURL, "https://",
		fmt.Sprintf("https://%s:%s@", h.GitAgentJWTRole, h.UserJWT(t)), 1)

	cmd := exec.Command("git",
		"-c", "http.sslVerify=false",
		"-c", "credential.helper=",
		"-c", "http.extraHeader=X-Warden-Agent-Token: "+h.GetDefaultJWT(t),
		"clone", "--quiet", withCreds, dest,
	)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")

	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git clone through the mount failed:\n%s", out)

	// A clone that produced no working tree would pass on exit code alone.
	body, err := os.ReadFile(filepath.Join(dest, "README.md"))
	require.NoError(t, err, "the clone produced no working tree")
	assert.Equal(t, "warden e2e fixture\n", string(body))
}
