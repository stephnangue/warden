package login

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

const sessionAddr = "https://warden.example:8400"

func setSessionEnv(t *testing.T, ns string) {
	t.Helper()
	t.Setenv(api.EnvWardenAddress, sessionAddr)
	t.Setenv(api.EnvWardenToken, "")
	t.Setenv(api.EnvWardenRole, "")
	t.Setenv(api.EnvWardenNamespace, ns)
}

func saveSession(t *testing.T, ns string, ttl time.Duration) {
	t.Helper()
	require.NoError(t, helpers.SaveSession(&helpers.Session{Addr: sessionAddr, Namespace: ns, Mount: "auth/oidc/",
		Token: "wdt.t-" + ns, ExpiresAt: time.Now().Add(ttl)}))
}

func TestLogout(t *testing.T) {
	useSessions(t)
	saveSession(t, "team-a", time.Hour)
	saveSession(t, "team-b", time.Hour)
	setSessionEnv(t, "team-a/dev")

	stderr := &bytes.Buffer{}
	LogoutCmd.SetErr(stderr)
	require.NoError(t, LogoutCmd.RunE(LogoutCmd, nil))
	assert.Contains(t, stderr.String(), "namespace team-a", "the session in use, named")

	s, err := helpers.LoadSession(sessionAddr, "team-a")
	require.NoError(t, err)
	assert.Nil(t, s)
	s, err = helpers.LoadSession(sessionAddr, "team-b")
	require.NoError(t, err)
	assert.NotNil(t, s, "another namespace's session is kept")

	stderr.Reset()
	require.NoError(t, LogoutCmd.RunE(LogoutCmd, nil))
	assert.Contains(t, stderr.String(), "No session")
}

// A session file that cannot be read is removed by logout.
func TestLogout_CorruptFile(t *testing.T) {
	useSessions(t)
	setSessionEnv(t, "")
	saveSession(t, "", time.Hour)
	dir, err := helpers.SessionDir()
	require.NoError(t, err)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.NoError(t, os.WriteFile(filepath.Join(dir, entries[0].Name()), []byte("{not json"), 0o600))

	stderr := &bytes.Buffer{}
	LogoutCmd.SetErr(stderr)
	require.NoError(t, LogoutCmd.RunE(LogoutCmd, nil))
	assert.Contains(t, stderr.String(), "could not be read")
	entries, _ = os.ReadDir(dir)
	assert.Empty(t, entries)
}
