package login

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/cmd/helpers"
	"github.com/stephnangue/warden/helper/dpop"
)

func TestPrintToken(t *testing.T) {
	useSessions(t)
	setSessionEnv(t, "team-a/dev")
	out := &bytes.Buffer{}
	printTokenCmd.SetOut(out)

	err := printTokenCmd.RunE(printTokenCmd, nil)
	assert.ErrorContains(t, err, "run warden login", "no session")

	saveSession(t, "team-a", time.Hour)
	require.NoError(t, printTokenCmd.RunE(printTokenCmd, nil))
	assert.Equal(t, "wdt.t-team-a\n", out.String(), "the parent's session serves the child")

	saveSession(t, "team-a/dev", -time.Minute)
	err = printTokenCmd.RunE(printTokenCmd, nil)
	assert.ErrorIs(t, err, helpers.ErrSessionExpired)
}

// A bound session's token still prints, with a note on stderr that it is
// refused without the session's key.
func TestPrintToken_BoundSession(t *testing.T) {
	useSessions(t)
	setSessionEnv(t, "")
	key, err := dpop.GenerateKey()
	require.NoError(t, err)
	s := &helpers.Session{Addr: sessionAddr, Mount: "auth/oidc/", Token: "wdt.bound", ExpiresAt: time.Now().Add(time.Hour)}
	t.Setenv(helpers.EnvSessionKeystore, "file")
	require.NoError(t, helpers.StoreSessionKey(s, key, io.Discard))
	require.NoError(t, helpers.SaveSession(s))

	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	printTokenCmd.SetOut(out)
	printTokenCmd.SetErr(errOut)
	require.NoError(t, printTokenCmd.RunE(printTokenCmd, nil))
	assert.Equal(t, "wdt.bound\n", out.String(), "stdout carries the token alone")
	assert.Contains(t, errOut.String(), "bound to the key")

	saveSession(t, "", time.Hour)
	errOut.Reset()
	require.NoError(t, printTokenCmd.RunE(printTokenCmd, nil))
	assert.Empty(t, errOut.String(), "a bearer session gets no note")
}

func TestPrintToken_CorruptFile(t *testing.T) {
	useSessions(t)
	setSessionEnv(t, "")
	saveSession(t, "", time.Hour)
	dir, _ := helpers.SessionDir()
	entries, _ := os.ReadDir(dir)
	require.Len(t, entries, 1)
	require.NoError(t, os.WriteFile(filepath.Join(dir, entries[0].Name()), []byte("{not json"), 0o600))
	err := printTokenCmd.RunE(printTokenCmd, nil)
	assert.ErrorContains(t, err, "reading the session")
}
