package login

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/cmd/helpers"
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
