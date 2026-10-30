package helpers

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func useSessionDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "sessions")
	SetSessionDir(dir)
	t.Cleanup(func() { SetSessionDir("") })
	return dir
}

func testSession(addr, ns string) *Session {
	return &Session{Addr: addr, Namespace: ns, Mount: "auth/oidc/", Token: "wdt.token-" + ns,
		Role: "operator", ExpiresAt: time.Now().Add(time.Hour).Truncate(time.Second)}
}

func TestNormalizeAddr(t *testing.T) {
	for in, want := range map[string]string{
		"HTTPS://Warden.Example:443/":  "https://warden.example:443",
		"https://warden.example":       "https://warden.example:443",
		"http://127.0.0.1:8400":        "http://127.0.0.1:8400",
		"http://127.0.0.1:8400/":       "http://127.0.0.1:8400",
		"http://[::1]:8400":            "http://[::1]:8400",
		"https://warden.example/base/": "https://warden.example:443/base",
	} {
		got, err := NormalizeAddr(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
	_, err := NormalizeAddr("warden.example")
	assert.Error(t, err)
}

func TestNormalizeNamespace(t *testing.T) {
	assert.Equal(t, "", NormalizeNamespace(""))
	assert.Equal(t, "", NormalizeNamespace("/"))
	assert.Equal(t, "team-a/dev", NormalizeNamespace("/team-a/dev/"))
}

func TestSession_SaveLoad(t *testing.T) {
	dir := useSessionDir(t)
	a := testSession("https://a.example:443", "")
	b := testSession("https://b.example:443", "")
	child := testSession("https://a.example:443", "team-a")
	for _, s := range []*Session{a, b, child} {
		require.NoError(t, SaveSession(s))
	}

	for _, s := range []*Session{a, b, child} {
		got, err := LoadSession(s.Addr, s.Namespace)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, s.Token, got.Token, "two clusters and namespaces side by side")
		assert.True(t, s.ExpiresAt.Equal(got.ExpiresAt))
		assert.Equal(t, "operator", got.Role)
	}

	fi, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), fi.Mode().Perm())
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 3, "no temporary file is left behind")
	for _, e := range entries {
		info, err := e.Info()
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), e.Name())
	}

	// Replacing a session rewrites its one file.
	a.Role = "auditor"
	require.NoError(t, SaveSession(a))
	got, err := LoadSession(a.Addr, "")
	require.NoError(t, err)
	assert.Equal(t, "auditor", got.Role)
	entries, _ = os.ReadDir(dir)
	assert.Len(t, entries, 3)

	none, err := LoadSession("https://c.example:443", "")
	require.NoError(t, err)
	assert.Nil(t, none)

	require.NoError(t, DeleteSession(a.Addr, ""))
	got, err = LoadSession(a.Addr, "")
	require.NoError(t, err)
	assert.Nil(t, got)
	assert.NoError(t, DeleteSession(a.Addr, ""), "deleting a missing session is not an error")
}

func TestSession_NoSessionDir(t *testing.T) {
	useSessionDir(t)
	s, err := FindSession("https://a.example:443", "team-a")
	require.NoError(t, err)
	assert.Nil(t, s)
}

func TestSession_RefusesSymlinks(t *testing.T) {
	dir := useSessionDir(t)
	s := testSession("https://a.example:443", "")
	require.NoError(t, SaveSession(s))
	path := sessionPath(dir, s.Addr, s.Namespace)

	// A symlinked file.
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	require.NoError(t, os.Rename(path, target))
	require.NoError(t, os.Symlink(target, path))
	_, err := LoadSession(s.Addr, "")
	assert.ErrorContains(t, err, "symbolic link")

	// A symlinked directory.
	real := t.TempDir()
	linked := filepath.Join(t.TempDir(), "sessions")
	require.NoError(t, os.Symlink(real, linked))
	SetSessionDir(linked)
	assert.ErrorContains(t, SaveSession(s), "symbolic link")
	_, err = LoadSession(s.Addr, "")
	assert.ErrorContains(t, err, "symbolic link")
}

// A file whose address is not the one it is filed under (hand-edited, or a
// collision) is refused, so a ticket is never sent to another server.
func TestSession_AddrMismatchRefused(t *testing.T) {
	dir := useSessionDir(t)
	s := testSession("https://evil.example:443", "")
	require.NoError(t, SaveSession(s))
	require.NoError(t, os.Rename(sessionPath(dir, s.Addr, ""), sessionPath(dir, "https://a.example:443", "")))
	_, err := LoadSession("https://a.example:443", "")
	assert.ErrorContains(t, err, "is for https://evil.example:443")
}

// The nearest ancestor's session serves a namespace without one; never a
// sibling's nor a descendant's, and an exact session wins.
func TestFindSession_Ancestors(t *testing.T) {
	useSessionDir(t)
	addr := "https://a.example:443"
	for _, ns := range []string{"", "team-a", "team-b", "team-a/dev/x"} {
		require.NoError(t, SaveSession(testSession(addr, ns)))
	}
	for ns, want := range map[string]string{
		"team-a/dev":   "team-a",
		"team-a":       "team-a",
		"team-a/dev/x": "team-a/dev/x",
		"team-b/qa":    "team-b",
		"team-c":       "",
		"":             "",
	} {
		s, err := FindSession(addr, ns)
		require.NoError(t, err, ns)
		require.NotNil(t, s, ns)
		assert.Equal(t, want, s.Namespace, ns)
	}

	useSessionDir(t)
	require.NoError(t, SaveSession(testSession(addr, "team-a/dev")))
	s, err := FindSession(addr, "team-a")
	require.NoError(t, err)
	assert.Nil(t, s, "a child's session never serves its parent")
	s, err = FindSession(addr, "team-b/dev")
	require.NoError(t, err)
	assert.Nil(t, s, "nor a sibling")
}

func TestSession_Expired(t *testing.T) {
	s := &Session{ExpiresAt: time.Now()}
	assert.True(t, s.Expired(time.Now()))
	assert.False(t, s.Expired(time.Now().Add(-time.Minute)))
}

// A session directory that already exists with a looser mode is restricted
// to its owner.
func TestSession_TightensExistingDir(t *testing.T) {
	dir := useSessionDir(t)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.Chmod(dir, 0o755))
	require.NoError(t, SaveSession(testSession("https://a.example:443", "")))
	fi, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), fi.Mode().Perm())
}
