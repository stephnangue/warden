package roles

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

// useEnv is a fake Warden granting roles to the session ticket, and a session
// for it in namespace ns.
func useEnv(t *testing.T, ns string, ttl time.Duration, roles ...string) (addr string, seen *http.Header) {
	t.Helper()
	seen = &http.Header{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = r.Header.Clone()
		list := make([]map[string]any, len(roles))
		for i, n := range roles {
			list[i] = map[string]any{"name": n, "description": "the " + n + " role"}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"roles": list}})
	}))
	t.Cleanup(srv.Close)

	helpers.SetSessionDir(filepath.Join(t.TempDir(), "sessions"))
	t.Cleanup(func() { helpers.SetSessionDir("") })
	t.Setenv(api.EnvWardenAddress, srv.URL)
	t.Setenv(api.EnvWardenToken, "")
	t.Setenv(api.EnvWardenRole, "")
	t.Setenv(api.EnvWardenNamespace, ns)
	addr, err := helpers.NormalizeAddr(srv.URL)
	require.NoError(t, err)
	if ttl != 0 {
		require.NoError(t, helpers.SaveSession(&helpers.Session{Addr: addr, Namespace: "", Mount: "auth/oidc/",
			Token: "wdt.session", Role: "operator", ExpiresAt: time.Now().Add(ttl)}))
	}
	helpers.SetTestClient(nil)
	interactive := helpers.Interactive
	helpers.Interactive = func() bool { return false }
	t.Cleanup(func() {
		helpers.SetTestClient(nil)
		helpers.ResetWriters()
		helpers.Interactive = interactive
	})
	return addr, seen
}

func runUseCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	helpers.SetTestClient(nil)
	stderr := &bytes.Buffer{}
	helpers.SetErrorWriter(stderr)
	UseCmd.SetErr(stderr)
	err := runUse(UseCmd, args)
	return stderr.String(), err
}

func TestRoleUse_WithName(t *testing.T) {
	addr, seen := useEnv(t, "team-a", time.Hour, "operator", "auditor")
	out, err := runUseCmd(t, "auditor")
	require.NoError(t, err)
	assert.Contains(t, out, `Using role "auditor"`)
	assert.Contains(t, out, "namespace root", "the session in use is the parent's, and is named")
	assert.Equal(t, "wdt.session", seen.Get("X-Warden-Token"))
	assert.Empty(t, seen.Get(api.RoleHeaderName), "discovery is asked with no role")

	s, err := helpers.LoadSession(addr, "")
	require.NoError(t, err)
	assert.Equal(t, "auditor", s.Role, "no new login: the session is updated")

	_, err = runUseCmd(t, "admin")
	assert.ErrorContains(t, err, `role "admin" is not one you can assume here`)
	s, _ = helpers.LoadSession(addr, "")
	assert.Equal(t, "auditor", s.Role, "unchanged")
}

func TestRoleUse_NoName(t *testing.T) {
	addr, _ := useEnv(t, "", time.Hour, "operator")
	_, err := runUseCmd(t)
	require.NoError(t, err)
	s, _ := helpers.LoadSession(addr, "")
	assert.Equal(t, "operator", s.Role, "one role is chosen without asking")

	useEnv(t, "", time.Hour, "operator", "auditor")
	out, err := runUseCmd(t)
	require.NoError(t, err)
	assert.Contains(t, out, "several roles", "no terminal: the roles are listed")
}

func TestRoleUse_NoSession(t *testing.T) {
	useEnv(t, "", 0, "operator")
	_, err := runUseCmd(t, "operator")
	assert.ErrorContains(t, err, "run warden login")

	useEnv(t, "", -time.Minute, "operator")
	_, err = runUseCmd(t, "operator")
	assert.ErrorIs(t, err, helpers.ErrSessionExpired)

	useEnv(t, "", time.Hour, "operator")
	t.Setenv(api.EnvWardenToken, "wds.root")
	_, err = runUseCmd(t, "operator")
	assert.ErrorContains(t, err, "with WARDEN_TOKEN set")
}
