package namespaces

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeNamespaces records every request and answers body.
type fakeNamespaces struct {
	mu     sync.Mutex
	method string
	path   string
	sent   map[string]any
	body   string
}

func setupFake(t *testing.T, body string) (*fakeNamespaces, *bytes.Buffer) {
	t.Helper()
	f := &fakeNamespaces{body: body}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.method, f.path, f.sent = r.Method, r.URL.Path, nil
		if raw, _ := io.ReadAll(r.Body); len(raw) > 0 {
			_ = json.Unmarshal(raw, &f.sent)
		}
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(f.body))
	}))
	cfg := api.DefaultConfig()
	cfg.Address = srv.URL
	client, err := api.NewClient(cfg)
	require.NoError(t, err)
	client.SetMaxRetries(0)
	helpers.SetTestClient(client)
	helpers.SetOutputFormat("json")
	stdout := &bytes.Buffer{}
	helpers.SetOutputWriter(stdout)
	helpers.SetErrorWriter(&bytes.Buffer{})
	t.Cleanup(func() {
		srv.Close()
		helpers.SetTestClient(nil)
		helpers.SetOutputFormat("")
		helpers.ResetWriters()
		createMetadata, createJSON, createEnableBuiltinRoles = nil, "", false
		updateMetadata, updateJSON, updateEnableBuiltinRoles = nil, "", false
	})
	return f, stdout
}

func freshCreate() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().StringToStringVar(&createMetadata, "metadata", nil, "")
	cmd.Flags().StringVarP(&createJSON, "json", "j", "", "")
	cmd.Flags().BoolVar(&createEnableBuiltinRoles, "enable-builtin-roles", false, "")
	return cmd
}

func freshUpdate() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().StringToStringVar(&updateMetadata, "metadata", nil, "")
	cmd.Flags().StringVarP(&updateJSON, "json", "j", "", "")
	cmd.Flags().BoolVar(&updateEnableBuiltinRoles, "enable-builtin-roles", false, "")
	return cmd
}

func decode(t *testing.T, out *bytes.Buffer) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &m), "stdout: %s", out.String())
	return m
}

func TestCreate_EnableBuiltinRoles(t *testing.T) {
	f, stdout := setupFake(t, `{"data":{"id":"a1","path":"acme/","enable_builtin_roles":true}}`)
	cmd := freshCreate()
	require.NoError(t, cmd.Flags().Set("enable-builtin-roles", "true"))

	require.NoError(t, runCreate(cmd, []string{"acme"}))
	assert.Equal(t, http.MethodPost, f.method)
	assert.Equal(t, "/v1/sys/namespaces/acme", f.path)
	assert.Equal(t, true, f.sent["enable_builtin_roles"])
	assert.Equal(t, true, decode(t, stdout)["enable_builtin_roles"])
}

func TestCreate_WithoutTheFlagSendsNothing(t *testing.T) {
	f, _ := setupFake(t, `{"data":{"id":"a1","path":"acme/"}}`)
	require.NoError(t, runCreate(freshCreate(), []string{"acme"}))
	assert.NotContains(t, f.sent, "enable_builtin_roles")
}

func TestCreate_FlagRefusedWithJSON(t *testing.T) {
	setupFake(t, `{"data":{}}`)
	cmd := freshCreate()
	require.NoError(t, cmd.Flags().Set("enable-builtin-roles", "true"))
	createJSON = `{"enable_builtin_roles": true}`
	assert.Error(t, runCreate(cmd, []string{"acme"}))
}

// An update naming only the setting sends only the setting, so the
// namespace's metadata is left as it is; =false is sent, not dropped.
func TestUpdate_EnableBuiltinRolesOnly(t *testing.T) {
	for _, v := range []bool{true, false} {
		f, stdout := setupFake(t, `{"data":{"id":"a1","path":"acme/","enable_builtin_roles":`+map[bool]string{true: "true", false: "false"}[v]+`}}`)
		cmd := freshUpdate()
		require.NoError(t, cmd.Flags().Set("enable-builtin-roles", map[bool]string{true: "true", false: "false"}[v]))

		require.NoError(t, runUpdate(cmd, []string{"acme"}))
		assert.Equal(t, http.MethodPut, f.method)
		assert.Equal(t, map[string]any{"enable_builtin_roles": v}, f.sent)
		assert.Equal(t, v, decode(t, stdout)["enable_builtin_roles"])
	}
}

func TestUpdate_NeedsAFlag(t *testing.T) {
	setupFake(t, `{"data":{}}`)
	err := runUpdate(freshUpdate(), []string{"acme"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "-metadata or -enable-builtin-roles is required")
}
