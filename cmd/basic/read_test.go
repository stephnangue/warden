package basic

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

// A read whose response carries warnings prints each on stderr and keeps
// them in the structured output on stdout.
func TestRead_PrintsWarnings(t *testing.T) {
	const warning = `auto_auth_path "auth/users/" names a human auth mount: agent credentials are never admitted through it, so every gateway request is refused`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/v1/aws/config" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"auto_auth_path":"auth/users/","warnings":["` +
			`auto_auth_path \"auth/users/\" names a human auth mount: agent credentials are never admitted through it, so every gateway request is refused"]}}`))
	}))
	t.Cleanup(srv.Close)

	cfg := api.DefaultConfig()
	cfg.Address = srv.URL
	client, err := api.NewClient(cfg)
	require.NoError(t, err)
	client.SetMaxRetries(0)
	helpers.SetTestClient(client)
	helpers.SetOutputFormat("json")
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	helpers.SetOutputWriter(stdout)
	helpers.SetErrorWriter(stderr)
	t.Cleanup(func() {
		helpers.SetTestClient(nil)
		helpers.SetOutputFormat("")
		helpers.ResetWriters()
	})

	require.NoError(t, runRead(nil, []string{"aws/config"}))
	assert.Equal(t, "warning: "+warning+"\n", stderr.String())
	assert.Contains(t, stdout.String(), `"warnings"`, "the structured output keeps them")
	assert.Contains(t, stdout.String(), `"auto_auth_path"`)
}
