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

// A write whose response carries warnings, such as a forced change, prints
// each on stderr and keeps them in the structured output on stdout.
func TestWrite_PrintsWarnings(t *testing.T) {
	const warning = `forced: auth/jwt/ now derives native identities as kind agent, fact "repo"`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/v1/auth/jwt/config" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"message":"configuration updated","warnings":["` +
			`forced: auth/jwt/ now derives native identities as kind agent, fact \"repo\""]}}`))
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

	require.NoError(t, runWrite(nil, []string{"auth/jwt/config", "alias_name_source=repo", "force=true"}))
	assert.Equal(t, "warning: "+warning+"\n", stderr.String())
	assert.Contains(t, stdout.String(), `"warnings"`, "the structured output keeps them")
	assert.Contains(t, stdout.String(), `"written": true`)
}
