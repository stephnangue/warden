package auth

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

const leftoverWarning = `auth mount "jwt/" holds 2 role(s) of a removed format`

// fakeSysAuth answers sys/auth listings and reads with a warning, as a server
// with leftover role storage does.
func fakeSysAuth(t *testing.T) (*bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/sys/auth":
			_, _ = w.Write([]byte(`{"data":{"mounts":{"jwt/":{"type":"jwt","accessor":"auth_jwt_1","description":"","config":{}}},` +
				`"warnings":["` + `auth mount \"jwt/\" holds 2 role(s) of a removed format` + `"]}}`))
		case "/v1/sys/auth/jwt/", "/v1/sys/auth/jwt":
			_, _ = w.Write([]byte(`{"data":{"type":"jwt","path":"jwt/","accessor":"auth_jwt_1","description":"","config":{},` +
				`"warnings":["` + `auth mount \"jwt/\" holds 2 role(s) of a removed format` + `"]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
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
	return stdout, stderr
}

func TestList_PrintsWarnings(t *testing.T) {
	stdout, stderr := fakeSysAuth(t)
	require.NoError(t, runList(nil, nil))
	assert.Equal(t, "warning: "+leftoverWarning+"\n", stderr.String())
	assert.Contains(t, stdout.String(), `"jwt/"`)
	assert.NotContains(t, stdout.String(), "warning", "stdout stays the listing")
}

func TestRead_PrintsWarnings(t *testing.T) {
	stdout, stderr := fakeSysAuth(t)
	require.NoError(t, runRead(nil, []string{"jwt/"}))
	assert.Equal(t, "warning: "+leftoverWarning+"\n", stderr.String())
	assert.Contains(t, stdout.String(), `"warnings"`, "the structured output keeps them")
}
