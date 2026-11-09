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

const (
	leftoverWarning = `auth mount "jwt/" holds 2 role(s) of a removed format`
	disableWarning  = `1 group(s) have a rule whose mount selector names auth/jwt/`
)

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
			if r.Method == http.MethodDelete {
				_, _ = w.Write([]byte(`{"data":{"message":"Successfully unmounted jwt/","warnings":["` + disableWarning + `"]}}`))
				return
			}
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

func TestDisable_PrintsWarnings(t *testing.T) {
	stdout, stderr := fakeSysAuth(t)
	require.NoError(t, runDisable(nil, []string{"jwt/"}))
	assert.Equal(t, "warning: "+disableWarning+"\n", stderr.String())
	assert.Contains(t, stdout.String(), `"warnings"`, "the structured output keeps them")
	assert.Contains(t, stdout.String(), `"disabled": true`)
}

// -force asks the server to disable a mount with claimed native identities.
func TestDisable_Force(t *testing.T) {
	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"message":"Successfully unmounted jwt/"}}`))
	}))
	t.Cleanup(srv.Close)
	cfg := api.DefaultConfig()
	cfg.Address = srv.URL
	client, err := api.NewClient(cfg)
	require.NoError(t, err)
	client.SetMaxRetries(0)
	helpers.SetTestClient(client)
	helpers.SetOutputFormat("json")
	helpers.SetOutputWriter(&bytes.Buffer{})
	t.Cleanup(func() {
		helpers.SetTestClient(nil)
		helpers.SetOutputFormat("")
		helpers.ResetWriters()
		disableForce = false
	})

	require.NoError(t, runDisable(nil, []string{"jwt/"}))
	assert.Empty(t, query, "no force unless asked")
	disableForce = true
	require.NoError(t, runDisable(nil, []string{"jwt/"}))
	assert.Equal(t, "force=true", query)
}

func TestRead_PrintsWarnings(t *testing.T) {
	stdout, stderr := fakeSysAuth(t)
	require.NoError(t, runRead(nil, []string{"jwt/"}))
	assert.Equal(t, "warning: "+leftoverWarning+"\n", stderr.String())
	assert.Contains(t, stdout.String(), `"warnings"`, "the structured output keeps them")
}
