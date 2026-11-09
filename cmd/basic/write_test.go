package basic

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

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

// writeWithStdin runs a write with stdin replaced and returns the body the
// server received. A write that blocks on stdin fails the test.
func writeWithStdin(t *testing.T, stdin *os.File, args ...string) string {
	t.Helper()
	bodies := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies <- string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
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
	helpers.SetErrorWriter(&bytes.Buffer{})
	original := os.Stdin
	os.Stdin = stdin
	t.Cleanup(func() {
		os.Stdin = original
		helpers.SetTestClient(nil)
		helpers.SetOutputFormat("")
		helpers.ResetWriters()
	})

	done := make(chan error, 1)
	go func() { done <- runWrite(nil, args) }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("write blocked on stdin")
	}
	return <-bodies
}

// Data given as arguments is sent without touching a stdin that is not a
// terminal, whether nobody writes to it or it is already empty.
func TestWrite_ArgumentsWinOverStdin(t *testing.T) {
	for name, closeWriter := range map[string]bool{
		"pipe left open":     false,
		"pipe already empty": true,
	} {
		for dataName, data := range map[string]string{
			"key=value": "timeout=30s",
			"json":      `{"timeout":"30s"}`,
		} {
			t.Run(name+"/"+dataName, func(t *testing.T) {
				reader, writer, err := os.Pipe()
				require.NoError(t, err)
				t.Cleanup(func() {
					_ = writer.Close()
					_ = reader.Close()
				})
				if closeWriter {
					require.NoError(t, writer.Close())
				}

				body := writeWithStdin(t, reader, "aws/config", data)
				assert.JSONEq(t, `{"timeout":"30s"}`, body)
			})
		}
	}
}

// With no data in the arguments, the JSON piped on stdin is the payload.
func TestWrite_ReadsPipedJSONWithoutArguments(t *testing.T) {
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = reader.Close() })
	_, err = writer.WriteString(`{"timeout":"30s"}`)
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	body := writeWithStdin(t, reader, "aws/config")
	assert.JSONEq(t, `{"timeout":"30s"}`, body)
}
