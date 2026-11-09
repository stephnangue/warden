package playground

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Start binds the fixtures, serves them over the playground's own TLS, and
// reports localhost URLs, so the bootstrap's verified HTTPS works as written.
func TestStart(t *testing.T) {
	pg, err := Start(Options{
		ASAddr:     "127.0.0.1:0",
		BankAddr:   "127.0.0.1:0",
		WardenAddr: "http://127.0.0.1:8400/",
		AuditPath:  "/tmp/audit.log",
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pg.Close(context.Background()) })

	assert.True(t, strings.HasPrefix(pg.ASURL(), "https://localhost:"))
	assert.True(t, strings.HasPrefix(pg.BankURL(), "https://localhost:"))
	assert.Equal(t, "http://127.0.0.1:8400", pg.Settings().WardenIssuer, "a trailing slash is dropped")

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: pg.tls.ClientConfig()}}
	resp, err := client.Get(pg.ASURL() + "/.well-known/openid-configuration")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp, err = client.Get(pg.BankURL() + BankAPIPath + "/accounts/me")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "the bank is a protected resource")

	token, err := pg.MintIdentity(Identity{Kind: KindAgent, Subject: "agent-1"})
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Len(t, pg.Bootstrap(), len(Bootstrap(pg.Settings())))

	require.NoError(t, pg.Close(context.Background()))
	_, err = client.Get(pg.ASURL() + "/jwks")
	assert.Error(t, err, "closed fixtures stop serving")
}

func TestStart_RefusesWithoutWarden(t *testing.T) {
	_, err := Start(Options{ASAddr: "127.0.0.1:0", BankAddr: "127.0.0.1:0"})
	require.Error(t, err)
}
