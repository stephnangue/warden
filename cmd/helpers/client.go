package helpers

import (
	"fmt"
	"strings"

	"github.com/stephnangue/warden/api"
)

var (
	c *api.Client
)

// SetTestClient installs an api.Client that Client() returns instead of
// constructing one from the environment. Pass nil to clear. Intended for tests.
func SetTestClient(client *api.Client) { c = client }

// Construct the HTTP API client
func Client() (*api.Client, error) {
	// Read the test client if present
	if c != nil {
		return c, nil
	}

	config := api.DefaultConfig()

	if err := config.ReadEnvironment(); err != nil {
		return nil, fmt.Errorf("failed to read environment: %w", err)
	}

	// Build the client
	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	// Turn off retries on the CLI
	if api.ReadWardenVariable(api.EnvWardenMaxRetries) == "" {
		client.SetMaxRetries(0)
	}

	// If WARDEN_TOKEN is a JWT, send it as `Authorization: Bearer` and
	// strip X-Warden-Token. The server's transparent-auth gate fires only
	// when X-Warden-Token is empty (a JWT is not a Warden session token
	// and would fail token-store lookup); routing the credential through
	// the Authorization header lets implicit auth resolve it against the
	// namespace's auto_auth_path. The "eyJ" prefix is the base64 of `{"`,
	// the start of every JWT header — the same heuristic used server-side
	// by provider/aws to detect JWT-shaped tokens.
	if token := client.Token(); strings.HasPrefix(token, "eyJ") {
		h := client.Headers()
		h.Set("Authorization", "Bearer "+token)
		client.SetHeaders(h)
		client.ClearToken()
	}

	c = client

	return client, nil
}
