package helpers

import (
	"fmt"
	"strings"

	"github.com/stephnangue/warden/api"
)

var (
	c *api.Client
)

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

	// If WARDEN_TOKEN is a JWT, also send it as `Authorization: Bearer` so
	// identity-introspection endpoints (sys/introspect/roles, the AWS
	// gateway, etc.) can read the JWT directly. The "eyJ" prefix is the
	// base64 of `{"`, the start of every JWT header — the same heuristic
	// used server-side by provider/aws to detect JWT-shaped tokens.
	// X-Warden-Token is still set; this is additive.
	if token := client.Token(); strings.HasPrefix(token, "eyJ") {
		h := client.Headers()
		h.Set("Authorization", "Bearer "+token)
		client.SetHeaders(h)
	}

	c = client

	return client, nil
}
