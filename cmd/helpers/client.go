package helpers

import (
	"fmt"

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

	c = client

	return client, nil
}
