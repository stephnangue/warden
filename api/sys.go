package api

import (
	"context"
	"errors"
	"net/http"
)

// Sys is used to perform system-related operations on Warden.
type Sys struct {
	c *Client
}

// Sys is used to return the client for sys-related API calls.
func (c *Client) Sys() *Sys {
	return &Sys{c: c}
}

// InitResponse is the response from the init endpoint
type InitResponse struct {
	RootToken string `json:"root_token"`
}

// Init initializes the Warden server and generates a root token.
func (c *Sys) Init() (*InitResponse, error) {
	return c.InitWithContext(context.Background())
}

// InitWithContext initializes the Warden server with context.
func (c *Sys) InitWithContext(ctx context.Context) (*InitResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, "/v1/sys/init")
	if err := r.SetJSONBody(map[string]any{}); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	resource, err := ParseResource(resp.Body)
	if err != nil {
		return nil, err
	}
	if resource == nil || resource.Data == nil {
		return nil, errors.New("data from server response is empty")
	}

	rootToken, ok := resource.Data["root_token"].(string)
	if !ok {
		return nil, errors.New("root_token field not found or invalid in response")
	}

	return &InitResponse{RootToken: rootToken}, nil
}

// RevokeRootToken revokes the current root token.
func (c *Sys) RevokeRootToken() error {
	return c.RevokeRootTokenWithContext(context.Background())
}

// RevokeRootTokenWithContext revokes the current root token with context.
func (c *Sys) RevokeRootTokenWithContext(ctx context.Context) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, "/v1/sys/revoke-root-token")
	if err := r.SetJSONBody(map[string]any{}); err != nil {
		return err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}