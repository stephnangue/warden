package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/go-viper/mapstructure/v2"
)

func (c *Sys) ListAuth() (map[string]*AuthMountOutput, error) {
	return c.ListAuthWithContext(context.Background())
}

func (c *Sys) ListAuthWithContext(ctx context.Context) (map[string]*AuthMountOutput, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/auth")

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

	// Extract the mounts field from the response data
	// The Huma framework returns: {"mounts": {...}, "$schema": "..."}
	mountsData, ok := resource.Data["mounts"]
	if !ok {
		return nil, errors.New("mounts field not found in response")
	}

	mounts := map[string]*AuthMountOutput{}
	err = mapstructure.Decode(mountsData, &mounts)
	if err != nil {
		return nil, err
	}

	return mounts, nil
}

func (c *Sys) EnableAuth(path string, authInfo *AuthMounthInput) error {
	return c.EnableAuthWithContext(context.Background(), path, authInfo)
}

func (c *Sys) EnableAuthWithContext(ctx context.Context, path string, authInfo *AuthMounthInput) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/auth/%s", url.PathEscape(path)))
	if err := r.SetJSONBody(authInfo); err != nil {
		return err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (c *Sys) DisableAuth(path string) error {
	return c.DisableAuthWithContext(context.Background(), path)
}

func (c *Sys) DisableAuthWithContext(ctx context.Context, path string) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, fmt.Sprintf("/v1/sys/auth/%s", url.PathEscape(path)))

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err == nil {
		defer resp.Body.Close()
	}
	return err
}

func (c *Sys) AuthInfo(path string) (*AuthMountOutput, error) {
	return c.AuthInfoWithContext(context.Background(), path)
}

func (c *Sys) AuthInfoWithContext(ctx context.Context, path string) (*AuthMountOutput, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/auth/%s", url.PathEscape(path)))

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

	var result AuthMountOutput
	err = mapstructure.Decode(resource.Data, &result)
	if err != nil {
		return nil, err
	}

	return &result, err
}

func (c *Sys) TuneAuth(path string, config map[string]any) error {
	return c.TuneAuthWithContext(context.Background(), path, config)
}

func (c *Sys) TuneAuthWithContext(ctx context.Context, path string, config map[string]any) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/auth/%s/tune", url.PathEscape(path)))

	// Wrap config in the expected request body structure
	body := map[string]any{
		"config": config,
	}
	if err := r.SetJSONBody(body); err != nil {
		return err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err == nil {
		defer resp.Body.Close()
	}
	return err
}

// Rather than duplicate, we can use modern Go's type aliasing
type (
	AuthMounthInput   = MountInput
	AuthMountOutput   = MountOutput
)