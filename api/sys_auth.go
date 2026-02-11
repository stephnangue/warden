package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-viper/mapstructure/v2"
)

func (c *Sys) ListAuth() (map[string]*AuthMountOutput, error) {
	return c.ListAuthWithContext(context.Background())
}

func (c *Sys) ListAuthWithContext(ctx context.Context) (map[string]*AuthMountOutput, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/auth")

	r.Params.Set("list", "true")

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

func (c *Sys) EnableAuth(path string, authInfo *AuthMountInput) error {
	return c.EnableAuthWithContext(context.Background(), path, authInfo)
}

func (c *Sys) EnableAuthWithContext(ctx context.Context, path string, authInfo *AuthMountInput) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/auth/%s", path))
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

	r := c.c.NewRequest(http.MethodDelete, fmt.Sprintf("/v1/sys/auth/%s", path))

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if resp != nil {
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

	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/auth/%s", path))

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

// Rather than duplicate, we can use modern Go's type aliasing
type (
	AuthMountInput   = MountInput
	AuthMountOutput   = MountOutput
)