package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-viper/mapstructure/v2"
)

func (c *Sys) ListMounts() (map[string]*MountOutput, error) {
	return c.ListMountsWithContext(context.Background())
}

func (c *Sys) ListMountsWithContext(ctx context.Context) (map[string]*MountOutput, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/mounts")

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

	mounts := map[string]*MountOutput{}
	err = mapstructure.Decode(resource.Data, &mounts)
	if err != nil {
		return nil, err
	}

	return mounts, nil
}

func (c *Sys) Mount(path string, mountInfo *MountInput) error {
	return c.MountWithContext(context.Background(), path, mountInfo)
}

func (c *Sys) MountWithContext(ctx context.Context, path string, mountInfo *MountInput) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/mounts/%s", path))
	if err := r.SetJSONBody(mountInfo); err != nil {
		return err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (c *Sys) Unmount(path string) error {
	return c.UnmountWithContext(context.Background(), path)
}

func (c *Sys) UnmountWithContext(ctx context.Context, path string) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, fmt.Sprintf("/v1/sys/mounts/%s", path))

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err == nil {
		defer resp.Body.Close()
	}
	return err
}

func (c *Sys) TuneMount(path string, config map[string]any) error {
	return c.TuneMountWithContext(context.Background(), path, config)
}

func (c *Sys) TuneMountWithContext(ctx context.Context, path string, config map[string]any) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/mounts/%s/tune", path))
	if err := r.SetJSONBody(config); err != nil {
		return err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err == nil {
		defer resp.Body.Close()
	}
	return err
}

func (c *Sys) MountConfig(path string) (map[string]any, error) {
	return c.MountConfigWithContext(context.Background(), path)
}

func (c *Sys) MountConfigWithContext(ctx context.Context, path string) (map[string]any, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/mounts/%s/tune", path))

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

	var result map[string]any
	err = mapstructure.Decode(resource.Data, &result)
	if err != nil {
		return nil, err
	}

	return result, err
}

func (c *Sys) MountInfo(path string) (*MountOutput, error) {
	return c.MountInfoWithContext(context.Background(), path)
}

func (c *Sys) MountInfoWithContext(ctx context.Context, path string) (*MountOutput, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/mounts/%s", path))

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

	var result MountOutput
	err = mapstructure.Decode(resource.Data, &result)
	if err != nil {
		return nil, err
	}

	return &result, err
}

type MountInput struct {
	Type                  string            `json:"type"`
	Description           string            `json:"description"`
	Config                map[string]any    `json:"config" mapstructure:"config"`
}

type MountOutput struct {
	Type                  string            `json:"type"`
	Description           string            `json:"description"`
	Accessor              string            `json:"accessor"`
	Config                map[string]any    `json:"config" mapstructure:"config"`
}
