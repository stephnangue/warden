package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-viper/mapstructure/v2"
)

func (c *Sys) ListAudit() (map[string]*Audit, error) {
	return c.ListAuditWithContext(context.Background())
}

func (c *Sys) ListAuditWithContext(ctx context.Context) (map[string]*Audit, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/audit")

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

	mounts := map[string]*Audit{}
	err = mapstructure.Decode(resource.Data, &mounts)
	if err != nil {
		return nil, err
	}

	return mounts, nil
}

func (c *Sys) EnableAudit(path string, auditInput *AuditInput) error {
	return c.EnableAuditWithContext(context.Background(), path, auditInput)
}

func (c *Sys) EnableAuditWithContext(ctx context.Context, path string, auditInput *AuditInput) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPut, fmt.Sprintf("/v1/sys/audit/%s", path))
	if err := r.SetJSONBody(auditInput); err != nil {
		return err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}


func (c *Sys) DisableAudit(path string) error {
	return c.DisableAuditWithContext(context.Background(), path)
}

func (c *Sys) DisableAuditWithContext(ctx context.Context, path string) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, fmt.Sprintf("/v1/sys/audit/%s", path))

	resp, err := c.c.rawRequestWithContext(ctx, r)

	if err == nil {
		defer resp.Body.Close()
	}
	return err
}


// Rather than duplicate, we can use modern Go's type aliasing
type (
	AuditInput   = MountInput
	Audit        = MountOutput
)