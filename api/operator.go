package api

import (
	"context"
	"io"
	"net/http"
	"net/url"
)

// Operator is used to perform operations on Warden.
type Operator struct {
	c *Client
}

// Operator is used to return the client for backend API calls.
func (c *Client) Operator() *Operator {
	return &Operator{c: c}
}

func (c *Operator) Read(path string) (*Resource, error) {
	return c.ReadWithDataWithContext(context.Background(), path, nil)
}

func (c *Operator) ReadWithContext(ctx context.Context, path string) (*Resource, error) {
	return c.ReadWithDataWithContext(ctx, path, nil)
}

func (c *Operator) ReadWithData(path string, data map[string][]string) (*Resource, error) {
	return c.ReadWithDataWithContext(context.Background(), path, data)
}

func (c *Operator) ReadWithDataWithContext(ctx context.Context, path string, data map[string][]string) (*Resource, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	resp, err := c.readRawWithDataWithContext(ctx, path, data)
	return c.ParseRawResponseAndCloseBody(resp, err)
}

// ReadRaw attempts to read the value stored at the given Vault path
// (without '/v1/' prefix) and returns a raw *http.Response.
//
// Note: the raw-response functions do not respect the client-configured
// request timeout; if a timeout is desired, please use ReadRawWithContext
// instead and set the timeout through context.WithTimeout or context.WithDeadline.
func (c *Operator) ReadRaw(path string) (*Response, error) {
	return c.ReadRawWithDataWithContext(context.Background(), path, nil)
}

// ReadRawWithContext attempts to read the value stored at the give Vault path
// (without '/v1/' prefix) and returns a raw *http.Response.
//
// Note: the raw-response functions do not respect the client-configured
// request timeout; if a timeout is desired, please set it through
// context.WithTimeout or context.WithDeadline.
func (c *Operator) ReadRawWithContext(ctx context.Context, path string) (*Response, error) {
	return c.ReadRawWithDataWithContext(ctx, path, nil)
}

// ReadRawWithData attempts to read the value stored at the given Vault
// path (without '/v1/' prefix) and returns a raw *http.Response. The 'data' map
// is added as query parameters to the request.
//
// Note: the raw-response functions do not respect the client-configured
// request timeout; if a timeout is desired, please use
// ReadRawWithDataWithContext instead and set the timeout through
// context.WithTimeout or context.WithDeadline.
func (c *Operator) ReadRawWithData(path string, data map[string][]string) (*Response, error) {
	return c.ReadRawWithDataWithContext(context.Background(), path, data)
}

// ReadRawWithDataWithContext attempts to read the value stored at the given
// Vault path (without '/v1/' prefix) and returns a raw *http.Response. The 'data'
// map is added as query parameters to the request.
//
// Note: the raw-response functions do not respect the client-configured
// request timeout; if a timeout is desired, please set it through
// context.WithTimeout or context.WithDeadline.
func (c *Operator) ReadRawWithDataWithContext(ctx context.Context, path string, data map[string][]string) (*Response, error) {
	return c.readRawWithDataWithContext(ctx, path, data)
}

func (c *Operator) ParseRawResponseAndCloseBody(resp *Response, err error) (*Resource, error) {
	if resp != nil {
		defer resp.Body.Close()
	}
	if resp != nil && resp.StatusCode == 404 {
		secret, parseErr := ParseResource(resp.Body)
		switch parseErr {
		case nil:
		case io.EOF:
			return nil, nil
		default:
			return nil, parseErr
		}
		if secret != nil && len(secret.Data) > 0 {
			return secret, nil
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return ParseResource(resp.Body)
}

func (c *Operator) readRawWithDataWithContext(ctx context.Context, path string, data map[string][]string) (*Response, error) {
	r := c.c.NewRequest(http.MethodGet, "/v1/"+path)

	var values url.Values
	for k, v := range data {
		if values == nil {
			values = make(url.Values)
		}
		for _, val := range v {
			values.Add(k, val)
		}
	}

	if values != nil {
		r.Params = values
	}

	return c.c.RawRequestWithContext(ctx, r)
}

func (c *Operator) Write(path string, data map[string]interface{}) (*Resource, error) {
	return c.WriteWithContext(context.Background(), path, data)
}

func (c *Operator) WriteWithContext(ctx context.Context, path string, data map[string]interface{}) (*Resource, error) {
	r := c.c.NewRequest(http.MethodPut, "/v1/"+path)
	if err := r.SetJSONBody(data); err != nil {
		return nil, err
	}

	return c.write(ctx, r)
}

func (c *Operator) write(ctx context.Context, request *Request) (*Resource, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	resp, err := c.c.rawRequestWithContext(ctx, request)
	if resp != nil {
		defer resp.Body.Close()
	}
	if resp != nil && resp.StatusCode == 404 {
		secret, parseErr := ParseResource(resp.Body)
		switch parseErr {
		case nil:
		case io.EOF:
			return nil, nil
		default:
			return nil, parseErr
		}
		if secret != nil && len(secret.Data) > 0 {
			return secret, err
		}
	}
	if err != nil {
		return nil, err
	}

	return ParseResource(resp.Body)
}

func (c *Operator) Delete(path string) (*Resource, error) {
	return c.DeleteWithContext(context.Background(), path)
}

func (c *Operator) DeleteWithContext(ctx context.Context, path string) (*Resource, error) {
	return c.DeleteWithDataWithContext(ctx, path, nil)
}

func (c *Operator) DeleteWithData(path string, data map[string][]string) (*Resource, error) {
	return c.DeleteWithDataWithContext(context.Background(), path, data)
}

func (c *Operator) DeleteWithDataWithContext(ctx context.Context, path string, data map[string][]string) (*Resource, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, "/v1/"+path)

	var values url.Values
	for k, v := range data {
		if values == nil {
			values = make(url.Values)
		}
		for _, val := range v {
			values.Add(k, val)
		}
	}

	if values != nil {
		r.Params = values
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if resp != nil {
		defer resp.Body.Close()
	}
	if resp != nil && resp.StatusCode == 404 {
		secret, parseErr := ParseResource(resp.Body)
		switch parseErr {
		case nil:
		case io.EOF:
			return nil, nil
		default:
			return nil, parseErr
		}
		if secret != nil && len(secret.Data) > 0 {
			return secret, err
		}
	}
	if err != nil {
		return nil, err
	}

	return ParseResource(resp.Body)
}