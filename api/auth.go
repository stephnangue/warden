package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// Auth is used to perform authentication related operations.
type Auth struct {
	c *Client
}

type AuthMethod interface {
	Login(ctx context.Context, client *Client) (*Resource, error)
}

// Auth is used to return the client for auth-backend API calls.
func (c *Client) Auth() *Auth {
	return &Auth{c: c}
}

// Login sets up the required request body for login requests to the given auth
// method's /login API endpoint, and then performs a write to it. After a
// successful login, this method will automatically set the client's token to
// the login response's ClientToken as well.
//
// The Resource returned is the authentication resource, which if desired can be
// passed as input to the NewLifetimeWatcher method in order to start
// automatically renewing the token.
func (a *Auth) Login(ctx context.Context, authMethod AuthMethod) (*Resource, error) {
	if authMethod == nil {
		return nil, errors.New("no auth method provided for login")
	}
	return a.login(ctx, authMethod)
}

// login performs the (*AuthMethod).Login() with the configured client and checks that a ClientToken is returned
func (a *Auth) login(ctx context.Context, authMethod AuthMethod) (*Resource, error) {
	r, err := authMethod.Login(ctx, a.c)
	if err != nil {
		return nil, fmt.Errorf("unable to log in to auth method: %w", err)
	}

	return r, nil
}

func (c *Auth) Read(path string) (*Resource, error) {
	return c.ReadWithDataWithContext(context.Background(), path, nil)
}

func (c *Auth) ReadWithContext(ctx context.Context, path string) (*Resource, error) {
	return c.ReadWithDataWithContext(ctx, path, nil)
}

func (c *Auth) ReadWithData(path string, data map[string][]string) (*Resource, error) {
	return c.ReadWithDataWithContext(context.Background(), path, data)
}

func (c *Auth) ReadWithDataWithContext(ctx context.Context, path string, data map[string][]string) (*Resource, error) {
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
func (c *Auth) ReadRaw(path string) (*Response, error) {
	return c.ReadRawWithDataWithContext(context.Background(), path, nil)
}

// ReadRawWithContext attempts to read the value stored at the give Vault path
// (without '/v1/' prefix) and returns a raw *http.Response.
//
// Note: the raw-response functions do not respect the client-configured
// request timeout; if a timeout is desired, please set it through
// context.WithTimeout or context.WithDeadline.
func (c *Auth) ReadRawWithContext(ctx context.Context, path string) (*Response, error) {
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
func (c *Auth) ReadRawWithData(path string, data map[string][]string) (*Response, error) {
	return c.ReadRawWithDataWithContext(context.Background(), path, data)
}

// ReadRawWithDataWithContext attempts to read the value stored at the given
// Vault path (without '/v1/' prefix) and returns a raw *http.Response. The 'data'
// map is added as query parameters to the request.
//
// Note: the raw-response functions do not respect the client-configured
// request timeout; if a timeout is desired, please set it through
// context.WithTimeout or context.WithDeadline.
func (c *Auth) ReadRawWithDataWithContext(ctx context.Context, path string, data map[string][]string) (*Response, error) {
	return c.readRawWithDataWithContext(ctx, path, data)
}

func (c *Auth) ParseRawResponseAndCloseBody(resp *Response, err error) (*Resource, error) {
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

func (c *Auth) readRawWithDataWithContext(ctx context.Context, path string, data map[string][]string) (*Response, error) {
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

func (c *Auth) Write(path string, data map[string]interface{}) (*Resource, error) {
	return c.WriteWithContext(context.Background(), path, data)
}

func (c *Auth) WriteWithContext(ctx context.Context, path string, data map[string]interface{}) (*Resource, error) {
	r := c.c.NewRequest(http.MethodPut, "/v1/"+path)
	if err := r.SetJSONBody(data); err != nil {
		return nil, err
	}

	return c.write(ctx, r)
}

func (c *Auth) write(ctx context.Context, request *Request) (*Resource, error) {
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

func (c *Auth) Delete(path string) (*Resource, error) {
	return c.DeleteWithContext(context.Background(), path)
}

func (c *Auth) DeleteWithContext(ctx context.Context, path string) (*Resource, error) {
	return c.DeleteWithDataWithContext(ctx, path, nil)
}

func (c *Auth) DeleteWithData(path string, data map[string][]string) (*Resource, error) {
	return c.DeleteWithDataWithContext(context.Background(), path, data)
}

func (c *Auth) DeleteWithDataWithContext(ctx context.Context, path string, data map[string][]string) (*Resource, error) {
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