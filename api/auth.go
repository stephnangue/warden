package api

import (
	"context"
	"errors"
	"fmt"
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

