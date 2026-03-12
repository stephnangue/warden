package cert

import (
	"context"
	"errors"
	"fmt"

	"github.com/stephnangue/warden/api"
)

// DefaultMountPath specifies the default mount path for the Cert
// Authentication Method.
const DefaultMountPath = "cert"

// ErrInvalidMountPath is an error, which is returned when configuring [CertAuth]
// to use an invalid mount path for an Authentication Method.
var ErrInvalidMountPath = errors.New("invalid auth method mount path specified")

// ErrNoRoleName is an error, which is returned when no role name was specified
// when creating a [CertAuth].
var ErrNoRoleName = errors.New("no role name specified")

type CertAuth struct {
	// roleName specifies the name of the role to use.
	roleName string

	// mountPath specifies the mount path for the Cert Authentication Method.
	mountPath string
}

var _ api.AuthMethod = &CertAuth{}

// Option is a function which configures [CertAuth].
type Option func(a *CertAuth) error

// New creates a new [CertAuth] and configures it with the given options.
//
// The default mount path for the Cert Authentication Method is
// [DefaultMountPath]. In order to configure a different mount path for the
// Authentication Method you can use the [WithMount] option.
//
// The client certificate used for authentication should be configured on the
// API client's TLS settings, either via environment variables
// (WARDEN_CLIENT_CERT, WARDEN_CLIENT_KEY) or via [api.Config.ConfigureTLS].
func New(roleName string, opts ...Option) (*CertAuth, error) {
	if roleName == "" {
		return nil, ErrNoRoleName
	}

	certAuth := &CertAuth{
		roleName:  roleName,
		mountPath: DefaultMountPath,
	}

	for _, opt := range opts {
		if err := opt(certAuth); err != nil {
			return nil, err
		}
	}

	if certAuth.mountPath == "" {
		return nil, ErrInvalidMountPath
	}

	return certAuth, nil
}

// Login implements the [api.AuthMethod] interface.
func (a *CertAuth) Login(ctx context.Context, client *api.Client) (*api.Resource, error) {
	path := fmt.Sprintf("auth/%s/login", a.mountPath)
	data := map[string]any{
		"role": a.roleName,
	}

	return client.Operator().WriteWithContext(ctx, path, data)
}

// WithMount is an [Option], which configures [CertAuth] to use the given mount
// when authenticating against the Warden Cert Authentication Method.
func WithMount(mount string) Option {
	opt := func(a *CertAuth) error {
		a.mountPath = mount
		return nil
	}

	return opt
}
