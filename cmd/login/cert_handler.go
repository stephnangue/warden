package login

import (
	"context"

	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/api/auth/cert"
)

type CertHandler struct{}

func (h CertHandler) Auth(ctx context.Context, c *api.Client, m map[string]string) (*api.Resource, error) {
	mount, ok := m["mount"]
	if !ok {
		mount = cert.DefaultMountPath
	}
	role := m["role"]

	// If --cert/--key flags were provided, create a new client with TLS configured.
	// Client.config is private, so we must build a new Config + Client.
	// DefaultConfig() already reads WARDEN_ADDR, WARDEN_CACERT, etc.
	if certFile := m["cert"]; certFile != "" {
		config := api.DefaultConfig()
		if err := config.ConfigureTLS(&api.TLSConfig{
			ClientCert: certFile,
			ClientKey:  m["key"],
		}); err != nil {
			return nil, err
		}
		var err error
		c, err = api.NewClient(config)
		if err != nil {
			return nil, err
		}
	}

	auth, err := cert.New(role, cert.WithMount(mount))
	if err != nil {
		return nil, err
	}

	result, err := auth.Login(ctx, c)
	if err != nil {
		return nil, err
	}

	return result, nil
}
