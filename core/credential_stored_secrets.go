package core

import (
	"github.com/stephnangue/warden/credential"
)

// sourceStoredSecrets returns the long-lived secrets a source of this type and
// config makes the server hold, or nil when it holds none. An unknown type
// reports nothing; validation refuses it with a better message.
func (c *Core) sourceStoredSecrets(sourceType string, config credential.Config) []string {
	if c.credentialDriverRegistry == nil {
		return nil
	}
	factory, err := c.credentialDriverRegistry.GetFactory(sourceType)
	if err != nil {
		return nil
	}
	return factory.StoredSecrets(config)
}

// specStoredSecrets returns the long-lived secrets a spec of this type holds in
// its own config, or nil when it holds none. It does not look at the spec's
// source. An unknown type reports nothing.
func (c *Core) specStoredSecrets(specType string, config credential.Config) []string {
	if c.credentialTypeRegistry == nil {
		return nil
	}
	credType, err := c.credentialTypeRegistry.GetByName(specType)
	if err != nil {
		return nil
	}
	return credType.StoredSecrets(config)
}

// withStoredSecrets adds stored_secrets to a read or list entry when there are
// any. Names only: the values stay masked in config.
func withStoredSecrets(data map[string]any, secrets []string) map[string]any {
	if len(secrets) > 0 {
		data["stored_secrets"] = secrets
	}
	return data
}
