package api

import (
	"context"
	"errors"
	"net/http"
)

// Sys is used to perform system-related operations on Warden.
type Sys struct {
	c *Client
}

// Sys is used to return the client for sys-related API calls.
func (c *Client) Sys() *Sys {
	return &Sys{c: c}
}

// InitRequest is the request payload for the init endpoint
type InitRequest struct {
	// PGPKeys specifies an array of PGP public keys used to encrypt the output unseal keys.
	// The keys must be base64-encoded from their original binary representation.
	// The size of this array must be the same as SecretShares.
	PGPKeys []string `json:"pgp_keys,omitempty"`

	// RootTokenPGPKey specifies a PGP public key used to encrypt the initial root token.
	// The key must be base64-encoded from its original binary representation.
	RootTokenPGPKey string `json:"root_token_pgp_key,omitempty"`

	// SecretShares specifies the number of shares to split the root key into.
	SecretShares int `json:"secret_shares,omitempty"`

	// SecretThreshold specifies the number of shares required to reconstruct the root key.
	// This must be less than or equal to SecretShares.
	SecretThreshold int `json:"secret_threshold,omitempty"`

	// StoredShares specifies the number of shares that should be encrypted by the HSM and stored for auto-unsealing.
	// Currently must be the same as SecretShares. Only supported when using Auto Unseal.
	StoredShares int `json:"stored_shares,omitempty"`

	// RecoveryShares specifies the number of shares to split the recovery key into.
	// Only available when using Auto Unseal.
	RecoveryShares int `json:"recovery_shares,omitempty"`

	// RecoveryThreshold specifies the number of shares required to reconstruct the recovery key.
	// This must be less than or equal to RecoveryShares. Only available when using Auto Unseal.
	RecoveryThreshold int `json:"recovery_threshold,omitempty"`

	// RecoveryPGPKeys specifies an array of PGP public keys used to encrypt the output recovery keys.
	// The keys must be base64-encoded from their original binary representation.
	// The size of this array must be the same as RecoveryShares. Only available when using Auto Unseal.
	RecoveryPGPKeys []string `json:"recovery_pgp_keys,omitempty"`
}

// InitResponse is the response from the init endpoint
type InitResponse struct {
	// Keys contains the unseal keys (base64-encoded, potentially PGP-encrypted)
	Keys []string `json:"keys,omitempty"`

	// KeysBase64 contains the base64-encoded unseal keys
	KeysBase64 []string `json:"keys_base64,omitempty"`

	// RecoveryKeys contains the recovery keys (for auto-unseal, base64-encoded, potentially PGP-encrypted)
	RecoveryKeys []string `json:"recovery_keys,omitempty"`

	// RecoveryKeysBase64 contains the base64-encoded recovery keys
	RecoveryKeysBase64 []string `json:"recovery_keys_base64,omitempty"`

	// RootToken is the generated root token for system administration
	RootToken string `json:"root_token"`
}

// Init initializes the Warden server and generates a root token with default parameters.
func (c *Sys) Init() (*InitResponse, error) {
	return c.InitWithRequest(nil)
}

// InitWithRequest initializes the Warden server with custom parameters.
func (c *Sys) InitWithRequest(req *InitRequest) (*InitResponse, error) {
	return c.InitWithRequestAndContext(context.Background(), req)
}

// InitWithContext initializes the Warden server with context and default parameters.
func (c *Sys) InitWithContext(ctx context.Context) (*InitResponse, error) {
	return c.InitWithRequestAndContext(ctx, nil)
}

// InitWithRequestAndContext initializes the Warden server with context and custom parameters.
func (c *Sys) InitWithRequestAndContext(ctx context.Context, initReq *InitRequest) (*InitResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, "/v1/sys/init")

	if initReq == nil {
		initReq = &InitRequest{}
	}

	if err := r.SetJSONBody(initReq); err != nil {
		return nil, err
	}

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

	initResp := &InitResponse{}

	// Extract root token
	if rootToken, ok := resource.Data["root_token"].(string); ok {
		initResp.RootToken = rootToken
	}

	// Extract keys
	if keys, ok := resource.Data["keys"].([]interface{}); ok {
		initResp.Keys = make([]string, len(keys))
		for i, k := range keys {
			if keyStr, ok := k.(string); ok {
				initResp.Keys[i] = keyStr
			}
		}
	}

	// Extract keys_base64
	if keysBase64, ok := resource.Data["keys_base64"].([]interface{}); ok {
		initResp.KeysBase64 = make([]string, len(keysBase64))
		for i, k := range keysBase64 {
			if keyStr, ok := k.(string); ok {
				initResp.KeysBase64[i] = keyStr
			}
		}
	}

	// Extract recovery_keys
	if recoveryKeys, ok := resource.Data["recovery_keys"].([]interface{}); ok {
		initResp.RecoveryKeys = make([]string, len(recoveryKeys))
		for i, k := range recoveryKeys {
			if keyStr, ok := k.(string); ok {
				initResp.RecoveryKeys[i] = keyStr
			}
		}
	}

	// Extract recovery_keys_base64
	if recoveryKeysBase64, ok := resource.Data["recovery_keys_base64"].([]interface{}); ok {
		initResp.RecoveryKeysBase64 = make([]string, len(recoveryKeysBase64))
		for i, k := range recoveryKeysBase64 {
			if keyStr, ok := k.(string); ok {
				initResp.RecoveryKeysBase64[i] = keyStr
			}
		}
	}

	return initResp, nil
}

// RevokeRootToken revokes the current root token.
func (c *Sys) RevokeRootToken() error {
	return c.RevokeRootTokenWithContext(context.Background())
}

// RevokeRootTokenWithContext revokes the current root token with context.
func (c *Sys) RevokeRootTokenWithContext(ctx context.Context) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, "/v1/sys/revoke-root-token")
	if err := r.SetJSONBody(map[string]any{}); err != nil {
		return err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}