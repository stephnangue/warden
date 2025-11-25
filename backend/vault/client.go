package vault

import (
	"context"
	"fmt"

	"github.com/stephnangue/warden/logger"

	vaultapi "github.com/hashicorp/vault/api"
)

type Client struct {
	*vaultapi.Client
	tokenManager *TokenManager
	logger logger.Logger
}

type Config struct {
	Address   string
	AuthMethod string
	AppRoleMountPath string
	RoleId	string
	SecretId string
	Namespace string
}

func NewClientWithTokenManager(cfg Config, logger logger.Logger) (VaultClient, error) {
	apiCfg := vaultapi.DefaultConfig()
	apiCfg.Address = cfg.Address
	
	apiClient, err := vaultapi.NewClient(apiCfg)
	if err != nil {
		return nil, err
	}
	apiClient.SetNamespace(cfg.Namespace)

	appRoleConf := AppRoleConfig{
		RoleID: cfg.RoleId,
		SecretID: cfg.SecretId,
		MountPath: cfg.AppRoleMountPath,
		Namespace: cfg.Namespace,
	}

	tokenMgtLogger := logger.WithSubsystem("token-manager")
	tokenManager := NewTokenManager(apiClient, &appRoleConf, tokenMgtLogger)

	return &Client{
		Client: apiClient,
		tokenManager: tokenManager,
		logger: logger,
	}, nil
}

// Start begins token management with AppRole authentication
func (c *Client) Start(ctx context.Context) error {
	return c.tokenManager.Start(ctx)
}

// Stop stops token management
func (c *Client) Stop() {
	c.tokenManager.Stop()
}

// SetMaxRetries configures the maximum number of renewal retries
func (c *Client) SetMaxRetries(maxRetries int) {
	c.tokenManager.maxRetries = maxRetries
}

func (c *Client) PutPolicy(ctx context.Context, namespace string, name string, policy string) error {
	err := c.WithNamespace(namespace).Sys().PutPolicyWithContext(ctx, name, policy)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) DeletePolicy(ctx context.Context, namespace string, policyName string) error {
	err := c.WithNamespace(namespace).Sys().DeletePolicyWithContext(ctx, policyName)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) PutEgpPolicy(ctx context.Context, namespace string, policyName string, paths []string, policy string, enforcementLevel string) error {
	path := fmt.Sprintf("sys/policies/egp/%s", policyName)
	data := map[string]any{
		"policy": policy,
		"enforcement_level": enforcementLevel,
		"paths": paths,
	}
	_, err := c.WithNamespace(namespace).Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) Health() (map[string]any, error) {
	health, err := c.WithNamespace("root").Sys().Health()
	if err != nil {
		return nil, err
	}
	// Convert the HealthResponse to a map for easier JSON serialization
	result := map[string]any{
		"Initialized":    health.Initialized,
		"Sealed":         health.Sealed,
		"Standby":        health.Standby,
		"PerformanceStandby": health.PerformanceStandby,
		"ReplicationPerformanceMode": health.ReplicationPerformanceMode,
		"ServerTimeUtc":   health.ServerTimeUTC,
		"Version":         health.Version,
		"ClusterName":     health.ClusterName,
		"ClusterID":       health.ClusterID,
		"Enterprise":      health.Enterprise,
	}
	return result, nil
}

func (c *Client) GetEntityId(ctx context.Context, name string) (string, error) {
	entity, err := c.Logical().ReadWithContext(ctx, 
		fmt.Sprintf("identity/entity/name/%s", name))
	if err != nil {
		return "",  err
	}
	if entity == nil {
		return "",  nil // Entity not found
	}
	return entity.Data["id"].(string), nil
}

func (c *Client) PutEntity(ctx context.Context, name string, metadata map[string]string) (string, error) {
	entityData := map[string]any{
		"name":     name,
		"metadata": metadata,
	}
	entity, err := c.Logical().Write("identity/entity", entityData)
	if err != nil {
		return "", err
	}
	if entity == nil || entity.Data == nil {
		return "", ErrFailedToCreateEntity
	}
	return entity.Data["id"].(string), nil
}

func (c *Client) PutEntityAlias(ctx context.Context, name string, entityId string, mountAccessor string) (string, error) {
	aliasData := map[string]any{
		"name":           name,
		"canonical_id":  entityId,
		"mount_accessor": mountAccessor,
	}
	data, err := c.Logical().Write("identity/entity-alias", aliasData)
	if err != nil {
		return "", err
	}
	return data.Data["id"].(string), nil
}

func (c *Client) RecycleEntity(ctx context.Context, name string, metadata map[string]string) (string, error) {
	_, err := c.Logical().Delete(fmt.Sprintf("identity/entity/name/%s", name))
	if err != nil {
		return "", err
	}
	return c.PutEntity(ctx, name, metadata)
}

func (c *Client) CreateTokenWithRole(ctx context.Context, roleName string, meta map[string]string, data map[string]any, policies []string) (map[string]any, error) {
	tokenData := map[string]any{
		"entity_alias": data["entity_alias"],
		"meta":         meta,
		"policies":  policies,
		"ttl":      data["ttl"],
		"renewable": data["renewable"],
		"type":     data["type"],
		"num_uses": data["num_uses"],
		"explicit_max_ttl": data["max_ttl"],
	}
	secret, err := c.Logical().WriteWithContext(ctx,
		fmt.Sprintf("auth/token/create/%s", roleName), tokenData)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Auth == nil {
		return nil, ErrInvalidAuthResponse
	}
	return map[string]any{
		"token": secret.Auth.ClientToken,
		"ttl":   secret.Auth.LeaseDuration,
	}, nil
}

func (c *Client) CreateToken(ctx context.Context, namespace string, meta map[string]string, data map[string]any, policies []string) (map[string]any, error) {
	tokenData := map[string]any{
		"meta":     meta,
		"policies": policies,
		"ttl":      data["ttl"],
		"renewable": data["renewable"],
		"type":     data["type"],
		"num_uses": data["num_uses"],
		"explicit_max_ttl": data["max_ttl"],
	}
	secret, err := c.WithNamespace(namespace).Logical().WriteWithContext(ctx, "auth/token/create", tokenData)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Auth == nil {
		return nil, ErrInvalidAuthResponse
	}
	return map[string]any{
		"token": secret.Auth.ClientToken,
		"ttl":   secret.Auth.LeaseDuration,
	}, nil
}

func (c *Client) GetAuthMountAccessor(ctx context.Context, mountPath string) (string, error) {
	mount, err := c.Logical().ReadWithContext(ctx, fmt.Sprintf("sys/auth/%s", mountPath))
	if err != nil {
		return "", err
	}
	if mount == nil || mount.Data == nil {
		return "", ErrFailedToRetrieveMount
	}
	return mount.Data["accessor"].(string), nil
}

func (c *Client) CreateTokenRole(ctx context.Context, roleName string, params map[string]interface{}) error {
	path := fmt.Sprintf("auth/token/roles/%s", roleName)

	_, err := c.Logical().WriteWithContext(ctx, path, params)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) CreateNamespace(ctx context.Context, parent, child string, meta map[string]any) error {
	path := fmt.Sprintf("sys/namespaces/%s", child)
	
	_, err := c.WithNamespace(parent).Logical().WriteWithContext(ctx, path, meta)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) VaultAddress() string {
	return c.Address()
}

