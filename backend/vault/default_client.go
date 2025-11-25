package vault

import "context"

type DefaultClient struct {
}

func (c *DefaultClient) PutPolicy(ctx context.Context, namespace string, name string, policy string) error {
	return nil
}

func (c *DefaultClient) DeletePolicy(ctx context.Context, namespace string, policyName string) error {
	return nil
}

func (c *DefaultClient) PutEgpPolicy(ctx context.Context, namespace string, policyName string, paths []string, policy string, enforcementLevel string) error {
	return nil
}

func (c *DefaultClient) Health() (map[string]any, error) {
	return nil, nil
}

func (c *DefaultClient) PutEntity(ctx context.Context, name string, metadata map[string]string) (string, error) {
	return "", nil
}

func (c *DefaultClient) PutEntityAlias(ctx context.Context, name string, entityId string, mountAccessor string) (string, error) {
	return "", nil
}

func (c *DefaultClient) RecycleEntity(ctx context.Context, name string, metadata map[string]string) (string, error) {
	return "", nil
}

func (c *DefaultClient) CreateTokenWithRole(ctx context.Context, roleName string, meta map[string]string, data map[string]any, policies []string) (map[string]any, error) {
	return nil, nil
}

func (c *DefaultClient) CreateToken(ctx context.Context, namespace string, meta map[string]string, data map[string]any, policies []string) (map[string]any, error) {
	return nil, nil
}

func (c *DefaultClient) GetAuthMountAccessor(ctx context.Context, mountPath string) (string, error) {
	return "", nil
}

func (c *DefaultClient) MountSecretEngine(ctx context.Context, namespace string, mountPath string, engineType string, description string, options map[string]string) error {
	return nil
}

func (c *DefaultClient) CreateTokenRole(ctx context.Context, roleName string, params map[string]interface{}) error {
	return nil
}

func (c *DefaultClient) VaultAddress() string{
	return ""
}

func (c *DefaultClient) Start(ctx context.Context) error {
	return nil
}

func (c *DefaultClient) Stop() {
}



