package vault

import "context"

type VaultClient interface {
	PutPolicy(ctx context.Context, namespace string, name string, policy string) error
	DeletePolicy(ctx context.Context, namespace string, policyName string) error
	PutEgpPolicy(ctx context.Context, namespace string, policyName string, paths []string, policy string, enforcementLevel string) error
	Health() (map[string]any, error)
	PutEntity(ctx context.Context, name string, metadata map[string]string) (string, error)
	PutEntityAlias(ctx context.Context, name string, entityId string, mountAccessor string) (string, error)
	RecycleEntity(ctx context.Context, name string, metadata map[string]string) (string, error)
	CreateTokenWithRole(ctx context.Context, roleName string, meta map[string]string, data map[string]any, policies []string) (map[string]any, error)
	CreateToken(ctx context.Context, namespace string, meta map[string]string, data map[string]any, policies []string) (map[string]any, error)
	GetAuthMountAccessor(ctx context.Context, mountPath string) (string, error)
	MountSecretEngine(ctx context.Context, namespace string, mountPath string, engineType string, description string, options map[string]string) error
	CheckIfMountExists(namespace string, mountPath string) (bool, *MountInfo, error)
	CreateTokenRole(ctx context.Context, roleName string, params map[string]interface{}) error
	CreateNamespace(ctx context.Context, parent, child string, meta map[string]any) error
	VaultAddress() string
	Start(ctx context.Context) error
	Stop()
}
