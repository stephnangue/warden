package storage

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/stephnangue/warden/backend/vault"
	"github.com/stephnangue/warden/logger"
)

type vaultStorage struct {
	*api.Client
	tokenManager *vault.TokenManager
	logger logger.Logger
	kvDbPath string
	namespace string
}

type VaultStorageConfig struct {
	Address   string
	AppRoleMountPath string
	RoleId	string
	SecretId string
	Namespace string
	KvMountPath string
	Logger logger.Logger
}

func NewVaultStorage(cfg VaultStorageConfig) (Storage, error) {
	apiCfg := api.DefaultConfig()
	apiCfg.Address = cfg.Address

	apiClient, err := api.NewClient(apiCfg)
	if err != nil {
		return nil, err
	}
	apiClient.SetNamespace(cfg.Namespace)

	appRoleConf := vault.AppRoleConfig{
		RoleID: cfg.RoleId,
		SecretID: cfg.SecretId,
		MountPath: cfg.AppRoleMountPath,
		Namespace: cfg.Namespace,
	}

	tokenMgtLogger := cfg.Logger.WithSubsystem("token-manager")
	tokenManager := vault.NewTokenManager(apiClient, &appRoleConf, tokenMgtLogger)

	return &vaultStorage{
		Client: apiClient,
		tokenManager: tokenManager,
		logger: cfg.Logger,
		kvDbPath: cfg.KvMountPath,
		namespace: cfg.Namespace,
	}, nil
}

// Start begins token management with AppRole authentication
func (v *vaultStorage) Init(ctx context.Context) error {
	return v.tokenManager.Start(ctx)
}

// Stop stops token management
func (v *vaultStorage) Stop() error {
	v.tokenManager.Stop()
	return nil
}

func (v *vaultStorage) Put(ctx context.Context, prefix string, key string, data map[string]any) error {
	path := fmt.Sprintf("%s/%s", prefix, key)
	_, err := v.WithNamespace(v.namespace).KVv2(v.kvDbPath).Put(ctx, path, data)
	return err
}

func (v *vaultStorage) Get(ctx context.Context, prefix string, key string) (map[string]any, error) {
	path := fmt.Sprintf("%s/%s", prefix, key)
	secret, err := v.WithNamespace(v.namespace).KVv2(v.kvDbPath).Get(ctx, path)
	if err != nil && !strings.Contains(err.Error(), "secret not found") {
        return nil, err
    }
    if secret == nil || secret.Data == nil {
        return nil, nil
    }
	return secret.Data, nil
}

func (v *vaultStorage) List(ctx context.Context, prefix string) ([]string, error) {
	cleanPrefix := strings.Trim(prefix, "/")
	path := fmt.Sprintf("%s/metadata/%s/", v.kvDbPath, cleanPrefix)
	secret, err := v.WithNamespace(v.namespace).Logical().List(path)
	if err != nil {
        return nil, err
    }
    if secret == nil || secret.Data == nil {
        return []string{}, nil
    }

    keysInterface, exists := secret.Data["keys"]
    if !exists {
        return []string{}, nil
    }

    keysSlice, ok := keysInterface.([]interface{})
    if !ok {
        return nil, fmt.Errorf("unexpected format for keys data")
    }

    var keys []string
    for _, key := range keysSlice {
        if keyStr, ok := key.(string); ok {
            keys = append(keys, keyStr)
        }
    }
    
    return keys, nil
}

func (v *vaultStorage) Delete(ctx context.Context, prefix string, key string) error {
	path := fmt.Sprintf("%s/%s", prefix, key)
	err := v.WithNamespace(v.namespace).KVv2(v.kvDbPath).DeleteMetadata(ctx, path)
	if err != nil {
        return err
    }
	return nil
}

