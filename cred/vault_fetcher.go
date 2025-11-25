package cred

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/role"
)

// VaultFetcher fetches credentials from Vault KV secret engine
// or generates Vault dynamic secrets (database, aws, azure, gcp)
type VaultFetcher struct {
	vault *api.Client
	credSource *CredSource
	role *role.Role
	logger logger.Logger
}

func NewVaultFetcher(credSource *CredSource, role *role.Role, logger logger.Logger) (*VaultFetcher, error) {
	apiCfg := api.DefaultConfig()
	apiCfg.Address = credSource.Config["vault_address"]

	apiClient, err := api.NewClient(apiCfg)
	if err != nil {
		return nil, err
	}
	apiClient.SetNamespace(credSource.Config["vault_namespace"])

	return &VaultFetcher{
		vault: apiClient,
		credSource: credSource,
		role: role,
		logger: logger,
	}, nil
}

func (f *VaultFetcher) GetSourceType() string {
	return "vault"
}

func (f *VaultFetcher) FetchCredential(ctx context.Context) (*Credential, bool, error) {
	switch f.credSource.Config["auth_method"] {
		case "approle":
			err := f.loginViaApprole()
			if err != nil {
				return nil, false, err
			}
			switch f.role.Type {
				case "static_database_userpass":
					cred, err := f.readStaticDBSecretFromVault(ctx)
					if err != nil {
						return nil, false, err
					}
					return cred, true, nil
				case "dynamic_database_userpass":
					cred, err := f.readDynamicDBSecretFromVault(ctx)
					if err != nil {
						return nil, false, err
					}
					return cred, true, nil
				case "static_aws_access_keys":
					cred, err := f.readStaticAwsSecretFromVault(ctx)
					if err != nil {
						return nil, false, err
					}
					return cred, true, nil
				case "dynamic_aws_access_keys":
					cred, err := f.readDynamicAwsSecretFromVault(ctx)
					if err != nil {
						return nil, false, err
					}
					return cred, true, nil
				default:
					return nil, false, fmt.Errorf("unsupported role type : %s", f.role.Type)
			}
		default:
			return nil, false, fmt.Errorf("unsupported auth method : %s", f.credSource.Config["auth_method"])
	}
}

func (f *VaultFetcher) loginViaApprole() error {
	data := map[string]any{
		"role_id":   f.credSource.Config["role_id"],
		"secret_id": f.credSource.Config["secret_id"],
	}
	secret, err := f.vault.Logical().Write(fmt.Sprintf("auth/%s/login", f.credSource.Config["approle_mount"]), data)
	if err != nil {
		return fmt.Errorf("AppRole authentication failed: %w", err)
	}

	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("no auth info returned from AppRole login")
	}

	f.vault.SetToken(secret.Auth.ClientToken)

	return nil
}

func (f *VaultFetcher) readStaticDBSecretFromVault(ctx context.Context) (*Credential, error) {
	secret, err := f.vault.KVv2(f.role.CredConfig["kv2_mount"]).Get(ctx, f.role.CredConfig["secret_path"])
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("no secret found in path '%s' on mount '%s'", f.role.CredConfig["secret_path"], f.role.CredConfig["kv2_mount"])
	}

	username, ok1 := secret.Data["username"].(string)
	if !ok1 {
		return nil, fmt.Errorf("the secret '%s' on mount '%s' does not contains a key named 'username'", f.role.CredConfig["secret_path"], f.role.CredConfig["kv2_mount"])
	}
	password, ok1 := secret.Data["password"].(string)
	if !ok1 {
		return nil, fmt.Errorf("the secret '%s' on mount '%s' does not contains a key named 'password'", f.role.CredConfig["secret_path"], f.role.CredConfig["kv2_mount"])
	}
	database, ok1 := secret.Data["database"].(string)
	if !ok1 {
		return nil, fmt.Errorf("the secret '%s' on mount '%s' does not contains a key named 'database'", f.role.CredConfig["secret_path"], f.role.CredConfig["kv2_mount"])
	}

	cred := Credential{
		Type: DATABASE_USERPASS,
		Data: map[string]string{
			"username": username,
			"password": password,
			"database": database,
		},
	}
	return &cred, nil
}

func (f *VaultFetcher) readStaticAwsSecretFromVault(ctx context.Context) (*Credential, error) {
	secret, err := f.vault.KVv2(f.role.CredConfig["kv2_mount"]).Get(ctx, f.role.CredConfig["secret_path"])
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("no secret found in path '%s' on mount '%s'", f.role.CredConfig["secret_path"], f.role.CredConfig["kv2_mount"])
	}

	accessKeyId, ok1 := secret.Data["access_key_id"].(string)
	if !ok1 {
		return nil, fmt.Errorf("the secret '%s' on mount '%s' does not contains a key named 'access_key_id'", f.role.CredConfig["secret_path"], f.role.CredConfig["kv2_mount"])
	}
	secretAccessKey, ok1 := secret.Data["secret_access_key"].(string)
	if !ok1 {
		return nil, fmt.Errorf("the secret '%s' on mount '%s' does not contains a key named 'secret_access_key'", f.role.CredConfig["secret_path"], f.role.CredConfig["kv2_mount"])
	}

	cred := Credential{
		Type: AWS_ACCESS_KEYS,
		Data: map[string]string{
			"access_key_id": accessKeyId,
			"secret_access_key": secretAccessKey,
			"cred_source": f.vault.Address(),
		},
	}
	return &cred, nil
}

func (f *VaultFetcher) readDynamicDBSecretFromVault(ctx context.Context) (*Credential, error) {
	role, err := f.vault.Logical().ReadWithContext(ctx, fmt.Sprintf("%s/roles/%s", f.role.CredConfig["database_mount"], f.role.CredConfig["role_name"]))
	if err != nil {
		return nil, err
	}
	if role == nil || role.Data == nil {
		return nil, fmt.Errorf("the role '%s' on mount '%s' returned nothing", f.role.CredConfig["role_name"], f.role.CredConfig["database_mount"])
	}

	switch role.Data["credential_type"] {
		case "password":
			secret, err := f.vault.Logical().ReadWithContext(ctx, fmt.Sprintf("%s/creds/%s", f.role.CredConfig["database_mount"], f.role.CredConfig["role_name"]))
			if err != nil {
				return nil, err
			}
			if secret == nil || secret.Data == nil {
				return nil, fmt.Errorf("no dynamic secret returned with role '%s' on mount '%s'", f.role.CredConfig["role_name"], f.role.CredConfig["database_mount"])
			}

			database, exits := f.role.CredConfig["database"]
			if !exits {
				database = ""
			}

			cred := Credential{
				Type: DATABASE_USERPASS,
				LeaseTTL: time.Duration(secret.LeaseDuration) * time.Second,
				LeaseID: secret.LeaseID,
				Data: map[string]string{
					"database": database,
					"username": secret.Data["username"].(string),
					"password": secret.Data["password"].(string),
					"lease_ttl": fmt.Sprint(secret.LeaseDuration),
				},
			}
			return &cred, nil
		default:
			return nil, fmt.Errorf("unsupported vault database credential type : %s", role.Data["credential_type"])
	}
}

func (f *VaultFetcher) readDynamicAwsSecretFromVault(ctx context.Context) (*Credential, error) {
	role, err := f.vault.Logical().ReadWithContext(ctx, fmt.Sprintf("%s/roles/%s", f.role.CredConfig["aws_mount"], f.role.CredConfig["role_name"]))
	if err != nil {
		return nil, err
	}
	if role == nil || role.Data == nil {
		return nil, fmt.Errorf("the role '%s' on mount '%s' returned nothing", f.role.CredConfig["role_name"], f.role.CredConfig["aws_mount"])
	}

	switch role.Data["credential_type"] {
		case "assumed_role":
			path := fmt.Sprintf("%s/creds/%s", f.role.CredConfig["aws_mount"], f.role.CredConfig["role_name"])
			data := make(map[string]interface{})
			if f.role.CredConfig["role_name"] != "" {
				data["role_arn"] = f.role.CredConfig["role_arn"]
			}
			if f.role.CredConfig["role_session_name"] != "" {
				data["role_session_name"] = f.role.CredConfig["role_session_name"]
			}
			if f.role.CredConfig["ttl"] != "" {
				data["ttl"] = f.role.CredConfig["ttl"]
			}
		var secret *api.Secret
		var err error

		if len(data) > 0 {
			// POST request with parameters
			secret, err = f.vault.Logical().WriteWithContext(ctx, path, data)
		} else {
			// GET request without parameters
			secret, err = f.vault.Logical().ReadWithContext(ctx, path)
		}
		if err != nil {
			return nil, err
		}
		if secret == nil || secret.Data == nil {
			return nil, fmt.Errorf("no dynamic secret returned with role '%s' on mount '%s'", f.role.CredConfig["role_name"], f.role.CredConfig["aws_mount"])
		}

		cred := Credential{
			Type: AWS_ACCESS_KEYS,
			LeaseTTL: time.Duration(secret.LeaseDuration) * time.Second,
			LeaseID: secret.LeaseID,
			Data: map[string]string{
				"cred_source": f.vault.Address(),
			},
		}
		var ok bool

		cred.Data["access_key_id"], ok = secret.Data["access_key"].(string)
		if !ok {
			return nil, fmt.Errorf("access_key not found in response")
		}
		cred.Data["secret_access_key"], ok = secret.Data["secret_key"].(string)
		if !ok {
			return nil, fmt.Errorf("secret_key not found in response")
		}
		cred.Data["session_token"], ok = secret.Data["session_token"].(string)
		if !ok {
			return nil, fmt.Errorf("session_token not found in response")
		}
		cred.Data["security_token"], ok = secret.Data["security_token"].(string)
		if !ok {
			return nil, fmt.Errorf("security_token not found in response")
		}

		return &cred, nil

		default:
			return nil, fmt.Errorf("unsupported vault aws credential type : %s", role.Data["credential_type"])
	}
}