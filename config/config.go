package config

import (
	"fmt"
	"time"

	"github.com/hashicorp/hcl/v2/hclsimple"
)

// Config is the configuration for warden server.
type Config struct {
	LogLevel           string `hcl:"log_level,optional"`
	LogFormat          string `hcl:"log_format,optional"`
	LogFile            string `hcl:"log_file,optional"`
	LogRotationPeriod  int    `hcl:"log_rotation_period,optional"`
	LogRotateMegabytes int    `hcl:"log_rotate_megabytes,optional"`
	LogRotateMaxFiles  int    `hcl:"log_rotate_max_files,optional"`

	Listeners []ListenerBlock `hcl:"listener,block"`
	Storage   *StorageBlock   `hcl:"storage,block"`
	Seals     []KMS `hcl:"seal,block"`

	// Whether read requests are disabled on standby nodes.
	DisableStandbyReads bool `hcl:"disable_standby_reads,optional"`

	// Rotation period bounds for credential sources.
	// Values must be valid Go duration strings (e.g., "24h", "720h").
	MinCredSourceRotationPeriod string `hcl:"min_cred_source_rotation_period,optional"`
	MaxCredSourceRotationPeriod string `hcl:"max_cred_source_rotation_period,optional"`

	// Rotation period bounds for credential specs that embed rotatable credentials.
	// Values must be valid Go duration strings (e.g., "1h", "720h").
	MinCredSpecRotationPeriod string `hcl:"min_cred_spec_rotation_period,optional"`
	MaxCredSpecRotationPeriod string `hcl:"max_cred_spec_rotation_period,optional"`

	// IPBindingPolicy controls how IP binding is enforced for tokens.
	// Valid values: "disabled", "optional", "required"
	// Defaults to "optional" if not specified.
	IPBindingPolicy string `hcl:"ip_binding_policy,optional"`
}

type KMS struct {
	Type string `hcl:"type,label"`
	UnusedKeys []string `hcl:"unused_keys,optional"`
	// Purpose can be used to allow a string-based specification of what this
	// KMS is designated for, in situations where we want to allow more than
	// one KMS to be specified
	Purpose []string `hcl:"purpose,optional"`
	Disabled string `hcl:"disabled,optional"`

	// config for static seal
	CurrentKeyID string `hcl:"current_key_id,optional"`
	CurrentKey string `hcl:"current_key,optional"`
	PreviousKeyID string `hcl:"previous_key_id,optional"`
	PreviousKey string `hcl:"previous_key,optional"`

	// config for transit seal
	Address string `hcl:"address,optional"`
	Token string `hcl:"token,optional"`
	KeyName string `hcl:"key_name,optional"`
	MountPath string `hcl:"mount_path,optional"`
	Namespace string `hcl:"namespace,optional"`
	DisableRenewal string `hcl:"disable_renewal,optional"`
	TlsCaCert string `hcl:"tls_ca_cert,optional"`
	TlsClientCert string `hcl:"tls_client_cert,optional"`
	TlsClientKey string `hcl:"tls_client_key,optional"`
	TlsServerName string `hcl:"tls_server_name,optional"`
	TlsSkipVerify string `hcl:"tls_skip_verify,optional"`

	// config for pkcs11 seal
	Lib string `hcl:"lib,optional"`
	Slot string `hcl:"slot,optional"`
	TokenLabel string `hcl:"token_label,optional"`
	Pin string `hcl:"pin,optional"`
	KeyLabel string `hcl:"key_label,optional"`
	KeyID string `hcl:"key_id,optional"`
	Mechanism string `hcl:"mechanism,optional"`
	DisableSoftwareEncryption bool `hcl:"disable_software_encryption,optional"`

	// config for ocikms seal
	CryptoEndpoint string `hcl:"crypto_endpoint,optional"`
	ManagementEndpoint string `hcl:"management_endpoint,optional"`
	AuthTypeApiKey bool `hcl:"auth_type_api_key,optional"`
	OciKeyID string `hcl:"key_id,optional"`

	// config for kmip seal
	KmsKeyId string `hcl:"kms_key_id,optional"`
	Endpoint string `hcl:"endpoint,optional"`
	ClientCert string `hcl:"client_cert,optional"`
	ClientKey string `hcl:"client_key,optional"`
	CaCert string `hcl:"ca_cert,optional"`
	ServerName string `hcl:"server_name,optional"`
	Timeout int `hcl:"timeout,optional"`
	EncryptAlg string `hcl:"encrypt_alg,optional"`
	Tls2Ciphers string `hcl:"tls12_ciphers,optional"`

	// config for gcpkms seal
	Credentials string `hcl:"credentials,optional"`
	Project string `hcl:"project,optional"`
	Region string `hcl:"region,optional"`
	KeyRing string `hcl:"key_ring,optional"`
	CryptoKey string `hcl:"crypto_key,optional"`

	// config for azurekeyvault seal
	TenantID string `hcl:"tenant_id,optional"`
	ClientID string `hcl:"client_id,optional"`
	ClientSecret string `hcl:"client_secret,optional"`
	Env string `hcl:"environment,optional"`
	VaultName string `hcl:"vault_name,optional"`
	AzureKeyName string `hcl:"key_name,optional"`
	Resource int `hcl:"resource,optional"`

	// config for awskms seal
	AwsRegion string `hcl:"region,optional"`
	AccessKey string `hcl:"access_key,optional"`
	SessionToken string `hcl:"session_token,optional"`
	SecretKey string `hcl:"secret_key,optional"`
	KmsKeyID string `hcl:"kms_key_id,optional"`
	AWSEndpoint string `hcl:"endpoint,optional"`
}

// Config returns the KMS configuration as a map
func (k *KMS) Config() map[string]string {
	config := make(map[string]string)

	// Add type (always present)
	config["type"] = k.Type

	// Add purpose if present
	if len(k.Purpose) > 0 {
		for i, p := range k.Purpose {
			config[fmt.Sprintf("purpose_%d", i)] = p
		}
	}

	// Add disabled flag if present
	if k.Disabled != "" {
		config["disabled"] = k.Disabled
	}

	// Static seal config
	if k.CurrentKeyID != "" {
		config["current_key_id"] = k.CurrentKeyID
	}
	if k.CurrentKey != "" {
		config["current_key"] = k.CurrentKey
	}
	if k.PreviousKeyID != "" {
		config["previous_key_id"] = k.PreviousKeyID
	}
	if k.PreviousKey != "" {
		config["previous_key"] = k.PreviousKey
	}

	// Transit seal config
	if k.Address != "" {
		config["address"] = k.Address
	}
	if k.Token != "" {
		config["token"] = k.Token
	}
	if k.KeyName != "" {
		config["key_name"] = k.KeyName
	}
	if k.MountPath != "" {
		config["mount_path"] = k.MountPath
	}
	if k.Namespace != "" {
		config["namespace"] = k.Namespace
	}
	if k.DisableRenewal != "" {
		config["disable_renewal"] = k.DisableRenewal
	}
	if k.TlsCaCert != "" {
		config["tls_ca_cert"] = k.TlsCaCert
	}
	if k.TlsClientCert != "" {
		config["tls_client_cert"] = k.TlsClientCert
	}
	if k.TlsClientKey != "" {
		config["tls_client_key"] = k.TlsClientKey
	}
	if k.TlsServerName != "" {
		config["tls_server_name"] = k.TlsServerName
	}
	if k.TlsSkipVerify != "" {
		config["tls_skip_verify"] = k.TlsSkipVerify
	}

	// PKCS11 seal config
	if k.Lib != "" {
		config["lib"] = k.Lib
	}
	if k.Slot != "" {
		config["slot"] = k.Slot
	}
	if k.TokenLabel != "" {
		config["token_label"] = k.TokenLabel
	}
	if k.Pin != "" {
		config["pin"] = k.Pin
	}
	if k.KeyLabel != "" {
		config["key_label"] = k.KeyLabel
	}
	if k.KeyID != "" {
		config["key_id"] = k.KeyID
	}
	if k.Mechanism != "" {
		config["mechanism"] = k.Mechanism
	}
	if k.DisableSoftwareEncryption {
		config["disable_software_encryption"] = "true"
	}

	// OCI KMS seal config
	if k.CryptoEndpoint != "" {
		config["crypto_endpoint"] = k.CryptoEndpoint
	}
	if k.ManagementEndpoint != "" {
		config["management_endpoint"] = k.ManagementEndpoint
	}
	if k.AuthTypeApiKey {
		config["auth_type_api_key"] = "true"
	}
	if k.OciKeyID != "" {
		config["oci_key_id"] = k.OciKeyID
	}

	// KMIP seal config
	if k.KmsKeyId != "" {
		config["kms_key_id"] = k.KmsKeyId
	}
	if k.Endpoint != "" {
		config["endpoint"] = k.Endpoint
	}
	if k.ClientCert != "" {
		config["client_cert"] = k.ClientCert
	}
	if k.ClientKey != "" {
		config["client_key"] = k.ClientKey
	}
	if k.CaCert != "" {
		config["ca_cert"] = k.CaCert
	}
	if k.ServerName != "" {
		config["server_name"] = k.ServerName
	}
	if k.Timeout != 0 {
		config["timeout"] = fmt.Sprintf("%d", k.Timeout)
	}
	if k.EncryptAlg != "" {
		config["encrypt_alg"] = k.EncryptAlg
	}
	if k.Tls2Ciphers != "" {
		config["tls12_ciphers"] = k.Tls2Ciphers
	}

	// GCP KMS seal config
	if k.Credentials != "" {
		config["credentials"] = k.Credentials
	}
	if k.Project != "" {
		config["project"] = k.Project
	}
	if k.Region != "" {
		config["region"] = k.Region
	}
	if k.KeyRing != "" {
		config["key_ring"] = k.KeyRing
	}
	if k.CryptoKey != "" {
		config["crypto_key"] = k.CryptoKey
	}

	// Azure KeyVault seal config
	if k.TenantID != "" {
		config["tenant_id"] = k.TenantID
	}
	if k.ClientID != "" {
		config["client_id"] = k.ClientID
	}
	if k.ClientSecret != "" {
		config["client_secret"] = k.ClientSecret
	}
	if k.Env != "" {
		config["environment"] = k.Env
	}
	if k.VaultName != "" {
		config["vault_name"] = k.VaultName
	}
	if k.AzureKeyName != "" {
		config["azure_key_name"] = k.AzureKeyName
	}
	if k.Resource != 0 {
		config["resource"] = fmt.Sprintf("%d", k.Resource)
	}

	// AWS KMS seal config
	if k.AwsRegion != "" {
		config["aws_region"] = k.AwsRegion
	}
	if k.AccessKey != "" {
		config["access_key"] = k.AccessKey
	}
	if k.SessionToken != "" {
		config["session_token"] = k.SessionToken
	}
	if k.SecretKey != "" {
		config["secret_key"] = k.SecretKey
	}
	if k.KmsKeyID != "" {
		config["kms_key_id"] = k.KmsKeyID
	}
	if k.AWSEndpoint != "" {
		config["aws_endpoint"] = k.AWSEndpoint
	}

	return config
}

func (k *KMS) IsDisabled() bool {
	return k.Disabled != "" && k.Disabled != "true" 
}

type StorageBlock struct {
	Type string `hcl:"type,label"` // "inmem", "file", or "postgres"

	RedirectAddr      string `hcl:"redirect_addr,optional"`
	ClusterAddr       string `hcl:"cluster_addr,optional"`
	DisableClustering bool `hcl:"diable_clustering,optional"`

	// In-memory storage specific config
	// (no additional config needed, but you could add cache size limits)

	// File storage specific config
	Path string `hcl:"path,optional"` // File system path for file backend

	// PostgreSQL storage specific config
	ConnectionUrl        string   `hcl:"connection_url,optional"`
	Table                string   `hcl:"table,optional"`                 // Table where data will be stored
	MaxIdleConnections   int      `hcl:"max_idle_connections,optional"`  // The maximum number of connections in the idle connection pool
	MaxParallel          string   `hcl:"max_parallel,optional"`          // The maximum number of concurrent requests to PostgreSQL
	HAEnabled            string   `hcl:"ha_enabled,optional"`            
	HATable              string   `hcl:"ha_table,optional"`              // The name of the table to use for storing High Availability information
	SkipCreateTable      string   `hcl:"skip_create_table,optional"`
	MaxConnectRetries    string   `hcl:"max_connect_retries,optional"`   // The maximum number of retries to perform when waiting for the database to be active
}

// Config returns the storage configuration as a map
func (s *StorageBlock) Config() map[string]string {
	config := make(map[string]string)

	// Add type (always present)
	config["type"] = s.Type

	// Add file storage config if present
	if s.Path != "" {
		config["path"] = s.Path
	}

	// Add PostgreSQL config if present
	if s.ConnectionUrl != "" {
		config["connection_url"] = s.ConnectionUrl
	}
	if s.Table != "" {
		config["table"] = s.Table
	}
	if s.MaxIdleConnections != 0 {
		config["max_idle_connections"] = fmt.Sprintf("%d", s.MaxIdleConnections)
	}
	if s.MaxParallel != "" {
		config["max_parallel"] = s.MaxParallel
	}
	if s.HAEnabled != "" {
		config["ha_enabled"] = s.HAEnabled
	}
	if s.HATable != "" {
		config["ha_table"] = s.HATable
	}
	if s.SkipCreateTable != "" {
		config["skip_create_table"] = s.SkipCreateTable
	}
	if s.MaxConnectRetries != "" {
		config["max_connect_retries"] = s.MaxConnectRetries
	}

	return config
}

type ListenerBlock struct {
	Type            string `hcl:"type,label"` // "tcp", "unix", etc.
	Address         string `hcl:"address"`
	TLSCertFile     string `hcl:"tls_cert_file,optional"`
	TLSKeyFile      string `hcl:"tls_key_file,optional"`
	TLSClientCAFile string `hcl:"tls_client_ca_file,optional"`
	TLSEnabled      bool   `hcl:"tls_enabled,optional"`
}

func LoadConfig(configFile string) (*Config, error) {
	var config Config

	// Load HCL using HashiCorp's hclsimple (easiest method)
	err := hclsimple.DecodeFile(configFile, nil, &config)
	if err != nil {
		return nil, err
	}

	// Validate rotation period bounds if set
	var minDur, maxDur time.Duration
	if config.MinCredSourceRotationPeriod != "" {
		minDur, err = time.ParseDuration(config.MinCredSourceRotationPeriod)
		if err != nil {
			return nil, fmt.Errorf("invalid min_cred_source_rotation_period %q: %w", config.MinCredSourceRotationPeriod, err)
		}
		if minDur <= 0 {
			return nil, fmt.Errorf("min_cred_source_rotation_period must be positive, got %s", minDur)
		}
	}
	if config.MaxCredSourceRotationPeriod != "" {
		maxDur, err = time.ParseDuration(config.MaxCredSourceRotationPeriod)
		if err != nil {
			return nil, fmt.Errorf("invalid max_cred_source_rotation_period %q: %w", config.MaxCredSourceRotationPeriod, err)
		}
		if maxDur <= 0 {
			return nil, fmt.Errorf("max_cred_source_rotation_period must be positive, got %s", maxDur)
		}
	}
	if minDur > 0 && maxDur > 0 && minDur > maxDur {
		return nil, fmt.Errorf("min_cred_source_rotation_period (%s) must be <= max_cred_source_rotation_period (%s)", minDur, maxDur)
	}

	// Validate spec rotation period bounds if set
	var minSpecDur, maxSpecDur time.Duration
	if config.MinCredSpecRotationPeriod != "" {
		minSpecDur, err = time.ParseDuration(config.MinCredSpecRotationPeriod)
		if err != nil {
			return nil, fmt.Errorf("invalid min_cred_spec_rotation_period %q: %w", config.MinCredSpecRotationPeriod, err)
		}
		if minSpecDur <= 0 {
			return nil, fmt.Errorf("min_cred_spec_rotation_period must be positive, got %s", minSpecDur)
		}
	}
	if config.MaxCredSpecRotationPeriod != "" {
		maxSpecDur, err = time.ParseDuration(config.MaxCredSpecRotationPeriod)
		if err != nil {
			return nil, fmt.Errorf("invalid max_cred_spec_rotation_period %q: %w", config.MaxCredSpecRotationPeriod, err)
		}
		if maxSpecDur <= 0 {
			return nil, fmt.Errorf("max_cred_spec_rotation_period must be positive, got %s", maxSpecDur)
		}
	}
	if minSpecDur > 0 && maxSpecDur > 0 && minSpecDur > maxSpecDur {
		return nil, fmt.Errorf("min_cred_spec_rotation_period (%s) must be <= max_cred_spec_rotation_period (%s)", minSpecDur, maxSpecDur)
	}

	// Validate ip_binding_policy if set
	if config.IPBindingPolicy != "" {
		switch config.IPBindingPolicy {
		case "disabled", "optional", "required":
			// valid
		default:
			return nil, fmt.Errorf("invalid ip_binding_policy %q: must be one of: disabled, optional, required", config.IPBindingPolicy)
		}
	}

	return &config, nil
}

// GetListenerByType returns a listener by its type (label)
func (c *Config) GetListenerByType(listenerType string) (*ListenerBlock, error) {
	for _, listener := range c.Listeners {
		if listener.Type == listenerType {
			return &listener, nil
		}
	}
	return nil, fmt.Errorf("listener of type '%s' not found", listenerType)
}

// GetTCPListener is a convenience method to get a TCP listener
func (c *Config) GetTCPListener() (*ListenerBlock, error) {
	return c.GetListenerByType("tcp")
}

// GetUnixListener is a convenience method to get a Unix socket listener
func (c *Config) GetUnixListener() (*ListenerBlock, error) {
	return c.GetListenerByType("unix")
}
