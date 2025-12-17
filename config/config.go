package config

import (
	"fmt"

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
}

type StorageBlock struct {
	Type string `hcl:"type,label"` // "inmem", "file", or "postgres"

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
	Name            string `hcl:"name,label"`
	Protocol        string `hcl:"protocol"`
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
	return &config, nil
}

// GetListenerByName returns a listener by its name (label)
func (c *Config) GetListenerByName(name string) (*ListenerBlock, error) {
	for _, listener := range c.Listeners {
		if listener.Name == name {
			return &listener, nil
		}
	}
	return nil, fmt.Errorf("listener '%s' not found", name)
}

// GetMySQLListener is a convenience method to get the MySQL listener
func (c *Config) GetMySQLListener() (*ListenerBlock, error) {
	return c.GetListenerByName("mysql")
}

// GetAuthListener is a convenience method to get the Api listener
func (c *Config) GetApiListener() (*ListenerBlock, error) {
	return c.GetListenerByName("api")
}
