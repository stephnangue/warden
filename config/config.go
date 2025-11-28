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
	Type string `hcl:"type,label"` // "inmem", "file", or "raft"

	// In-memory storage specific config
	// (no additional config needed, but you could add cache size limits)

	// File storage specific config
	Path string `hcl:"path,optional"` // File system path for file backend

	// Raft storage specific config
	RaftNodeID        string   `hcl:"node_id,optional"`
	RaftAddress       string   `hcl:"address,optional"`        // This node's Raft address
	RaftDataDir       string   `hcl:"data_dir,optional"`       // Directory for Raft data
	RaftBootstrap     bool     `hcl:"bootstrap,optional"`      // Bootstrap a new cluster
	RaftJoinAddresses []string `hcl:"retry_join,optional"`     // Other nodes to join
	RaftMaxEntrySize  int      `hcl:"max_entry_size,optional"` // Max size of entries
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
