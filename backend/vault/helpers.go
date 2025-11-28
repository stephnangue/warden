package vault

import (
	"context"
	"fmt"
	"strings"

	"github.com/stephnangue/warden/logger"

	"github.com/hashicorp/vault/api"
)

// MountInfo represents a simplified mount point
type MountInfo struct {
	Path        string
	Type        string
	Description string
}

// CheckIfMountExists checks if a mount already exists at the given path
func (c *Client) CheckIfMountExists(namespace string, mountPath string) (bool, *MountInfo, error) {
	// Normalize the path (ensure it ends with '/')
	if !strings.HasSuffix(mountPath, "/") {
		mountPath = mountPath + "/"
	}

	// Get all existing mounts
	mounts, err := c.WithNamespace(namespace).Sys().ListMounts()
	if err != nil {
		return false, nil, fmt.Errorf("failed to list mounts: %w", err)
	}

	// Check if our path exists
	for path, mount := range mounts {
		if path == mountPath {
			return true, &MountInfo{
				Path:        path,
				Type:        mount.Type,
				Description: mount.Description,
			}, nil
		}
	}

	return false, nil, nil
}

// MountSecretsEngine safely mounts a secrets engine only if it doesn't exist
func (c *Client) MountSecretEngine(ctx context.Context, namespace string, mountPath string, engineType string, description string, options map[string]string) error {
	exists, existingMount, err := c.CheckIfMountExists(namespace, mountPath)
	if err != nil {
		return fmt.Errorf("failed to check mount existence: %w", err)
	}

	if exists {
		// Check if it's the same type
		if existingMount.Type != engineType {
			return fmt.Errorf("mount path %s already exists with type %s, cannot mount %s",
				mountPath, existingMount.Type, engineType)
		}
		c.logger.Warn("mount already exist at the provide path", logger.String("path", mountPath), logger.String("type", engineType), logger.String("namespace", namespace))
		return nil
	}

	// Mount the secrets engine
	mountInput := &api.MountInput{
		Type:        engineType,
		Description: description,
		Options:     options,
	}

	err = c.WithNamespace(namespace).Sys().Mount(mountPath, mountInput)
	if err != nil {
		return fmt.Errorf("failed to mount secrets engine: %w", err)
	}

	return nil
}
