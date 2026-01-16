package core

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
)

// StoredCredSpec is the versioned storage format for credential specs
type StoredCredSpec struct {
	Version     int               `json:"version"`
	NamespaceID string            `json:"namespace_id"`
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Source      string            `json:"source"`
	Config      map[string]string `json:"config"`
	MinTTL      string            `json:"min_ttl"` // Duration as string
	MaxTTL      string            `json:"max_ttl"` // Duration as string
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// StoredCredSource is the versioned storage format for credential sources
type StoredCredSource struct {
	Version     int               `json:"version"`
	NamespaceID string            `json:"namespace_id"`
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Config      map[string]string `json:"config"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// ============================================================================
// CredSpec Storage Operations
// ============================================================================

// persistSpec writes a credential spec to storage
func (s *CredentialConfigStore) persistSpec(namespaceID string, spec *credential.CredSpec) error {
	now := time.Now()

	stored := &StoredCredSpec{
		Version:     1,
		NamespaceID: namespaceID,
		Name:        spec.Name,
		Type:        spec.Type,
		Source:      spec.Source,
		Config:      spec.Config,
		MinTTL:      spec.MinTTL.String(),
		MaxTTL:      spec.MaxTTL.String(),
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	data, err := json.Marshal(stored)
	if err != nil {
		return fmt.Errorf("failed to marshal spec: %w", err)
	}

	path := fmt.Sprintf("%s%s/%s", credSpecPrefix, namespaceID, spec.Name)
	entry := &sdklogical.StorageEntry{
		Key:   path,
		Value: data,
	}

	if err := s.storage.Put(context.Background(), entry); err != nil {
		return fmt.Errorf("failed to write spec to storage: %w", err)
	}

	return nil
}

// loadSpec reads a credential spec from storage
func (s *CredentialConfigStore) loadSpec(namespaceID, name string) (*credential.CredSpec, error) {
	path := fmt.Sprintf("%s%s/%s", credSpecPrefix, namespaceID, name)

	entry, err := s.storage.Get(context.Background(), path)
	if err != nil {
		return nil, fmt.Errorf("failed to read spec from storage: %w", err)
	}
	if entry == nil {
		return nil, ErrSpecNotFound
	}

	var stored StoredCredSpec
	if err := json.Unmarshal(entry.Value, &stored); err != nil {
		return nil, fmt.Errorf("failed to unmarshal spec: %w", err)
	}

	minTTL, _ := time.ParseDuration(stored.MinTTL)
	maxTTL, _ := time.ParseDuration(stored.MaxTTL)

	spec := &credential.CredSpec{
		Name:   stored.Name,
		Type:   stored.Type,
		Source: stored.Source,
		Config: stored.Config,
		MinTTL: minTTL,
		MaxTTL: maxTTL,
	}

	return spec, nil
}

// deleteSpec removes a credential spec from storage
func (s *CredentialConfigStore) deleteSpec(namespaceID, name string) error {
	path := fmt.Sprintf("%s%s/%s", credSpecPrefix, namespaceID, name)

	if err := s.storage.Delete(context.Background(), path); err != nil {
		return fmt.Errorf("failed to delete spec from storage: %w", err)
	}

	return nil
}

// loadAllSpecs loads all credential specs for a namespace
func (s *CredentialConfigStore) loadAllSpecs(namespaceID string) ([]*credential.CredSpec, error) {
	path := fmt.Sprintf("%s%s/", credSpecPrefix, namespaceID)

	keys, err := s.storage.List(context.Background(), path)
	if err != nil {
		return nil, fmt.Errorf("failed to list specs: %w", err)
	}

	var specs []*credential.CredSpec
	for _, key := range keys {
		// Extract spec name from full path
		// Path format: specs/{namespace-uuid}/{spec-name}
		// Key format: {spec-name}
		spec, err := s.loadSpec(namespaceID, key)
		if err != nil {
			s.logger.Warn("failed to load spec from storage",
				logger.String("namespace", namespaceID),
				logger.String("source_name", key),
				logger.Err(err),
			)
			continue
		}
		specs = append(specs, spec)
	}

	return specs, nil
}

// ============================================================================
// CredSource Storage Operations
// ============================================================================

// persistSource writes a credential source to storage
func (s *CredentialConfigStore) persistSource(namespaceID string, source *credential.CredSource) error {
	now := time.Now()

	stored := &StoredCredSource{
		Version:     1,
		NamespaceID: namespaceID,
		Name:        source.Name,
		Type:        source.Type,
		Config:      source.Config,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	data, err := json.Marshal(stored)
	if err != nil {
		return fmt.Errorf("failed to marshal source: %w", err)
	}

	path := fmt.Sprintf("%s%s/%s", credSourcePrefix, namespaceID, source.Name)
	entry := &sdklogical.StorageEntry{
		Key:   path,
		Value: data,
	}

	if err := s.storage.Put(context.Background(), entry); err != nil {
		return fmt.Errorf("failed to write source to storage: %w", err)
	}

	return nil
}

// loadSource reads a credential source from storage
func (s *CredentialConfigStore) loadSource(namespaceID, name string) (*credential.CredSource, error) {
	path := fmt.Sprintf("%s%s/%s", credSourcePrefix, namespaceID, name)

	entry, err := s.storage.Get(context.Background(), path)
	if err != nil {
		return nil, fmt.Errorf("failed to read source from storage: %w", err)
	}
	if entry == nil {
		return nil, ErrSourceNotFound
	}

	var stored StoredCredSource
	if err := json.Unmarshal(entry.Value, &stored); err != nil {
		return nil, fmt.Errorf("failed to unmarshal source: %w", err)
	}

	source := &credential.CredSource{
		Name:   stored.Name,
		Type:   stored.Type,
		Config: stored.Config,
	}

	return source, nil
}

// deleteSource removes a credential source from storage
func (s *CredentialConfigStore) deleteSource(namespaceID, name string) error {
	path := fmt.Sprintf("%s%s/%s", credSourcePrefix, namespaceID, name)

	if err := s.storage.Delete(context.Background(), path); err != nil {
		return fmt.Errorf("failed to delete source from storage: %w", err)
	}

	return nil
}

// loadAllSources loads all credential sources for a namespace
func (s *CredentialConfigStore) loadAllSources(namespaceID string) ([]*credential.CredSource, error) {
	path := fmt.Sprintf("%s%s/", credSourcePrefix, namespaceID)

	keys, err := s.storage.List(context.Background(), path)
	if err != nil {
		return nil, fmt.Errorf("failed to list sources: %w", err)
	}

	var sources []*credential.CredSource
	for _, key := range keys {
		// Extract source name from full path
		// Path format: sources/{namespace-uuid}/{source-name}
		// Key format: {source-name}
		source, err := s.loadSource(namespaceID, key)
		if err != nil {
			s.logger.Warn("failed to load source from storage",
			logger.String("namespace", namespaceID),
			logger.String("source_name", key),
			logger.Err(err),
			)
			continue
		}
		sources = append(sources, source)
	}

	return sources, nil
}
