package core

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// Storage layout, under the barrier view at roleStorePath:
//
//	{namespace-uuid}/role/{name} -> JSON-encoded StoredRole
const (
	roleStorePath     = "core/roles/"
	roleKeySegment    = "role/"
	storedRoleVersion = 1
)

// StoredRole is the versioned storage format for a role. Version lets a later
// format be recognised on read; Hash is the role's content hash at the write.
type StoredRole struct {
	Version int           `json:"version"`
	Role    *logical.Role `json:"role"`
	Hash    string        `json:"hash"`
}

// roleListPrefix is the storage prefix listing one namespace's role names.
func roleListPrefix(nsUUID string) string {
	return nsUUID + "/" + roleKeySegment
}

// roleStorageKey is the storage key of one role.
func roleStorageKey(nsUUID, name string) string {
	return roleListPrefix(nsUUID) + name
}

// persistRole writes e to storage. Caller holds mu.
func (s *RoleStore) persistRole(ctx context.Context, nsUUID string, e *roleEntry) error {
	data, err := json.Marshal(&StoredRole{
		Version: storedRoleVersion,
		Role:    e.role,
		Hash:    e.hash,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal role: %w", err)
	}
	if err := s.storage.Put(ctx, &sdklogical.StorageEntry{
		Key:   roleStorageKey(nsUUID, e.role.Name),
		Value: data,
	}); err != nil {
		return fmt.Errorf("failed to write role %q: %w", e.role.Name, err)
	}
	return nil
}

// loadAllLocked reads every stored role into a new snapshot and returns it with
// the number of roles it holds. A listing that fails fails the load; a record
// that does not decode, or whose namespace no longer exists, is logged and
// skipped, so it reads as not found. Caller holds mu.
func (s *RoleStore) loadAllLocked(ctx context.Context) (*roleSnapshot, int, error) {
	nsKeys, err := s.storage.List(ctx, "")
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list role namespaces: %w", err)
	}

	snap := &roleSnapshot{byNS: make(map[string]*nsRoles, len(nsKeys))}
	count := 0
	for _, nsKey := range nsKeys {
		nsUUID := strings.TrimSuffix(nsKey, "/")
		ns, err := s.core.namespaceStore.GetNamespace(ctx, nsUUID)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to resolve namespace %q of stored roles: %w", nsUUID, err)
		}
		if ns == nil {
			s.logger.Warn("skipping roles stored for a namespace that does not exist",
				logger.String("namespace_uuid", nsUUID))
			continue
		}

		names, err := s.storage.List(ctx, roleListPrefix(nsUUID))
		if err != nil {
			return nil, 0, fmt.Errorf("failed to list roles of namespace %q: %w", ns.Path, err)
		}
		byName := make(map[string]*roleEntry, len(names))
		for _, name := range names {
			e, err := s.readRole(ctx, nsUUID, name)
			if err != nil {
				s.logger.Warn("skipping a stored role that cannot be read",
					logger.String("namespace", ns.Path),
					logger.String("name", name),
					logger.Err(err))
				continue
			}
			byName[name] = e
		}
		if len(byName) > 0 {
			snap.byNS[ns.ID] = &nsRoles{byName: byName}
			count += len(byName)
		}
	}
	return snap, count, nil
}

// readRole reads and decodes one stored role.
func (s *RoleStore) readRole(ctx context.Context, nsUUID, name string) (*roleEntry, error) {
	entry, err := s.storage.Get(ctx, roleStorageKey(nsUUID, name))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, ErrRoleNotFound
	}
	var stored StoredRole
	if err := json.Unmarshal(entry.Value, &stored); err != nil {
		return nil, fmt.Errorf("failed to decode: %w", err)
	}
	if stored.Version != storedRoleVersion {
		return nil, fmt.Errorf("unknown storage version %d", stored.Version)
	}
	if stored.Role == nil || stored.Role.Name != name {
		return nil, fmt.Errorf("record does not hold role %q", name)
	}
	hash := stored.Hash
	if hash == "" {
		hash = stored.Role.Hash()
	}
	// Published like a written role: as a clone, with no spare capacity left
	// behind by the decoder.
	return &roleEntry{role: stored.Role.Clone(), hash: hash}, nil
}
