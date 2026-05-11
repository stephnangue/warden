package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

const (
	skillStorePath = "core/skills/"
)

var (
	ErrSkillStoreClosed   = errors.New("skill store is closed")
	ErrSkillNotFound      = errors.New("skill not found")
	ErrSkillAlreadyExists = errors.New("skill already exists")
)

// SkillStore manages the global set of agent skill records.
//
// Skills are not per-namespace: every namespace's agents read the same
// catalog. Mutations are gated at the HTTP layer (PathsSpecial.Root); this
// store does not enforce authorization itself.
//
// Storage layout (under barrier view at "core/skills/"):
//
//	{skill-name}        -> JSON-encoded storedSkill
//	_meta/seeded        -> sentinel byte set after the one-time seed runs
//
// Skills are read-light and written rarely; no in-memory cache is
// maintained. Skill bodies are bounded (see maxSkillBodyBytes) so a
// straight List-then-Get is acceptable.
type SkillStore struct {
	core    *Core
	logger  *logger.GatedLogger
	storage sdklogical.Storage

	mu     sync.RWMutex
	closed bool
}

// storedSkill is the on-disk format. The Version field exists so future
// schema changes can be detected and migrated lazily on read.
type storedSkill struct {
	Version int    `json:"version"`
	Skill   *Skill `json:"skill"`
}

// NewSkillStore constructs the store. Storage is wired up later by
// LoadFromStorage so the store can be allocated before the barrier is ready.
func NewSkillStore(c *Core) *SkillStore {
	return &SkillStore{
		core:   c,
		logger: c.logger.WithSystem("skill.store"),
	}
}

// LoadFromStorage initializes the barrier-backed storage view. Called once
// the barrier is unsealed.
func (s *SkillStore) LoadFromStorage(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrSkillStoreClosed
	}
	if s.storage == nil {
		s.storage = NewBarrierView(s.core.barrier, skillStorePath)
	}
	s.logger.Debug("skill store initialized")
	return nil
}

// UnloadFromCache is the seal-time inverse of LoadFromStorage. There is no
// in-memory cache today, so this is a no-op — the BarrierView is left in
// place exactly as CredentialConfigStore.UnloadFromCache leaves its
// storage view. The hook exists so a future cache (e.g. parsed seed
// markdown) has a clear teardown point.
func (s *SkillStore) UnloadFromCache() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.logger.Debug("skill store cache unloaded (no-op)")
}

// Close shuts the store down. Idempotent.
func (s *SkillStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

// Create persists a new skill. Returns ErrSkillAlreadyExists if a skill
// with the same name already exists.
//
// Mutates the input: CreatedAt, UpdatedAt, Version, and (if empty) Origin
// are written back onto skill so callers can read them post-create. This
// matches CredentialConfigStore.CreateSpec behaviour.
func (s *SkillStore) Create(ctx context.Context, skill *Skill) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return ErrSkillStoreClosed
	}
	if s.storage == nil {
		return errors.New("skill store storage not initialized")
	}

	if err := validateSkill(skill); err != nil {
		return err
	}

	if skill.Origin == "" {
		skill.Origin = SkillOriginUser
	}
	if skill.Origin != SkillOriginSeed && skill.Origin != SkillOriginUser {
		return logical.ErrBadRequestf("invalid origin %q", skill.Origin)
	}

	existing, err := s.load(ctx, skill.Name)
	if err != nil && !errors.Is(err, ErrSkillNotFound) {
		return err
	}
	if existing != nil {
		return ErrSkillAlreadyExists
	}

	now := time.Now()
	skill.CreatedAt = now
	skill.UpdatedAt = now
	skill.Version = 1

	if err := s.persist(ctx, skill); err != nil {
		return err
	}

	s.logger.Info("created skill",
		logger.String("name", skill.Name),
		logger.String("category", skill.Category),
		logger.String("origin", skill.Origin),
	)
	return nil
}

// Get reads a single skill by name.
func (s *SkillStore) Get(ctx context.Context, name string) (*Skill, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrSkillStoreClosed
	}
	if s.storage == nil {
		return nil, errors.New("skill store storage not initialized")
	}

	return s.load(ctx, name)
}

// Update merges patch fields into the existing skill. Non-zero patch
// fields overwrite. CreatedAt, Origin, and Name are preserved from the
// existing record; Version is bumped.
func (s *SkillStore) Update(ctx context.Context, name string, patch *Skill) (*Skill, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrSkillStoreClosed
	}
	if s.storage == nil {
		return nil, errors.New("skill store storage not initialized")
	}

	existing, err := s.load(ctx, name)
	if err != nil {
		return nil, err
	}

	merged := *existing
	if patch != nil {
		if patch.Description != "" {
			merged.Description = patch.Description
		}
		if patch.Category != "" {
			merged.Category = patch.Category
		}
		if patch.Requires != nil {
			merged.Requires = patch.Requires
		}
		if patch.Upstream != "" {
			merged.Upstream = patch.Upstream
		}
		if patch.Body != "" {
			merged.Body = patch.Body
		}
		if patch.Provider != "" {
			merged.Provider = patch.Provider
		}
	}

	if err := validateSkill(&merged); err != nil {
		return nil, err
	}

	merged.UpdatedAt = time.Now()
	merged.Version = existing.Version + 1
	merged.CreatedAt = existing.CreatedAt
	merged.Origin = existing.Origin
	merged.Name = existing.Name

	if err := s.persist(ctx, &merged); err != nil {
		return nil, err
	}

	s.logger.Debug("updated skill",
		logger.String("name", name),
		logger.Int("version", merged.Version),
	)
	return &merged, nil
}

// Delete removes a skill by name. Returns ErrSkillNotFound if absent.
func (s *SkillStore) Delete(ctx context.Context, name string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return ErrSkillStoreClosed
	}
	if s.storage == nil {
		return errors.New("skill store storage not initialized")
	}

	if _, err := s.load(ctx, name); err != nil {
		return err
	}

	if err := s.storage.Delete(ctx, name); err != nil {
		return fmt.Errorf("failed to delete skill: %w", err)
	}

	s.logger.Info("deleted skill", logger.String("name", name))
	return nil
}

// List returns every skill record. Records are returned with full bodies;
// HTTP handlers strip Body for list responses. The internal _meta/ prefix
// is filtered out.
func (s *SkillStore) List(ctx context.Context) ([]*Skill, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrSkillStoreClosed
	}
	if s.storage == nil {
		return nil, errors.New("skill store storage not initialized")
	}

	keys, err := s.storage.List(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to list skills: %w", err)
	}

	skills := make([]*Skill, 0, len(keys))
	for _, key := range keys {
		// Skip internal metadata entries (e.g. _meta/seeded).
		if len(key) > 0 && key[0] == '_' {
			continue
		}
		skill, err := s.load(ctx, key)
		if err != nil {
			s.logger.Warn("failed to load skill during list",
				logger.String("name", key),
				logger.Err(err),
			)
			continue
		}
		skills = append(skills, skill)
	}
	return skills, nil
}

// load reads one skill record from storage. Returns ErrSkillNotFound if the
// key is absent. Caller must hold the read lock.
func (s *SkillStore) load(ctx context.Context, name string) (*Skill, error) {
	entry, err := s.storage.Get(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to read skill: %w", err)
	}
	if entry == nil {
		return nil, ErrSkillNotFound
	}

	var stored storedSkill
	if err := json.Unmarshal(entry.Value, &stored); err != nil {
		return nil, fmt.Errorf("failed to unmarshal skill %q: %w", name, err)
	}
	if stored.Skill == nil {
		return nil, fmt.Errorf("skill %q decoded to nil", name)
	}
	return stored.Skill, nil
}

// setupSkillStore is called during unseal to wire the SkillStore's
// storage view to the unsealed barrier and seed the foundation skills
// on first run. Provider-type skills follow a different lifecycle
// (seeded at provider mount time) and are not handled here.
func (c *Core) setupSkillStore(ctx context.Context) error {
	if c.skillStore == nil {
		return fmt.Errorf("skill store not initialized")
	}
	if err := c.skillStore.LoadFromStorage(ctx); err != nil {
		return err
	}
	if err := c.skillStore.SeedFoundation(ctx); err != nil {
		// Seed failures must not block unseal: agents can still operate
		// without the foundation catalog (the markdown is also embedded
		// in the binary). Log and continue.
		c.logger.Warn("failed to seed foundation skills", logger.Err(err))
	}
	return nil
}

// teardownSkillStore is the seal-time inverse of setupSkillStore.
func (c *Core) teardownSkillStore() error {
	if c.skillStore != nil {
		c.skillStore.UnloadFromCache()
	}
	return nil
}

// persist writes one skill record to storage. Caller must hold the read
// lock and have validated the skill.
func (s *SkillStore) persist(ctx context.Context, skill *Skill) error {
	stored := &storedSkill{
		Version: 1,
		Skill:   skill,
	}
	data, err := json.Marshal(stored)
	if err != nil {
		return fmt.Errorf("failed to marshal skill: %w", err)
	}
	entry := &sdklogical.StorageEntry{
		Key:   skill.Name,
		Value: data,
	}
	if err := s.storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to write skill: %w", err)
	}
	return nil
}
