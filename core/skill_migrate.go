package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// skillNamesMigratedMarkerKey records that MigrateSkillNames has run against
// this barrier view. Once set, the migration is a no-op.
const skillNamesMigratedMarkerKey = "_meta/names-agentskills"

// MigrateSkillNames renames stored skills whose names predate the Agent
// Skills naming rule (logical.ValidSkillName), replacing underscores with
// hyphens: the seeded mcp_aws and ansible_tower skills become mcp-aws and
// ansible-tower. `requires` entries naming a renamed skill are rewritten.
//
// A skill whose hyphenated name is still invalid, or is already taken by a
// different skill, is left in place and logged: the operator resolves it by
// hand. The migration runs once, guarded by a marker, and must only run on
// the active node.
func (s *SkillStore) MigrateSkillNames(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrSkillStoreClosed
	}
	if s.storage == nil {
		return errors.New("skill store storage not initialized")
	}

	marker, err := s.storage.Get(ctx, skillNamesMigratedMarkerKey)
	if err != nil {
		return fmt.Errorf("read migration marker: %w", err)
	}
	if marker != nil {
		return nil
	}

	keys, err := s.storage.List(ctx, "")
	if err != nil {
		return fmt.Errorf("list skills: %w", err)
	}
	byName := make(map[string]*Skill, len(keys))
	for _, key := range keys {
		if strings.HasPrefix(key, "_") {
			continue
		}
		skill, err := s.load(ctx, key)
		if err != nil {
			return fmt.Errorf("load %q: %w", key, err)
		}
		byName[key] = skill
	}

	now := time.Now()
	renamed := make(map[string]string)
	for oldName, skill := range byName {
		if !strings.Contains(oldName, "_") {
			continue
		}
		newName := strings.ReplaceAll(oldName, "_", "-")
		if !logical.ValidSkillName(newName) {
			s.logger.Warn("skill name is not a valid Agent Skills name and cannot be migrated automatically; rename it by hand",
				logger.String("name", oldName))
			continue
		}
		if existing, taken := byName[newName]; taken {
			// A previous run that was interrupted between writing the new
			// record and deleting the old one leaves both behind with the
			// same content: finish that run instead of reporting a clash.
			if !sameSkillContent(existing, skill) {
				s.logger.Warn("cannot migrate skill name: the hyphenated name is already taken; rename it by hand",
					logger.String("name", oldName), logger.String("taken", newName))
				continue
			}
		} else {
			moved := *skill
			moved.Name = newName
			moved.UpdatedAt = now
			moved.Version = skill.Version + 1
			if err := s.persist(ctx, &moved); err != nil {
				return fmt.Errorf("write %q: %w", newName, err)
			}
			byName[newName] = &moved
		}
		if err := s.storage.Delete(ctx, oldName); err != nil {
			return fmt.Errorf("delete %q: %w", oldName, err)
		}
		s.core.skillRenders.forget(oldName)
		delete(byName, oldName)
		renamed[oldName] = newName
		s.logger.Info("migrated skill name", logger.String("from", oldName), logger.String("to", newName))
	}

	if len(renamed) > 0 {
		for _, skill := range byName {
			changed := false
			for i, req := range skill.Requires {
				if to, ok := renamed[req]; ok {
					skill.Requires[i] = to
					changed = true
				}
			}
			if !changed {
				continue
			}
			skill.UpdatedAt = now
			skill.Version++
			if err := s.persist(ctx, skill); err != nil {
				return fmt.Errorf("rewrite requires of %q: %w", skill.Name, err)
			}
		}
	}

	if err := s.storage.Put(ctx, &sdklogical.StorageEntry{
		Key:   skillNamesMigratedMarkerKey,
		Value: []byte("1"),
	}); err != nil {
		return fmt.Errorf("write migration marker: %w", err)
	}
	return nil
}

// sameSkillContent reports whether two records carry the same skill apart
// from name, timestamps and version.
func sameSkillContent(a, b *Skill) bool {
	return a.Description == b.Description &&
		a.Category == b.Category &&
		a.Body == b.Body &&
		a.Upstream == b.Upstream &&
		a.Provider == b.Provider &&
		a.Origin == b.Origin
}
