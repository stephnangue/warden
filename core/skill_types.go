package core

import (
	"regexp"
	"time"

	"github.com/stephnangue/warden/logical"
)

// Skill is an agent-facing capability description stored globally.
// Skills are markdown documents with structured metadata that agents read
// at discovery time. There is one global set, seeded at first system unseal
// and freely mutable by root admins thereafter; sub-namespace agents have
// read-only access.
type Skill struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Category    string    `json:"category"`
	Requires    []string  `json:"requires,omitempty"`
	Upstream    string    `json:"upstream,omitempty"`
	Body        string    `json:"body"`
	Origin      string    `json:"origin"`
	Provider    string    `json:"provider,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Version     int       `json:"version"`
}

// Skill category enum.
const (
	SkillCategoryAgentFlow       = "agent-flow"
	SkillCategoryShared          = "shared"
	SkillCategoryProviderGuide   = "provider-guide"
	SkillCategoryTroubleshooting = "troubleshooting"
	SkillCategoryCustom          = "custom"
)

// Skill origin enum. Origin is informational and does not gate mutation.
const (
	SkillOriginSeed = "seed"
	SkillOriginUser = "user"
)

// Skill validation limits. Name length is enforced by skillNameRegex
// directly (2-64 characters); the regex below is the authoritative bound.
const (
	maxSkillBodyBytes   = 256 * 1024
	maxSkillRequiresLen = 32
	maxSkillUpstreamLen = 256
	maxSkillProviderLen = 64
	maxSkillDescription = 1024
)

var skillNameRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,63}$`)

var skillCategories = map[string]struct{}{
	SkillCategoryAgentFlow:       {},
	SkillCategoryShared:          {},
	SkillCategoryProviderGuide:   {},
	SkillCategoryTroubleshooting: {},
	SkillCategoryCustom:          {},
}

// validateSkill enforces the skill schema. Returns logical.ErrBadRequest
// (400) on any failure so handlers can pass it straight through.
//
// Caller responsibilities:
//   - timestamps and Version are set by the store, not validated here.
//   - Origin defaults to "user" at the store level if empty.
//   - Provider-existence (does this driver factory exist?) is checked by the
//     caller against the live driver registry — this validator only enforces
//     shape, not cross-package referential integrity.
func validateSkill(s *Skill) error {
	if s == nil {
		return logical.ErrBadRequest("skill cannot be nil")
	}

	if !skillNameRegex.MatchString(s.Name) {
		return logical.ErrBadRequestf(
			"invalid skill name %q: must match %s",
			s.Name, skillNameRegex.String())
	}

	if s.Description == "" {
		return logical.ErrBadRequest("skill description cannot be empty")
	}
	if len(s.Description) > maxSkillDescription {
		return logical.ErrBadRequestf("skill description exceeds %d bytes", maxSkillDescription)
	}

	if _, ok := skillCategories[s.Category]; !ok {
		return logical.ErrBadRequestf(
			"invalid skill category %q: must be one of agent-flow, shared, provider-guide, troubleshooting, custom",
			s.Category)
	}

	if s.Body == "" {
		return logical.ErrBadRequest("skill body cannot be empty")
	}
	if len(s.Body) > maxSkillBodyBytes {
		return logical.ErrBadRequestf("skill body exceeds %d bytes", maxSkillBodyBytes)
	}

	if len(s.Requires) > maxSkillRequiresLen {
		return logical.ErrBadRequestf("skill requires exceeds %d entries", maxSkillRequiresLen)
	}
	for _, req := range s.Requires {
		if !skillNameRegex.MatchString(req) {
			return logical.ErrBadRequestf("invalid requires entry %q: must match %s", req, skillNameRegex.String())
		}
	}

	if len(s.Upstream) > maxSkillUpstreamLen {
		return logical.ErrBadRequestf("skill upstream exceeds %d bytes", maxSkillUpstreamLen)
	}

	if s.Category == SkillCategoryProviderGuide {
		if s.Provider == "" {
			return logical.ErrBadRequest("provider field is required for provider-guide category")
		}
	}
	if len(s.Provider) > maxSkillProviderLen {
		return logical.ErrBadRequestf("skill provider exceeds %d bytes", maxSkillProviderLen)
	}

	return nil
}
