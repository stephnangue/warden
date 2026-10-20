package logical

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"time"
)

// Bounds on a role's free-form fields. The number of roles is not bounded: a
// role lookup is one map access however many there are.
const (
	MaxRoleDescriptionBytes = 1024
	MaxRoleMetadataKeys     = 32
)

// roleNameRegex is the name rule shared by every named object under sys/: a
// word character, optionally followed by word characters, '-' and '.', ending
// in a word character. It never admits '/'.
var roleNameRegex = regexp.MustCompile(`^\w(([\w-.]+)?\w)?$`)

// RoleNameRule is a human-readable statement of the rule enforced by
// ValidRoleName, for error messages.
const RoleNameRule = `letters, digits, "_", "-" and ".", starting and ending with a letter, digit or "_"`

// ValidRoleName reports whether name is a valid role name.
func ValidRoleName(name string) bool {
	return roleNameRegex.MatchString(name)
}

// Role is a namespace role: what a caller running under it may do (Policies,
// CredSpecName) and how discovery describes it (Description, Skill,
// ProviderPath).
//
// A *Role published by the role store is never written again: a write builds a
// new value and publishes it, so any number of readers share one without a
// lock. Code that wants to change a role works on Clone().
type Role struct {
	Name         string            `json:"name"`
	Description  string            `json:"description,omitempty"`
	Policies     []string          `json:"policies"` // sorted, deduplicated
	CredSpecName string            `json:"cred_spec_name,omitempty"`
	Skill        string            `json:"skill,omitempty"`
	ProviderPath string            `json:"provider_path,omitempty"` // with a trailing slash
	Metadata     map[string]string `json:"metadata,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// Clone returns a deep copy of r, or nil for a nil role.
func (r *Role) Clone() *Role {
	if r == nil {
		return nil
	}
	out := *r
	out.Policies = slices.Clone(r.Policies)
	out.Metadata = maps.Clone(r.Metadata)
	return &out
}

// Hash identifies the role's content: two roles with the same name, fields and
// metadata hash alike, whenever they were written. A writer that read a role
// passes its hash back to make the write conditional on nothing having changed
// since. Timestamps are not part of it.
func (r *Role) Hash() string {
	h := sha256.New()
	// Length-prefixed, so no choice of values can make two different roles
	// serialize to the same bytes.
	field := func(s string) { fmt.Fprintf(h, "%d:%s", len(s), s) }
	field(r.Name)
	field(r.Description)
	fmt.Fprintf(h, "%d:", len(r.Policies))
	for _, p := range r.Policies {
		field(p)
	}
	field(r.CredSpecName)
	field(r.Skill)
	field(r.ProviderPath)
	keys := slices.Sorted(maps.Keys(r.Metadata))
	fmt.Fprintf(h, "%d:", len(keys))
	for _, k := range keys {
		field(k)
		field(r.Metadata[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// rootPolicy is the policy that makes a token a root token. No login and no
// role may hand it out.
const rootPolicy = "root"

// nonAssignablePolicies are policies that exist but that no login and no role
// may hand out, beyond rootPolicy.
var nonAssignablePolicies = []string{}

// IsNonAssignablePolicy reports whether name is a policy that exists but may not
// be handed out. It does not cover rootPolicy, which is refused separately.
func IsNonAssignablePolicy(name string) bool {
	return slices.Contains(nonAssignablePolicies, name)
}

// ValidateAssignablePolicies refuses a policy list that holds the root policy or
// a non-assignable one. It is the one check for every place that hands policies
// to a caller: a login (LoginCreateToken) and a role write. The error is plain;
// each caller attaches the status it answers with.
func ValidateAssignablePolicies(policies []string) error {
	for _, p := range policies {
		if p == rootPolicy {
			return fmt.Errorf("policy %q cannot be assigned: it would grant a root token", rootPolicy)
		}
		if IsNonAssignablePolicy(p) {
			return fmt.Errorf("cannot assign policy %q", p)
		}
	}
	return nil
}
