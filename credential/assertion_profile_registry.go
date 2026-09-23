package credential

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// AssertionProfileRegistry manages registered assertion profiles.
// This mirrors the TypeRegistry pattern in credential/type_registry.go.
type AssertionProfileRegistry struct {
	mu       sync.RWMutex
	profiles map[string]AssertionProfile // name -> AssertionProfile
}

// NewAssertionProfileRegistry creates a new assertion profile registry
func NewAssertionProfileRegistry() *AssertionProfileRegistry {
	return &AssertionProfileRegistry{
		profiles: make(map[string]AssertionProfile),
	}
}

// Register adds an assertion profile to the registry. It rejects duplicates and
// reserved names.
//
// The reserved-name rejection is where the id_jag reservation lives in code: it
// fires at startup when a builtin is added, not only when an operator writes one
// into a spec config.
func (r *AssertionProfileRegistry) Register(profile AssertionProfile) error {
	if profile == nil {
		return fmt.Errorf("%w: nil profile", ErrAssertionProfileInvalid)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	name := profile.Name()

	if IsReservedAssertionProfileName(name) {
		return fmt.Errorf("%w: %q", ErrAssertionProfileNameReserved, name)
	}

	// A profile that emits no typ header would sign an assertion with a blank
	// header value; refuse it at registration rather than at mint. Whitespace is
	// trimmed first: a typ of " " is functionally no typ, and accepting it would
	// sign `"typ":" "` into a header a verifier may well reject.
	if strings.TrimSpace(profile.Typ()) == "" {
		return fmt.Errorf("%w: %s", ErrAssertionProfileInvalid, name)
	}

	// Check for duplicate registration
	if _, exists := r.profiles[name]; exists {
		return fmt.Errorf("%w: %s", ErrAssertionProfileAlreadyRegistered, name)
	}

	r.profiles[name] = profile
	return nil
}

// GetByName retrieves an assertion profile by its name
func (r *AssertionProfileRegistry) GetByName(name string) (AssertionProfile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	profile, exists := r.profiles[name]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrAssertionProfileNotFound, name)
	}

	return profile, nil
}

// Resolve returns the named profile, or an "unknown assertion profile" error that
// lists what is registered. It is the single lookup both spec-create validation and
// mint-time resolution use, so the two can never disagree about which names exist
// or phrase the failure differently.
//
// The error is rebuilt rather than wrapping ErrAssertionProfileNotFound, to read
// exactly like its sibling "unknown credential type: %s (available types: %v)";
// callers that need the sentinel get it from GetByName.
func (r *AssertionProfileRegistry) Resolve(name string) (AssertionProfile, error) {
	r.mu.RLock()
	profile, exists := r.profiles[name]
	r.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("unknown assertion profile: %s (available profiles: %v)", name, r.ListProfiles())
	}
	return profile, nil
}

// ListProfiles returns all registered assertion profile names, SORTED.
//
// The one deliberate divergence from TypeRegistry.ListTypes, which returns map
// order: this list is interpolated into the "unknown assertion profile (available
// profiles: ...)" error, and map order would make that message — and its test —
// nondeterministic as soon as a second profile is registered.
func (r *AssertionProfileRegistry) ListProfiles() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.profiles))
	for name := range r.profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// HasProfile checks if an assertion profile is registered with the given name
func (r *AssertionProfileRegistry) HasProfile(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, exists := r.profiles[name]
	return exists
}
