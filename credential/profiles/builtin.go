package profiles

import "github.com/stephnangue/warden/credential"

// defaultProfile is the single shared instance. Profiles are stateless, so one
// instance serves every request; Claims builds a fresh map per call.
var defaultProfile = &DefaultProfile{}

// Default returns the built-in default assertion profile — the same instance the
// registry serves.
//
// The issuer (for a nil AssertionClaims.Profile) and the request handler (for a nil
// registry) fall back through this rather than constructing the struct inline. The
// profile is stateless, so a second instance would behave identically today; routing
// every fallback through one accessor is what keeps it that way should the type ever
// grow state, and gives "which profile is the default" exactly one answer.
func Default() credential.AssertionProfile { return defaultProfile }

// RegisterBuiltinProfiles registers all built-in assertion profiles
func RegisterBuiltinProfiles(registry *credential.AssertionProfileRegistry) error {
	// Register the default (historical) claim shape
	if err := registry.Register(defaultProfile); err != nil {
		return err
	}

	// Register the AWS STS shape (composite sub + session tags; pinned to AWS sources)
	if err := registry.Register(&AWSProfile{}); err != nil {
		return err
	}

	// Register the registered-claims-only shape (for verifiers that bind iss/sub/aud
	// exactly, such as Entra ID; not source-pinned)
	if err := registry.Register(&MinimalProfile{}); err != nil {
		return err
	}

	return nil
}
