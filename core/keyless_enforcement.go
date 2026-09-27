package core

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/stephnangue/warden/config"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// KeylessEnforcementLevel is keyless_enforcement_level: what happens to an
// operator write that would leave a long-lived secret stored on the server.
type KeylessEnforcementLevel string

const (
	// KeylessEnforcementOff accepts the write silently.
	KeylessEnforcementOff KeylessEnforcementLevel = "off"
	// KeylessEnforcementWarn accepts the write and returns a warning (default).
	KeylessEnforcementWarn KeylessEnforcementLevel = "warn"
	// KeylessEnforcementEnforce refuses the write.
	KeylessEnforcementEnforce KeylessEnforcementLevel = "enforce"
)

const (
	keylessKindSource = "credential source"
	keylessKindSpec   = "credential spec"
)

// localSourceSecret is what a spec on the local source reports. That source
// hands the spec's own config out as the credential, so such a spec holds a
// secret by construction, whatever its type declares.
const localSourceSecret = "local source: the spec config is the credential"

// parseKeylessEnforcementLevel resolves the configured level. The config loader
// has already refused an unknown value; an absent one is warn, so a keyed write
// is flagged without breaking a server that never set the key.
func parseKeylessEnforcementLevel(conf *config.Config) KeylessEnforcementLevel {
	if conf == nil || conf.KeylessEnforcementLevel == "" {
		return KeylessEnforcementWarn
	}
	return KeylessEnforcementLevel(conf.KeylessEnforcementLevel)
}

// KeylessEnforcementLevel returns the configured keyless_enforcement_level.
func (c *Core) KeylessEnforcementLevel() KeylessEnforcementLevel {
	return c.keylessEnforcement
}

// checkKeyless applies keyless_enforcement_level to an operator write whose
// result would leave the named secrets stored. It returns a warning under warn,
// a bad-request error under enforce, and nothing under off or when secrets is
// empty.
//
// Enforcement belongs to the handlers, for the reason SystemManagedConfig gives:
// internal writers — rotation, the refresh-token write-back, the connect seal —
// go through the same store validators and must keep working for a source or
// spec created before the level was raised. They bypass this by construction.
// Any new operator surface that writes source or spec config must call it too,
// or the guarantee is only as wide as the paths that remember it.
func (c *Core) checkKeyless(kind, name string, secrets []string) (warnings []string, err error) {
	if len(secrets) == 0 || c.keylessEnforcement == KeylessEnforcementOff {
		return nil, nil
	}

	held := strings.Join(secrets, ", ")
	hint := "Fetch the secret with secret_spec (credential chaining), exchange the caller's identity with subject_token_source, or use a keyless source."
	if kind == keylessKindSource {
		hint = "Use a keyless source instead: auth_method=oidc_federation (federation) or secret_spec (credential chaining)."
	}

	if c.keylessEnforcement == KeylessEnforcementEnforce {
		return nil, logical.ErrBadRequestf("keyless_enforcement_level=enforce refuses %s %q: it would store %s. %s",
			kind, name, held, hint)
	}
	return []string{fmt.Sprintf("%s %q stores %s; keyless_enforcement_level=enforce would refuse this write. %s",
		kind, name, held, hint)}, nil
}

// logKeylessWarnings records warnings from checkKeyless once the write they
// describe has succeeded, so a write the store then refuses leaves no trace.
func (c *Core) logKeylessWarnings(kind, name string, warnings []string) {
	for _, w := range warnings {
		c.logger.Warn(w, logger.String("kind", kind), logger.String("name", name))
	}
}

// specKeylessSecrets returns what a spec write would leave stored: the spec's own
// secrets, the local-source rule, and — when withSource is set — the secrets its
// source holds, each prefixed with the source name.
//
// withSource is set on create only. A new spec on a keyed source widens the use
// of that source's secret; an edit to an existing spec does not, and the
// source's secret is judged on the source's own writes.
//
// A missing source is not an error here: the store refuses the write with its
// own message, and the spec's own secrets are still reported.
func (b *SystemBackend) specKeylessSecrets(ctx context.Context, spec *credential.CredSpec, withSource bool) ([]string, error) {
	secrets := b.core.specStoredSecrets(spec.Type, spec.Config)

	source, err := b.core.credConfigStore.GetSource(ctx, spec.Source)
	if err != nil {
		if errors.Is(err, ErrSourceNotFound) {
			return secrets, nil
		}
		return nil, err
	}

	if source.Type == credential.SourceTypeLocal {
		secrets = append(secrets, localSourceSecret)
	}
	if withSource {
		for _, s := range b.core.sourceStoredSecrets(source.Type, source.Config) {
			secrets = append(secrets, fmt.Sprintf("source %q: %s", source.Name, s))
		}
	}
	return secrets, nil
}

// checkSpecKeyless runs checkKeyless for a spec write, returning the warnings to
// report on success or the error response to return instead.
func (b *SystemBackend) checkSpecKeyless(ctx context.Context, spec *credential.CredSpec, withSource bool) ([]string, *logical.Response) {
	secrets, err := b.specKeylessSecrets(ctx, spec, withSource)
	if err != nil {
		return nil, logical.ErrorResponse(err)
	}
	warnings, err := b.core.checkKeyless(keylessKindSpec, spec.Name, secrets)
	if err != nil {
		return nil, logical.ErrorResponse(err)
	}
	return warnings, nil
}

// appendWarnings adds warnings to a response's data["warnings"], keeping any
// already there.
func appendWarnings(data map[string]any, warnings ...string) {
	if len(warnings) == 0 {
		return
	}
	existing, _ := data["warnings"].([]string)
	data["warnings"] = append(existing, warnings...)
}
