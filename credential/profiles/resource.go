package profiles

import (
	"fmt"

	"github.com/stephnangue/warden/credential"
)

// rejectExplicitResource refuses an explicit assertion_resource on a spec whose
// profile never emits warden_resource: that key's sole effect is the claim, so the
// spec would read as naming a resource while naming none. Unset is accepted — it
// means "derive", which is invisible to a config-only check, and the profile simply
// ignores the derived value — and so is "none", which asks for nothing.
func rejectExplicitResource(profile string, config credential.Config) error {
	if r := config.Get(credential.ConfigAssertionResource); r != "" && r != credential.AssertionResourceNone {
		return fmt.Errorf("field '%s': profile '%s' never emits warden_resource, so an explicit resource would have no effect; remove it or set it to '%s'",
			credential.ConfigAssertionResource, profile, credential.AssertionResourceNone)
	}
	return nil
}
