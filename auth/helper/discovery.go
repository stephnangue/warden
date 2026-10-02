package helper

import (
	"strings"

	"github.com/stephnangue/warden/logical"
)

// Field descriptions for the discovery fields every auth method's role
// carries. The discovery server (list_roles) turns them into the role's
// skill URI and the URL an agent calls.
const (
	SkillFieldDescription = "Name of the skill that teaches an agent to use this role. " +
		"Defaults to the skill of the provider at provider_path."
	ProviderPathFieldDescription = "Mount path of the provider this role is used with, relative to the " +
		"role's namespace (e.g. vault/). The discovery server derives the role's URL from it."
)

// maxProviderPathLen bounds provider_path; mount paths are short.
const maxProviderPathLen = 256

// ValidateDiscoveryFields checks the shape of a role's skill and
// provider_path and returns provider_path normalised to a trailing slash.
// Existence is not checked here: skills are global and providers can be
// mounted later, so the discovery server resolves both when it lists roles.
func ValidateDiscoveryFields(skill, providerPath string) (string, error) {
	if skill != "" && !logical.ValidSkillName(skill) {
		return "", logical.ErrBadRequestf("invalid skill %q: %s", skill, logical.SkillNameRule)
	}
	if providerPath == "" {
		return "", nil
	}
	if len(providerPath) > maxProviderPathLen {
		return "", logical.ErrBadRequestf("provider_path exceeds %d bytes", maxProviderPathLen)
	}
	if strings.HasPrefix(providerPath, "/") {
		return "", logical.ErrBadRequest(`provider_path must be relative to the namespace (no leading "/")`)
	}
	p := strings.TrimSuffix(providerPath, "/")
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", logical.ErrBadRequestf("invalid provider_path %q: empty, \".\" or \"..\" segment", providerPath)
		}
	}
	return p + "/", nil
}
