package core

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// mcpRole is a single role projected for the list_roles tool. It names no
// auth mount: the agent acts through url.
type mcpRole struct {
	Name        string `json:"name" jsonschema:"the role name the identity can assume"`
	Description string `json:"description,omitempty" jsonschema:"operator-written description of what the role is for"`
	Provider    string `json:"provider,omitempty" jsonschema:"type of the provider this role is used with (e.g. vault, aws, mcp)"`
	Skill       string `json:"skill,omitempty" jsonschema:"skill:// URI of the skill teaching how to use this role; read it with the read_skill tool, or with resources/read if your client supports MCP skills"`
	URL         string `json:"url,omitempty" jsonschema:"where to call the provider under this role, relative to the Warden address; the role's skill explains how to use it"`
}

// skillURIScheme prefixes every skill URI the discovery server hands out.
const skillURIScheme = "skill://"

// skillURI returns the URI of a skill's SKILL.md.
func skillURI(name string) string {
	return skillURIScheme + name + "/SKILL.md"
}

// parseSkillURI returns the skill name in a skill://<name>/SKILL.md URI.
func parseSkillURI(uri string) (string, error) {
	rest, ok := strings.CutPrefix(uri, skillURIScheme)
	if !ok {
		return "", fmt.Errorf("invalid skill URI %q: want skill://<name>/SKILL.md", uri)
	}
	name, ok := strings.CutSuffix(rest, "/SKILL.md")
	if !ok || !logical.ValidSkillName(name) {
		return "", fmt.Errorf("invalid skill URI %q: want skill://<name>/SKILL.md", uri)
	}
	return name, nil
}

// discoveryProvider is what list_roles needs to know about one provider mount.
type discoveryProvider struct {
	path string // mount path relative to the namespace, e.g. "vault/"
	typ  string

	// autoAuthPath is the auto_auth_path the provider names ("" for none),
	// and authMount the path of the auth mount it resolves to, relative to
	// the namespace and without "auth/" ("" when it resolves to none). The
	// provider's gateway admits every request through that mount, so a role
	// is served there only when it is granted there.
	autoAuthPath string
	authMount    string

	// urlSuffix returns the provider's role-scoped entry point.
	urlSuffix func(role string) string
}

// resolveDiscovery resolves the discovery of the request in ctx into the
// provider type, skill URI and URL of each granted role, as list_roles returns
// them (resolveDiscoveryWith). A role whose provider or skill cannot be
// resolved is still listed, without the unresolved fields, and the reason goes
// into the returned warnings; the call fails only when discovery does (for
// example, no credential was presented).
func (c *Core) resolveDiscovery(ctx context.Context) ([]mcpRole, []string, error) {
	return c.resolveDiscoveryWith(ctx, c.discoverySkillChecker(ctx))
}

// discoveryEntry projects one granted role for list_roles: its provider type
// and URL when its provider_path resolves to a provider whose auto_auth_path
// names an auth mount (discovery granted the role there, so the provider's
// gateway serves it), and its skill URI: the role's own skill when it exists,
// else the provider type's skill when the role has a URL and that skill ships.
// A field that cannot be resolved is left out and a warning appended to
// warnings says why; the warnings, returned, name the role, provider mounts
// and their auto_auth_path only, never an auth mount discovery admitted
// through or provider configuration.
func discoveryEntry(ns *namespace.Namespace, r *logical.Role, providers map[string]discoveryProvider,
	skillExists func(name string) bool, warnings []string) (mcpRole, []string) {
	name := r.Name
	role := mcpRole{Name: name, Description: r.Description}
	label := fmt.Sprintf("role %q", name)

	resolved := r.Skill
	if r.ProviderPath != "" {
		p, ok := providers[r.ProviderPath]
		switch {
		case !ok:
			warnings = append(warnings, fmt.Sprintf("%s: provider_path %q is not a provider mount in this namespace",
				label, r.ProviderPath))
		case p.autoAuthPath == "":
			warnings = append(warnings, fmt.Sprintf("%s: provider %q has no auto_auth_path, so no role can be used through it",
				label, p.path))
		case p.authMount == "":
			warnings = append(warnings, fmt.Sprintf("%s: provider %q: auto_auth_path %q names no auth mount",
				label, p.path, p.autoAuthPath))
		default:
			role.Provider = p.typ
			role.URL = mountURL(ns, p.path) + p.urlSuffix(name)
			if resolved == "" {
				// The provider's own skill, only when one ships: most
				// provider types have none, and a URI to nothing would
				// mislead.
				if def := logical.SkillNameForProvider(p.typ); skillExists(def) {
					resolved = def
				}
			}
		}
	}
	if r.Skill != "" && !skillExists(r.Skill) {
		warnings = append(warnings, fmt.Sprintf("%s: skill %q does not exist", label, r.Skill))
		resolved = ""
	}
	if resolved != "" {
		role.Skill = skillURI(resolved)
	}
	return role, warnings
}

// resolveDiscoveryProviders returns the namespace's provider mounts named in
// providerPaths (empty entries ignored), keyed by mount path, each resolved
// once: its auth mount and its role URL suffix. The mount table lock is held
// only for the copy.
func (c *Core) resolveDiscoveryProviders(ctx context.Context, providerPaths []string) (map[string]discoveryProvider, error) {
	wanted := make(map[string]struct{})
	for _, path := range providerPaths {
		if path != "" {
			wanted[path] = struct{}{}
		}
	}
	out := make(map[string]discoveryProvider, len(wanted))
	if len(wanted) == 0 {
		return out, nil
	}

	c.mountsLock.RLock()
	entries, err := c.mounts.findAllProviderMountsInNamespace(ctx)
	if err == nil {
		for _, e := range entries {
			if _, ok := wanted[e.Path]; ok {
				out[e.Path] = discoveryProvider{path: e.Path, typ: e.Type}
			}
		}
	}
	c.mountsLock.RUnlock()
	if err != nil {
		return nil, err
	}

	for path, p := range out {
		backend := c.router.MatchingBackend(ctx, path)
		p.urlSuffix = logical.DefaultRoleURLSuffix
		if up, ok := backend.(logical.RoleURLProvider); ok {
			p.urlSuffix = up.RoleURLSuffix
		}
		if tmp, ok := backend.(logical.TransparentModeProvider); ok {
			if autoAuthPath := tmp.GetAutoAuthPath(); autoAuthPath != "" {
				p.autoAuthPath = autoAuthPath
				// Resolve exactly as the gateway does (resolveTransparentIdentity):
				// the path verbatim, so discovery never vouches for a URL the
				// gateway would refuse.
				if e := c.router.MatchingMountEntry(ctx, autoAuthPath); e != nil && e.Class == mountClassAuth {
					p.authMount = e.Path
				}
			}
		}
		out[path] = p
	}
	return out, nil
}

// discoverySkillChecker returns a memoised existence check against the skill
// store, so each distinct skill name costs at most one storage read per call.
func (c *Core) discoverySkillChecker(ctx context.Context) func(name string) bool {
	seen := make(map[string]bool)
	return func(name string) bool {
		if exists, ok := seen[name]; ok {
			return exists
		}
		exists := false
		if c.skillStore != nil {
			_, err := c.skillStore.Get(ctx, name)
			exists = err == nil
			if err != nil && !errors.Is(err, ErrSkillNotFound) {
				c.logger.Warn("discovery: skill lookup failed", logger.String("skill", name), logger.Err(err))
			}
		}
		seen[name] = exists
		return exists
	}
}
