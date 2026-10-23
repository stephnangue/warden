package core

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/listener"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// mcpRole is a single role projected for the list_roles tool. The aggregator's
// auth_path is dropped: the agent acts through url and never needs the auth
// mount path.
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

	// hasAutoAuth reports whether the provider names an auto_auth_path, and
	// authMount is the path of the auth mount it resolves to ("" when it
	// resolves to none). Only roles in that auth mount can be used through
	// the provider's gateway.
	hasAutoAuth bool
	authMount   string

	// urlSuffix returns the provider's role-scoped entry point.
	urlSuffix func(role string) string
}

// resolveDiscovery runs the identity's role introspection and resolves each
// role's provider_path and skill into the provider type, skill URI and URL
// list_roles returns. A role whose provider or skill cannot be resolved is
// still listed, without the unresolved fields, and the reason goes into the
// returned warnings; the call fails only when introspection does (for
// example, no credential was presented).
func (c *Core) resolveDiscovery(ctx context.Context) ([]mcpRole, []string, error) {
	return c.resolveDiscoveryWith(ctx, c.discoverySkillChecker(ctx))
}

// resolveDiscoveryWith is resolveDiscovery with the skill-existence check
// supplied, for callers that already hold the skill catalog.
func (c *Core) resolveDiscoveryWith(ctx context.Context, skillExists func(name string) bool) ([]mcpRole, []string, error) {
	if c.systemBackend == nil {
		return nil, nil, fmt.Errorf("system backend not initialized")
	}
	httpReq := mcpRequestFromContext(ctx)
	if httpReq == nil {
		return nil, nil, fmt.Errorf("internal: request context missing")
	}
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, nil, err
	}

	// FieldData is ignored by the aggregator, so pass nil.
	resp, err := c.systemBackend.handleIntrospectRoles(ctx, &logical.Request{
		HTTPRequest: httpReq,
		ClientIP:    listener.ClientIP(httpReq),
	}, nil)
	if err != nil {
		return nil, nil, err
	}
	// A no-credential call comes back as a 401 with Err set (mirrors the
	// endpoint); surface it so the caller sees why.
	if resp != nil && resp.Err != nil {
		return nil, nil, resp.Err
	}

	var aggregated []aggregatedRole
	warnings := []string{}
	if resp != nil && resp.Data != nil {
		aggregated, _ = resp.Data["roles"].([]aggregatedRole)
		if w, ok := resp.Data["warnings"].([]string); ok {
			warnings = append(warnings, w...)
		}
	}

	providerPaths := make([]string, len(aggregated))
	for i, r := range aggregated {
		providerPaths[i] = r.ProviderPath
	}
	providers, err := c.resolveDiscoveryProviders(ctx, providerPaths)
	if err != nil {
		return nil, nil, err
	}

	roles := make([]mcpRole, len(aggregated))
	for i, r := range aggregated {
		// The gateway resolves the URL's role segment against the provider's
		// auth mount, so a URL is only given when that is the mount that
		// listed the role (otherwise it would not reach this role, or would
		// reach a same-named role elsewhere).
		roles[i], warnings = discoveryEntry(ns, r.Name, r.Description, r.Skill, r.ProviderPath, providers,
			func(p discoveryProvider) bool { return p.authMount == r.AuthPath }, skillExists, warnings)
	}
	return roles, warnings, nil
}

// discoveryEntry projects one listed role for list_roles: its provider type
// and URL when its provider_path resolves to a provider whose gateway can be
// used for it (reachable reports that for a provider with an auth mount), and
// its skill URI: the role's own skill when it exists, else the provider type's
// skill when the role has a URL and that skill ships. A field that cannot be
// resolved is left out and a warning appended to warnings says why; the
// warnings, returned, name the role and provider mounts only, never auth mount
// paths or provider configuration.
func discoveryEntry(ns *namespace.Namespace, name, description, skill, providerPath string,
	providers map[string]discoveryProvider, reachable func(discoveryProvider) bool,
	skillExists func(name string) bool, warnings []string) (mcpRole, []string) {
	role := mcpRole{Name: name, Description: description}
	label := fmt.Sprintf("role %q", name)

	resolved := skill
	if providerPath != "" {
		p, ok := providers[providerPath]
		switch {
		case !ok:
			warnings = append(warnings, fmt.Sprintf("%s: provider_path %q is not a provider mount in this namespace",
				label, providerPath))
		case !p.hasAutoAuth:
			warnings = append(warnings, fmt.Sprintf("%s: provider %q has no auto_auth_path, so no role can be used through it",
				label, p.path))
		case !reachable(p):
			warnings = append(warnings, fmt.Sprintf("%s: provider %q does not authenticate through this role's auth mount",
				label, p.path))
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
	if skill != "" && !skillExists(skill) {
		warnings = append(warnings, fmt.Sprintf("%s: skill %q does not exist", label, skill))
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
				p.hasAutoAuth = true
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
