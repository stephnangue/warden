package core

import (
	"context"
	"fmt"
	"sort"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The MCP Skills extension (io.modelcontextprotocol/skills, SEP-2640) on the
// discovery server. Each skill is served as one resource,
// skill://<name>/SKILL.md, read with resources/read, enumerated with
// skills/list and described with skills/get. The read_skill tool serves the
// same bytes to clients without the extension.
//
// Every entry point serves only the skills visible to the presented identity
// (visibleSkills); a skill outside that set is answered exactly like one that
// does not exist.

// skillsExtension is the extension identifier declared in the server's
// capabilities.
const skillsExtension = "io.modelcontextprotocol/skills"

// skillTemplateURI is the resource template every Warden skill matches.
const skillTemplateURI = "skill://{name}/SKILL.md"

// foundationSkillCategories are the categories every identity sees whatever
// roles it holds: guidance about Warden itself rather than about a provider.
var foundationSkillCategories = map[string]bool{
	SkillCategoryShared:          true,
	SkillCategoryAgentFlow:       true,
	SkillCategoryTroubleshooting: true,
}

// skillResource is one file of a skill entry: a Warden skill has exactly one,
// its SKILL.md.
type skillResource struct {
	URI    string `json:"uri"`
	Digest string `json:"digest"`
	Size   int    `json:"size"`
}

// skillEntry describes one skill as skills/list and skills/get return it.
type skillEntry struct {
	URI         string           `json:"uri"`
	Frontmatter skillFrontmatter `json:"frontmatter"`
	Resources   []skillResource  `json:"resources"`
}

type skillsListParams struct {
	mcp.ParamsBase
	Cursor string `json:"cursor,omitempty"`
}

type skillsListResult struct {
	mcp.ResultBase
	mcp.Cacheable
	ResultType string       `json:"resultType"`
	Skills     []skillEntry `json:"skills"`
}

type skillsGetParams struct {
	mcp.ParamsBase
	URI string `json:"uri"`
}

type skillsGetResult struct {
	mcp.ResultBase
	ResultType string     `json:"resultType"`
	Skill      skillEntry `json:"skill"`
}

// visibleSkills returns the skills the presented identity may read, keyed by
// name: the skill of every role it can assume, the foundation skills, and
// every skill those name in requires, transitively.
func (c *Core) visibleSkills(ctx context.Context) (map[string]*Skill, error) {
	if c.skillStore == nil {
		return nil, fmt.Errorf("skill store not initialized")
	}
	// One read of the catalog serves both role resolution's existence checks
	// and the closure below. It is loaded lazily, so a call that fails
	// introspection (no credential) never reads it.
	var (
		byName  map[string]*Skill
		loadErr error
	)
	load := func() {
		if byName != nil || loadErr != nil {
			return
		}
		all, err := c.skillStore.List(ctx)
		if err != nil {
			loadErr = err
			return
		}
		byName = make(map[string]*Skill, len(all))
		for _, s := range all {
			byName[s.Name] = s
		}
	}

	roles, _, err := c.resolveDiscoveryWith(ctx, func(name string) bool {
		load()
		_, ok := byName[name]
		return ok
	})
	if err != nil {
		return nil, err
	}
	if load(); loadErr != nil {
		return nil, loadErr
	}

	var pending []string
	for name, s := range byName {
		if foundationSkillCategories[s.Category] {
			pending = append(pending, name)
		}
	}
	for _, r := range roles {
		if r.Skill == "" {
			continue
		}
		if name, err := parseSkillURI(r.Skill); err == nil {
			pending = append(pending, name)
		}
	}

	visible := make(map[string]*Skill)
	for len(pending) > 0 {
		name := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if _, seen := visible[name]; seen {
			continue
		}
		s, ok := byName[name]
		if !ok {
			continue
		}
		visible[name] = s
		pending = append(pending, s.Requires...)
	}
	return visible, nil
}

// visibleSkill returns the visible skill at uri, or nil when the URI is not a
// skill URI, names no skill, or names one the identity cannot see.
func (c *Core) visibleSkill(ctx context.Context, uri string) (*Skill, error) {
	name, err := parseSkillURI(uri)
	if err != nil {
		return nil, nil
	}
	visible, err := c.visibleSkills(ctx)
	if err != nil {
		return nil, err
	}
	return visible[name], nil
}

// skillEntryFor builds the extension's entry for s.
func (c *Core) skillEntryFor(s *Skill) (skillEntry, error) {
	r, err := c.skillRenders.get(s)
	if err != nil {
		return skillEntry{}, err
	}
	uri := skillURI(s.Name)
	return skillEntry{
		URI:         uri,
		Frontmatter: frontmatterFor(s),
		Resources:   []skillResource{{URI: uri, Digest: r.digest, Size: len(r.markdown)}},
	}, nil
}

// unknownSkillError is the answer for a skill URI the identity cannot read,
// whether it is malformed, names no skill or names an invisible one.
func unknownSkillError(uri string) error {
	return &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: fmt.Sprintf("unknown skill URI %q", uri)}
}

// registerSkillsExtension serves the Skills extension on the MCP server: the
// skill:// resource template and the skills/list and skills/get methods. The
// extension and resources capabilities are declared by the caller
// (discoveryServerCapabilities).
func (c *Core) registerSkillsExtension(server *mcp.Server) error {
	server.AddResourceTemplate(&mcp.ResourceTemplate{
		URITemplate: skillTemplateURI,
		Name:        "skill",
		Description: "An agent skill (SKILL.md) teaching how to drive a provider through Warden. " +
			"Roles from list_roles name theirs in their skill field.",
		MIMEType: "text/markdown",
	}, c.handleReadSkillResource)

	if err := mcp.AddReceivingCustomMethod(server, "skills/list", c.handleSkillsList); err != nil {
		return err
	}
	return mcp.AddReceivingCustomMethod(server, "skills/get", c.handleSkillsGet)
}

func (c *Core) handleReadSkillResource(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	uri := req.Params.URI
	s, err := c.visibleSkill(ctx, uri)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, mcp.ResourceNotFoundError(uri)
	}
	r, err := c.skillRenders.get(s)
	if err != nil {
		return nil, err
	}
	res := &mcp.ReadResourceResult{
		Contents: []*mcp.ResourceContents{{URI: uri, MIMEType: "text/markdown", Text: string(r.markdown)}},
	}
	// Whether this URI resolves depends on the identity, so no shared cache
	// may serve the answer to another caller. The SDK otherwise marks read
	// results public.
	res.CacheScope = "private"
	return res, nil
}

// handleSkillsList returns every visible skill, sorted by name. The set is
// small, so it is returned whole: no cursor is honoured or returned. The
// listing depends on the identity, so it must not be shared between callers.
func (c *Core) handleSkillsList(ctx context.Context, _ *mcp.ServerSession, p *skillsListParams) (*skillsListResult, error) {
	if p != nil && p.Cursor != "" {
		// No cursor is ever issued, so any cursor is invalid.
		return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: fmt.Sprintf("invalid cursor %q", p.Cursor)}
	}
	visible, err := c.visibleSkills(ctx)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(visible))
	for name := range visible {
		names = append(names, name)
	}
	sort.Strings(names)

	out := &skillsListResult{ResultType: "complete", Skills: make([]skillEntry, 0, len(names))}
	out.CacheScope = "private"
	for _, name := range names {
		e, err := c.skillEntryFor(visible[name])
		if err != nil {
			return nil, err
		}
		out.Skills = append(out.Skills, e)
	}
	return out, nil
}

func (c *Core) handleSkillsGet(ctx context.Context, _ *mcp.ServerSession, p *skillsGetParams) (*skillsGetResult, error) {
	if p == nil {
		return nil, unknownSkillError("")
	}
	s, err := c.visibleSkill(ctx, p.URI)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, unknownSkillError(p.URI)
	}
	e, err := c.skillEntryFor(s)
	if err != nil {
		return nil, err
	}
	return &skillsGetResult{ResultType: "complete", Skill: e}, nil
}

// discoveryServerCapabilities are the capabilities the discovery server
// declares: the SDK defaults (logging), resources, and the Skills extension.
// Tools are added by the SDK from the registered tools.
func discoveryServerCapabilities() *mcp.ServerCapabilities {
	caps := &mcp.ServerCapabilities{
		Logging:   &mcp.LoggingCapabilities{},
		Resources: &mcp.ResourceCapabilities{},
	}
	caps.AddExtension(skillsExtension, nil)
	return caps
}
