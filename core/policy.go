package core

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/openbao/openbao/sdk/v2/helper/hclutil"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/internal/namespace"
)

const (
	DenyCapability   = "deny"
	CreateCapability = "create"
	ReadCapability   = "read"
	UpdateCapability = "update"
	DeleteCapability = "delete"
	ListCapability   = "list"
	SudoCapability   = "sudo"
	RootCapability   = "root"
	PatchCapability  = "patch"
	ScanCapability   = "scan"
)

const (
	DenyCapabilityInt uint32 = 1 << iota
	CreateCapabilityInt
	ReadCapabilityInt
	UpdateCapabilityInt
	DeleteCapabilityInt
	ListCapabilityInt
	SudoCapabilityInt
	PatchCapabilityInt
	ScanCapabilityInt
)

type PolicyType uint32

// CBP is meant for Capability-Based Policy. MCP policies are purely
// restrictive: they grant nothing on their own and are ANDed with the CBP
// decision at request time.
//
// These values are persisted verbatim in PolicyEntry.Type, so the ordering is
// storage-stable: append new types at the end, never reorder or reuse a value.
const (
	PolicyTypeCBP PolicyType = iota
	PolicyTypeMCP
)

func (p PolicyType) String() string {
	switch p {
	case PolicyTypeCBP:
		return "cbp"
	case PolicyTypeMCP:
		return "mcp"
	}

	return ""
}

var cap2Int = map[string]uint32{
	DenyCapability:   DenyCapabilityInt,
	CreateCapability: CreateCapabilityInt,
	ReadCapability:   ReadCapabilityInt,
	UpdateCapability: UpdateCapabilityInt,
	DeleteCapability: DeleteCapabilityInt,
	ListCapability:   ListCapabilityInt,
	SudoCapability:   SudoCapabilityInt,
	PatchCapability:  PatchCapabilityInt,
	ScanCapability:   ScanCapabilityInt,
}

// Policy is used to represent the policy specified by an CBP configuration.
type Policy struct {
	Name        string `hcl:"name"`
	DataVersion int
	CASRequired bool
	Paths       []*PathRules `hcl:"-"`
	Raw         string
	Type        PolicyType
	Templated   bool
	Expiration  time.Time
	Modified    time.Time
	namespace   *namespace.Namespace

	// info is the one-element granting-policies answer of every request this
	// policy alone grants. Built by finalize, before the policy is published
	// to the cache, so the request path never allocates it. Shared and read
	// only once published; nil on a policy that was never finalized.
	info []sdklogical.PolicyInfo
}

// grantRef is one policy merged into a compiled path entry after the first,
// with the capabilities its stanza brought.
type grantRef struct {
	policy *Policy
	caps   uint32
}

// policyInfo is the granting-policies record naming p.
func policyInfo(p *Policy) sdklogical.PolicyInfo {
	info := sdklogical.PolicyInfo{Name: p.Name, Type: "cbp"}
	if p.namespace != nil {
		info.NamespaceId, info.NamespacePath = p.namespace.ID, p.namespace.Path
	}
	return info
}

// grantInfo returns the slice naming p as sole granter: the shared one built
// by finalize, or, for a policy never finalized, a fresh one.
func (p *Policy) grantInfo() []sdklogical.PolicyInfo {
	if p.info != nil {
		return p.info
	}
	return []sdklogical.PolicyInfo{policyInfo(p)}
}

// finalize prepares a freshly built policy for sharing, once, before it is
// published to the policy cache: it builds the granting-policies slice and
// stamps each MCP rule-set with the policy's name. NewCBP then indexes the
// parsed objects as they are, without copying them; nothing writes them
// afterwards.
func (p *Policy) finalize() {
	p.info = []sdklogical.PolicyInfo{policyInfo(p)}
	for _, pc := range p.Paths {
		if pc == nil || pc.Permissions == nil {
			continue
		}
		for _, m := range pc.Permissions.MCP {
			m.SourcePolicy = p.Name
		}
	}
}

// ShallowClone returns a shallow clone of the policy. This should not be used
// if any of the reference-typed fields are going to be modified
func (p *Policy) ShallowClone() *Policy {
	return &Policy{
		Name:        p.Name,
		DataVersion: p.DataVersion,
		CASRequired: p.CASRequired,
		Paths:       p.Paths,
		Raw:         p.Raw,
		Type:        p.Type,
		Templated:   p.Templated,
		namespace:   p.namespace,
	}
}

// PathRules represents a policy for a path in the namespace.
type PathRules struct {
	Path                string
	Policy              string
	Permissions         *CBPPermissions
	IsPrefix            bool
	HasSegmentWildcards bool
	Capabilities        []string

	ExpirationRaw string    `hcl:"expiration"`
	Expiration    time.Time `hcl:"-"`

	// These keys are used at the top level to make the HCL nicer; we store in
	// the CBPPermissions object though
	AllowedParametersHCL      map[string][]any    `hcl:"allowed_parameters"`
	DeniedParametersHCL       map[string][]any    `hcl:"denied_parameters"`
	RequiredParametersHCL     []string            `hcl:"required_parameters"`
	PaginationLimitHCL        int                 `hcl:"pagination_limit"`
	ResponseKeysFilterPathHCL string              `hcl:"list_scan_response_keys_filter_path"`
	ConditionsHCL             map[string][]string `hcl:"conditions"`

	// ConditionHCL is the optional path-level CEL condition expression. The
	// rule applies only if it evaluates true (in addition to the structured
	// gates). Compiled at parse time into pc.Permissions.Conditions.
	ConditionHCL string `hcl:"condition"`

	// MCPHCL is the decode target for the removed `mcp { }` block. It exists
	// only so parsePaths can detect a policy still carrying one and reject it
	// with a directed error pointing at sys/policies/mcp/<name>; a non-nil
	// value never reaches canonicalisation.
	MCPHCL *MCPRulesHCL `hcl:"mcp"`
}

// MCPRulesHCL is the canonical decode shape of one MCP rule-set. An MCP
// policy's path stanza flattens into it (see mcpPolicyPathHCL.flatten), and
// it is also the decode target for the removed `mcp { }` block so that block
// can be detected and rejected. Each field corresponds to one
// operator-facing key; the parser canonicalises (lowercases) all entries and validates wildcard
// patterns before populating the internal CBPMCPRules form.
type MCPRulesHCL struct {
	AllowedMethods   []string            `hcl:"allowed_methods"`
	DeniedMethods    []string            `hcl:"denied_methods"`
	AllowedTools     []string            `hcl:"allowed_tools"`
	DeniedTools      []string            `hcl:"denied_tools"`
	AllowedResources []string            `hcl:"allowed_resources"`
	DeniedResources  []string            `hcl:"denied_resources"`
	AllowedPrompts   []string            `hcl:"allowed_prompts"`
	DeniedPrompts    []string            `hcl:"denied_prompts"`
	AllowedParams    map[string][]string `hcl:"allowed_params"`
	DeniedParams     map[string][]string `hcl:"denied_params"`
	Condition        string              `hcl:"condition"`
}

type CBPPermissions struct {
	CapabilitiesBitmap     uint32
	PaginationLimit        int
	ResponseKeysFilterPath string
	// owner is the policy whose stanza created this compiled entry, ownerCaps
	// the capabilities that stanza brought, and extra the policies merged in
	// after it. Together they answer grantingFor. Set by NewCBP on its own
	// copy; nil on a parsed stanza.
	owner     *Policy
	ownerCaps uint32
	extra     []grantRef
	// Conditions holds compiled path-level CEL conditions from all merged
	// policies for this path. nil means no condition (unconditional at this
	// layer). Non-nil: the gate passes if at least one program evaluates true
	// (OR across policies). Programs are immutable and shared (not deep-copied)
	// across merged CBPs.
	Conditions []*compiledCondition
	// MCP holds MCP rule-sets from all merged policies for this path.
	// nil/empty means no MCP enforcement applies. Non-nil: each entry is one
	// source stanza's rules; a request is allowed if at least one set
	// allows it (OR between sets), with the strongest-reason audit picked
	// on full deny. Populated by parsePaths via append per stanza so multiple
	// `path` blocks at the same path layer naturally into multiple rule-sets.
	MCP []*CBPMCPRules
}

// CBPMCPRules holds one merged MCP rule-set after validation and
// canonicalisation. All list entries are lowercased; param-name keys
// are lowercased and hyphens preserved. Patterns use trailing-`*` only
// per the policy Semantics; the parser rejects leading or internal `*`
// before constructing this type.
type CBPMCPRules struct {
	AllowedMethods   []string
	DeniedMethods    []string
	AllowedTools     []string
	DeniedTools      []string
	AllowedResources []string
	DeniedResources  []string
	AllowedPrompts   []string
	DeniedPrompts    []string
	// Condition is the optional per-call CEL condition for this rule-set,
	// compiled against the MCP env (call.* available). The set allows a call
	// only if its structural gates pass AND this condition evaluates true.
	Condition *compiledCondition

	// SourcePolicy names the MCP policy this rule-set came from, stamped onto
	// the decision for audit. Contracts are separately-owned documents, so
	// "which policy denied this?" is not answerable from the matched rule
	// alone. Set by the index at compile time, not by the parser.
	SourcePolicy string
}

// grantingFor names the policies whose stanzas brought capability cap to this
// compiled entry, owner first, then merged policies in insertion order. When
// the owner alone grants it, the answer is the owner's shared slice and costs
// no allocation; only a grant shared by several policies builds a new one.
func (p *CBPPermissions) grantingFor(cap uint32) []sdklogical.PolicyInfo {
	if p.owner == nil {
		return nil
	}
	n := 0
	if p.ownerCaps&cap != 0 {
		n++
	}
	for _, g := range p.extra {
		if g.caps&cap != 0 {
			n++
		}
	}
	switch {
	case n == 0:
		return nil
	case n == 1 && p.ownerCaps&cap != 0:
		return p.owner.grantInfo()
	}
	out := make([]sdklogical.PolicyInfo, 0, n)
	if p.ownerCaps&cap != 0 {
		out = append(out, policyInfo(p.owner))
	}
	for _, g := range p.extra {
		if g.caps&cap != 0 {
			out = append(out, policyInfo(g.policy))
		}
	}
	return out
}

// ParseCBPPolicy is used to parse the specified CBP rules into an
// intermediary set of policies, before being compiled into
// the CBP
func ParseCBPPolicy(ns *namespace.Namespace, rules string) (*Policy, error) {
	return parseCBPPolicy(ns, rules)
}

func parseCBPPolicy(ns *namespace.Namespace, rules string) (*Policy, error) {
	// Parse the rules
	root, err := hclutil.ParseConfig([]byte(rules))
	if err != nil {
		return nil, fmt.Errorf("failed to parse policy: %w", err)
	}

	// Top-level item should be the object list
	list, ok := root.Node.(*ast.ObjectList)
	if !ok {
		return nil, errors.New("failed to parse policy: does not contain a root object")
	}

	// Check for invalid top-level keys
	valid := []string{
		"name",
		"path",
	}
	if err := hclutil.CheckHCLKeys(list, valid); err != nil {
		return nil, fmt.Errorf("failed to parse policy: %w", err)
	}

	// Create the initial policy and store the raw text of the rules
	p := Policy{
		Raw:       rules,
		Type:      PolicyTypeCBP,
		namespace: ns,
	}
	if err := hcl.DecodeObject(&p, list); err != nil {
		return nil, fmt.Errorf("failed to parse policy: %w", err)
	}

	if o := list.Filter("path"); len(o.Items) > 0 {
		if err := parsePaths(&p, o); err != nil {
			return nil, fmt.Errorf("failed to parse policy: %w", err)
		}
	}
	// A parsed policy always carries Paths, empty for a body with no stanza:
	// nil reads as "never parsed" to PolicyStore.CBP, which would parse the
	// body again on every request that names this policy.
	if p.Paths == nil {
		p.Paths = []*PathRules{}
	}

	return &p, nil
}

func parsePaths(result *Policy, list *ast.ObjectList) error {
	paths := make([]*PathRules, 0, len(list.Items))
	for _, item := range list.Items {
		key := "path"
		if len(item.Keys) > 0 {
			key = item.Keys[0].Token.Value().(string)
		}

		valid := []string{
			"comment",
			"policy",
			"capabilities",
			"allowed_parameters",
			"denied_parameters",
			"required_parameters",
			"pagination_limit",
			"expiration",
			"list_scan_response_keys_filter_path",
			"conditions",
			"condition",
			"mcp",
		}
		if err := hclutil.CheckHCLKeys(item.Val, valid); err != nil {
			return multierror.Prefix(err, fmt.Sprintf("path %q:", key))
		}

		var pc PathRules

		// allocate memory so that DecodeObject can initialize the CBPPermissions struct
		pc.Permissions = new(CBPPermissions)

		pc.Path = key

		if err := hcl.DecodeObject(&pc, item.Val); err != nil {
			return multierror.Prefix(err, fmt.Sprintf("path %q:", key))
		}

		// Checked before the deny capability's `goto PathFinished`, which would
		// skip a check placed later in the loop body and let a denying stanza
		// carry the removed block forever. Because this rejects every non-nil
		// MCPHCL, no `mcp { }` block ever reaches canonicalisation — MCPHCL is
		// a detector, not a decode path (see its field doc).
		if pc.MCPHCL != nil {
			return fmt.Errorf("path %q: the mcp { } block has been removed from capability policies — "+
				"MCP rules now live in their own policy, written to sys/policies/mcp/<name>, whose "+
				"path stanzas group rules by what they govern:\n"+
				"    path %q {\n"+
				"      methods { allowed = [\"tools/call\"] }\n"+
				"      tools {\n"+
				"        allowed = [\"get_repository\"]\n"+
				"        denied  = [\"delete_*\"]\n"+
				"      }\n"+
				"    }\n"+
				"Create one and attach it to the token alongside this policy", key, key)
		}

		if len(pc.ExpirationRaw) > 0 {
			expiration, err := parseutil.ParseAbsoluteTime(pc.ExpirationRaw)
			if err != nil {
				return fmt.Errorf("path %q: invalid expiration time: %w", pc.Path, err)
			}

			pc.Expiration = expiration

			// If this path is expired, ignore it. We assume that the policy
			// author has set an overall expiration time of the last-valid
			// path for automatic cleanup.
			if time.Now().After(expiration) {
				// Skip the path because it has expired.
				continue
			}
		}

		normPath, isPrefix, hasSegmentWildcards, err := normalizePathPattern(result.namespace, pc.Path)
		if err != nil {
			return err
		}
		pc.Path = normPath
		pc.IsPrefix = isPrefix
		pc.HasSegmentWildcards = hasSegmentWildcards

		// Initialize the map
		pc.Permissions.CapabilitiesBitmap = 0
		for _, cap := range pc.Capabilities {
			switch cap {
			// If it's deny, don't include any other capability
			case DenyCapability:
				pc.Capabilities = []string{DenyCapability}
				pc.Permissions.CapabilitiesBitmap = DenyCapabilityInt
				goto PathFinished
			case CreateCapability, ReadCapability, UpdateCapability, DeleteCapability, ListCapability, SudoCapability, PatchCapability, ScanCapability:
				pc.Permissions.CapabilitiesBitmap |= cap2Int[cap]
			default:
				return fmt.Errorf("path %q: invalid capability %q", key, cap)
			}
		}

		if len(pc.AllowedParametersHCL) > 0 || len(pc.DeniedParametersHCL) > 0 || len(pc.RequiredParametersHCL) > 0 {
			return fmt.Errorf("path %q: required_parameters/allowed_parameters/denied_parameters have been removed — "+
				"express request-body constraints as a CEL `condition` over request.data, e.g. "+
				"condition = \"has(request.data.owner) && request.data.tier in ['gold','silver']\"", key)
		}
		if len(pc.ResponseKeysFilterPathHCL) > 0 {
			pc.Permissions.ResponseKeysFilterPath = pc.ResponseKeysFilterPathHCL
			if (pc.Permissions.CapabilitiesBitmap & ListCapabilityInt) == 0 {
				return errors.New("list_scan_response_keys_filter_path needs to be used on a path with the list capability")
			}

			tmpl, err := compileTemplatePathForFiltering(pc.Permissions.ResponseKeysFilterPath)
			if err != nil {
				return fmt.Errorf("unable to compile template for list_scan_response_keys_filter_path: %w", err)
			}

			// Use a random string to validate that key was used.
			keyOne, err := base62.Random(32)
			if err != nil {
				return fmt.Errorf("failed to generate random string to validate policy: %w", err)
			}

			keyTwo, err := base62.Random(32)
			if err != nil {
				return fmt.Errorf("failed to generate random string to validate policy: %w", err)
			}

			checkPathOne, err := useTemplateForFiltering(tmpl, pc.Path, keyOne)
			if err != nil {
				return fmt.Errorf("failed to validate list_scan_response_keys_filter_path: %w", err)
			}

			checkPathTwo, err := useTemplateForFiltering(tmpl, pc.Path, keyTwo)
			if err != nil {
				return fmt.Errorf("failed to validate list_scan_response_keys_filter_path: %w", err)
			}

			if checkPathOne == checkPathTwo && keyOne != keyTwo {
				return fmt.Errorf("list_scan_response_keys_filter_path resulted in same path for two different keys")
			}
		}

		pc.Permissions.PaginationLimit = pc.PaginationLimitHCL

		if len(pc.ConditionsHCL) > 0 {
			return fmt.Errorf("path %q: the conditions {} block has been removed — express it as a CEL `condition`. "+
				"source_ip → cidrContains(\"…\", request.client_ip); "+
				"time_window → now.getHours(tz)/getMinutes(tz); "+
				"day_of_week → now.getDayOfWeek(\"UTC\"); "+
				"token_metadata → agent.metadata.<key>", key)
		}

		if pc.ConditionHCL != "" {
			env, err := baseCELEnv()
			if err != nil {
				return fmt.Errorf("path %q: cel env: %w", key, err)
			}
			cond, err := compileCELCondition(env, pc.ConditionHCL)
			if err != nil {
				return fmt.Errorf("path %q condition: %w", key, err)
			}
			pc.Permissions.Conditions = []*compiledCondition{cond}
		}
	PathFinished:
		paths = append(paths, &pc)
	}

	result.Paths = paths
	return nil
}

// normalizePathPattern canonicalises a `path "..."` stanza key into the form
// the policy indexes are keyed on: leading slash stripped, namespace path
// prefixed, segment wildcards and trailing-glob prefixes detected.
//
// Both the CBP and the MCP parser call this. Sharing it is what guarantees the
// two indexes can never disagree on a path key — a divergence there would make
// MCP stanzas silently miss the requests they were written for.
func normalizePathPattern(ns *namespace.Namespace, key string) (path string, isPrefix, hasSegmentWildcards bool, err error) {
	path = key

	// Strip a leading '/' as paths start after the / in the API path
	if len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}

	// Ensure we are using the full request path internally
	path = ns.Path + path

	if strings.Contains(path, "+*") {
		return "", false, false, fmt.Errorf("path %q: invalid use of wildcards ('+*' is forbidden)", path)
	}

	if path == "+" || strings.Count(path, "/+") > 0 || strings.HasPrefix(path, "+/") {
		hasSegmentWildcards = true
	}

	if strings.HasSuffix(path, "*") {
		// If there are segment wildcards, don't actually strip the trailing
		// asterisk, but don't want to hit the default case
		if !hasSegmentWildcards {
			// Strip the glob character if found
			path = strings.TrimSuffix(path, "*")
			isPrefix = true
		}
	}

	return path, isPrefix, hasSegmentWildcards, nil
}

// canonicaliseMCPRules converts a parsed MCP rule-set into the
// internal CBPMCPRules form, validating wildcard patterns and
// lowercasing all entries so AllowOperation can do case-insensitive
// equality and prefix matching at request time without re-canonicalising.
func canonicaliseMCPRules(h *MCPRulesHCL) (*CBPMCPRules, error) {
	canonList := func(field string, in []string) ([]string, error) {
		if len(in) == 0 {
			return nil, nil
		}
		out := make([]string, len(in))
		for i, pat := range in {
			if err := validateMCPPattern(field, pat); err != nil {
				return nil, err
			}
			out[i] = strings.ToLower(pat)
		}
		return out, nil
	}
	r := &CBPMCPRules{}
	var err error
	if r.AllowedMethods, err = canonList("allowed_methods", h.AllowedMethods); err != nil {
		return nil, err
	}
	if r.DeniedMethods, err = canonList("denied_methods", h.DeniedMethods); err != nil {
		return nil, err
	}
	if r.AllowedTools, err = canonList("allowed_tools", h.AllowedTools); err != nil {
		return nil, err
	}
	if r.DeniedTools, err = canonList("denied_tools", h.DeniedTools); err != nil {
		return nil, err
	}
	if r.AllowedResources, err = canonList("allowed_resources", h.AllowedResources); err != nil {
		return nil, err
	}
	if r.DeniedResources, err = canonList("denied_resources", h.DeniedResources); err != nil {
		return nil, err
	}
	if r.AllowedPrompts, err = canonList("allowed_prompts", h.AllowedPrompts); err != nil {
		return nil, err
	}
	if r.DeniedPrompts, err = canonList("denied_prompts", h.DeniedPrompts); err != nil {
		return nil, err
	}
	if len(h.AllowedParams) > 0 || len(h.DeniedParams) > 0 {
		return nil, fmt.Errorf("mcp allowed_params/denied_params have been removed — " +
			"express argument constraints as a CEL `condition` over call.args, e.g. " +
			"condition = \"call.args.amount <= 1500 && call.args.currency in ['USD','EUR']\"")
	}
	if h.Condition != "" {
		env, err := mcpCELEnv()
		if err != nil {
			return nil, fmt.Errorf("mcp cel env: %w", err)
		}
		cond, err := compileCELCondition(env, h.Condition)
		if err != nil {
			return nil, fmt.Errorf("mcp condition: %w", err)
		}
		r.Condition = cond
	}
	return r, nil
}

// validateMCPPattern enforces the trailing-`*` glob rule from the policy
// Semantics: a `*` is allowed only as the final character of the pattern
// (or as the entire pattern, which is the zero-prefix wildcard matching
// everything). Leading and internal `*` are rejected with a clear error
// rather than silently treated as literals.
func validateMCPPattern(field, pat string) error {
	idx := strings.IndexByte(pat, '*')
	if idx == -1 {
		return nil // literal, no wildcard
	}
	if idx != len(pat)-1 {
		return fmt.Errorf("mcp %s: pattern %q has '*' in a non-trailing position; only trailing '*' wildcards are supported", field, pat)
	}
	return nil
}
