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
	"github.com/mitchellh/copystructure"
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

// CPB is meant for Capability-Based Policy
const (
	PolicyTypeCBP PolicyType = iota
)

func (p PolicyType) String() string {
	switch p {
	case PolicyTypeCBP:
		return "cbp"
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

	// MCPHCL is the parsed `mcp { }` block. Nil when no such block is
	// present on this path stanza. Stored on PathRules as the HCL
	// decode target; the parser then validates it and appends a
	// CBPMCPRules entry to pc.Permissions.MCP.
	MCPHCL *MCPRulesHCL `hcl:"mcp"`
}

// MCPRulesHCL is the HCL decode shape of one `mcp { }` block. Each
// field corresponds to one operator-facing key inside the block; the
// parser canonicalises (lowercases) all entries and validates wildcard
// patterns before populating the internal CBPMCPRules form.
type MCPRulesHCL struct {
	AllowedMethods   []string            `hcl:"allowed_methods"`
	DeniedMethods    []string            `hcl:"denied_methods"`
	AllowedTools     []string            `hcl:"allowed_tools"`
	DeniedTools      []string            `hcl:"denied_tools"`
	AllowedResources []string            `hcl:"allowed_resources"`
	AllowedPrompts   []string            `hcl:"allowed_prompts"`
	AllowedParams    map[string][]string `hcl:"allowed_params"`
	DeniedParams     map[string][]string `hcl:"denied_params"`
}

type CBPPermissions struct {
	CapabilitiesBitmap     uint32
	AllowedParameters      map[string][]any
	DeniedParameters       map[string][]any
	RequiredParameters     []string
	PaginationLimit        int
	GrantingPoliciesMap    map[uint32][]sdklogical.PolicyInfo
	ResponseKeysFilterPath string
	// ConditionSets holds condition sets from all merged policies for this path.
	// nil means unconditional access (at least one policy had no conditions).
	// Non-nil: each entry is one policy's conditions; request must satisfy at
	// least one set (OR between sets, AND within each set's types).
	ConditionSets []*PolicyConditions
	// MCP holds mcp { } rule-sets from all merged policies for this path.
	// nil/empty means no MCP enforcement applies. Non-nil: each entry is one
	// source stanza's mcp block; a request is allowed if at least one set
	// allows it (OR between sets), with the strongest-reason audit picked
	// on full deny. Populated by parsePaths via append per stanza so multiple
	// `path` blocks at the same path layer naturally into multiple rule-sets.
	MCP []*CBPMCPRules
}

// CBPMCPRules holds one merged mcp { } rule-set after validation and
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
	AllowedPrompts   []string
	AllowedParams    map[string][]string
	DeniedParams     map[string][]string
}

// Clone returns a deep copy of the CBPMCPRules. Safe to call on a nil
// receiver (returns nil). All slices and maps are independently
// allocated so mutating the clone never affects the original.
func (m *CBPMCPRules) Clone() *CBPMCPRules {
	if m == nil {
		return nil
	}
	clone := &CBPMCPRules{}
	if m.AllowedMethods != nil {
		clone.AllowedMethods = append([]string(nil), m.AllowedMethods...)
	}
	if m.DeniedMethods != nil {
		clone.DeniedMethods = append([]string(nil), m.DeniedMethods...)
	}
	if m.AllowedTools != nil {
		clone.AllowedTools = append([]string(nil), m.AllowedTools...)
	}
	if m.DeniedTools != nil {
		clone.DeniedTools = append([]string(nil), m.DeniedTools...)
	}
	if m.AllowedResources != nil {
		clone.AllowedResources = append([]string(nil), m.AllowedResources...)
	}
	if m.AllowedPrompts != nil {
		clone.AllowedPrompts = append([]string(nil), m.AllowedPrompts...)
	}
	if m.AllowedParams != nil {
		clone.AllowedParams = make(map[string][]string, len(m.AllowedParams))
		for k, v := range m.AllowedParams {
			clone.AllowedParams[k] = append([]string(nil), v...)
		}
	}
	if m.DeniedParams != nil {
		clone.DeniedParams = make(map[string][]string, len(m.DeniedParams))
		for k, v := range m.DeniedParams {
			clone.DeniedParams[k] = append([]string(nil), v...)
		}
	}
	return clone
}

func (p *CBPPermissions) Clone() (*CBPPermissions, error) {
	ret := &CBPPermissions{
		CapabilitiesBitmap:     p.CapabilitiesBitmap,
		RequiredParameters:     p.RequiredParameters[:],
		PaginationLimit:        p.PaginationLimit,
		ResponseKeysFilterPath: p.ResponseKeysFilterPath,
	}

	switch {
	case p.AllowedParameters == nil:
	case len(p.AllowedParameters) == 0:
		ret.AllowedParameters = make(map[string][]any)
	default:
		clonedAllowed, err := copystructure.Copy(p.AllowedParameters)
		if err != nil {
			return nil, err
		}
		ret.AllowedParameters = clonedAllowed.(map[string][]any)
	}

	switch {
	case p.DeniedParameters == nil:
	case len(p.DeniedParameters) == 0:
		ret.DeniedParameters = make(map[string][]any)
	default:
		clonedDenied, err := copystructure.Copy(p.DeniedParameters)
		if err != nil {
			return nil, err
		}
		ret.DeniedParameters = clonedDenied.(map[string][]any)
	}

	switch {
	case p.GrantingPoliciesMap == nil:
	case len(p.GrantingPoliciesMap) == 0:
		ret.GrantingPoliciesMap = make(map[uint32][]sdklogical.PolicyInfo)
	default:
		clonedGrantingPoliciesMap, err := copystructure.Copy(p.GrantingPoliciesMap)
		if err != nil {
			return nil, err
		}
		ret.GrantingPoliciesMap = clonedGrantingPoliciesMap.(map[uint32][]sdklogical.PolicyInfo)
	}

	switch {
	case p.ConditionSets == nil:
	case len(p.ConditionSets) == 0:
		ret.ConditionSets = make([]*PolicyConditions, 0)
	default:
		ret.ConditionSets = make([]*PolicyConditions, len(p.ConditionSets))
		for i, cs := range p.ConditionSets {
			ret.ConditionSets[i] = cs.Clone()
		}
	}

	switch {
	case p.MCP == nil:
	case len(p.MCP) == 0:
		ret.MCP = make([]*CBPMCPRules, 0)
	default:
		ret.MCP = make([]*CBPMCPRules, len(p.MCP))
		for i, m := range p.MCP {
			ret.MCP[i] = m.Clone()
		}
	}

	return ret, nil
}

func addGrantingPoliciesToMap(m map[uint32][]sdklogical.PolicyInfo, policy *Policy, capabilitiesBitmap uint32) map[uint32][]sdklogical.PolicyInfo {
	if m == nil {
		m = make(map[uint32][]sdklogical.PolicyInfo)
	}

	// For all possible policies, check if the provided capabilities include
	// them
	for _, capability := range cap2Int {
		if capabilitiesBitmap&capability == 0 {
			continue
		}

		m[capability] = append(m[capability], sdklogical.PolicyInfo{
			Name:          policy.Name,
			NamespaceId:   policy.namespace.ID,
			NamespacePath: policy.namespace.Path,
			Type:          "cbp",
		})
	}

	return m
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

		// Strip a leading '/' as paths in Vault start after the / in the API path
		if len(pc.Path) > 0 && pc.Path[0] == '/' {
			pc.Path = pc.Path[1:]
		}

		// Ensure we are using the full request path internally
		pc.Path = result.namespace.Path + pc.Path

		if strings.Contains(pc.Path, "+*") {
			return fmt.Errorf("path %q: invalid use of wildcards ('+*' is forbidden)", pc.Path)
		}

		if pc.Path == "+" || strings.Count(pc.Path, "/+") > 0 || strings.HasPrefix(pc.Path, "+/") {
			pc.HasSegmentWildcards = true
		}

		if strings.HasSuffix(pc.Path, "*") {
			// If there are segment wildcards, don't actually strip the
			// trailing asterisk, but don't want to hit the default case
			if !pc.HasSegmentWildcards {
				// Strip the glob character if found
				pc.Path = strings.TrimSuffix(pc.Path, "*")
				pc.IsPrefix = true
			}
		}

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

		if pc.AllowedParametersHCL != nil {
			pc.Permissions.AllowedParameters = make(map[string][]interface{}, len(pc.AllowedParametersHCL))
			for k, v := range pc.AllowedParametersHCL {
				pc.Permissions.AllowedParameters[strings.ToLower(k)] = v
			}
		}
		if pc.DeniedParametersHCL != nil {
			pc.Permissions.DeniedParameters = make(map[string][]interface{}, len(pc.DeniedParametersHCL))

			for k, v := range pc.DeniedParametersHCL {
				pc.Permissions.DeniedParameters[strings.ToLower(k)] = v
			}
		}
		if len(pc.RequiredParametersHCL) > 0 {
			pc.Permissions.RequiredParameters = pc.RequiredParametersHCL[:]
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
			conditions, err := parseAndValidateConditions(pc.ConditionsHCL)
			if err != nil {
				return fmt.Errorf("path %q: %w", key, err)
			}
			pc.Permissions.ConditionSets = []*PolicyConditions{conditions}
		}

		if pc.MCPHCL != nil {
			rules, err := canonicaliseMCPRules(pc.MCPHCL)
			if err != nil {
				return fmt.Errorf("path %q: %w", key, err)
			}
			pc.Permissions.MCP = append(pc.Permissions.MCP, rules)
		}
	PathFinished:
		paths = append(paths, &pc)
	}

	result.Paths = paths
	return nil
}

// canonicaliseMCPRules converts a parsed mcp { } HCL block into the
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
	canonMap := func(field string, in map[string][]string) (map[string][]string, error) {
		if len(in) == 0 {
			return nil, nil
		}
		out := make(map[string][]string, len(in))
		for k, vs := range in {
			canonValues, err := canonList(fmt.Sprintf("%s[%q]", field, k), vs)
			if err != nil {
				return nil, err
			}
			out[strings.ToLower(k)] = canonValues
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
	if r.AllowedPrompts, err = canonList("allowed_prompts", h.AllowedPrompts); err != nil {
		return nil, err
	}
	if r.AllowedParams, err = canonMap("allowed_params", h.AllowedParams); err != nil {
		return nil, err
	}
	if r.DeniedParams, err = canonMap("denied_params", h.DeniedParams); err != nil {
		return nil, err
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
