package core

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/armon/go-radix"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
)

// CBP is used to wrap a set of policies to provide
// an efficient interface for access control.
type CBP struct {
	// exactRules contains the path policies that are exact. An exact key is
	// only ever looked up exactly — no walk over the exact paths exists — so a
	// map serves it: one allocation however many stanzas, a hash lookup per
	// request. An endpoint that needs to walk them in order would scan or sort
	// the keys; a radix tree here would make every request pay for it.
	exactRules map[string]*CBPPermissions

	// prefixRules contains the path policies that are a prefix, found by
	// longest-prefix match.
	prefixRules *radix.Tree

	segmentWildcardPaths map[string]interface{}

	// The MCP index mirrors the three above for PolicyTypeMCP policies. It is
	// keyed and ranked identically — same normalized path keys, same
	// single-winner resolution — but consulted separately, so a request's
	// capability grant and its tool contract can come from different documents
	// whose stanzas need not be spelled the same way. Values are
	// *CBPPermissions carrying only .MCP.
	mcpExactRules           map[string]*CBPPermissions
	mcpPrefixRules          *radix.Tree
	mcpSegmentWildcardPaths map[string]interface{}

	// Every index above starts nil and is allocated by the first stanza that
	// needs it (store, storeMCP): a compile pays only for the indexes its
	// policies use. Readers tolerate nil: a nil map reads as empty, and the
	// trees are guarded (lookupEntry, checkAllowedFromNonExactPaths).

	// root is enabled if the "root" named policy is present.
	root bool

	// slab backs every capability entry of this compile: one copy per stanza,
	// allocated together. Entries are addressed by pointer, so the slab is
	// sized up front and never grows.
	slab []CBPPermissions

	// ownedMCP lists the MCP index entries this compile allocated, because two
	// stanzas met at one key or a rule-set was not stamped with its policy.
	// Every other MCP entry is a parsed policy's own CBPPermissions, shared
	// with the policy cache and never written.
	ownedMCP []*CBPPermissions
}

// rootGrantingPolicies is the granting-policies answer of every root request.
// Shared: read only.
var rootGrantingPolicies = []sdklogical.PolicyInfo{{
	Name:          "root",
	NamespaceId:   "root",
	NamespacePath: "",
	Type:          "cbp",
}}

// lookupEntry returns the entry already indexed under pc's key in the given
// index, if any.
func lookupEntry(exact map[string]*CBPPermissions, prefix *radix.Tree, wild map[string]interface{}, pc *PathRules) (*CBPPermissions, bool) {
	switch {
	case pc.HasSegmentWildcards:
		raw, ok := wild[pc.Path]
		if !ok {
			return nil, false
		}
		return raw.(*CBPPermissions), true
	case pc.IsPrefix:
		if prefix == nil {
			return nil, false
		}
		raw, ok := prefix.Get(pc.Path)
		if !ok {
			return nil, false
		}
		return raw.(*CBPPermissions), true
	default:
		e, ok := exact[pc.Path]
		return e, ok
	}
}

// store indexes e under pc's key in the capability index, allocating the
// index on first use. hint sizes the exact-path map: the compile's stanzas.
func (a *CBP) store(pc *PathRules, e *CBPPermissions, hint int) {
	switch {
	case pc.HasSegmentWildcards:
		if a.segmentWildcardPaths == nil {
			a.segmentWildcardPaths = make(map[string]interface{}, 1)
		}
		a.segmentWildcardPaths[pc.Path] = e
	case pc.IsPrefix:
		if a.prefixRules == nil {
			a.prefixRules = radix.New()
		}
		a.prefixRules.Insert(pc.Path, e)
	default:
		if a.exactRules == nil {
			a.exactRules = make(map[string]*CBPPermissions, hint)
		}
		a.exactRules[pc.Path] = e
	}
}

// storeMCP indexes e under pc's key in the MCP index, allocating the index on
// first use.
func (a *CBP) storeMCP(pc *PathRules, e *CBPPermissions) {
	switch {
	case pc.HasSegmentWildcards:
		if a.mcpSegmentWildcardPaths == nil {
			a.mcpSegmentWildcardPaths = make(map[string]interface{}, 1)
		}
		a.mcpSegmentWildcardPaths[pc.Path] = e
	case pc.IsPrefix:
		if a.mcpPrefixRules == nil {
			a.mcpPrefixRules = radix.New()
		}
		a.mcpPrefixRules.Insert(pc.Path, e)
	default:
		if a.mcpExactRules == nil {
			a.mcpExactRules = make(map[string]*CBPPermissions, 1)
		}
		a.mcpExactRules[pc.Path] = e
	}
}

type PolicyCheckOpts struct {
	RootPrivsRequired bool
	Unauth            bool
}

type AuthzResults struct {
	CBPResults  *CBPResults
	Allowed     bool
	RootPrivs   bool
	DeniedError bool
	Error       *multierror.Error
}

type CBPResults struct {
	Allowed            bool
	RootPrivs          bool
	IsRoot             bool
	CapabilitiesBitmap uint32

	// GrantingPolicies names the policies that granted the operation. It is
	// shared, not built per request: a single granter's slice lives on its
	// cached policy, root's is a package-level value. Read only — write a
	// copy.
	GrantingPolicies       []sdklogical.PolicyInfo
	ResponseKeysFilterPath string

	// MCPDecision is populated on every branch of the MCP gate, allow and
	// deny, so the audit and deny-response layers can render the decision
	// unconditionally. That covers two cases: a rule-set was consulted, or an
	// MCP-shaped request met no rule-set at all and was denied with
	// no_mcp_policy. Nil for everything else — every non-MCP provider, and the
	// body-less verbs an MCP mount serves alongside its JSON-RPC POSTs.
	//
	// Invariant: when MCPDecision.Decision == "deny", Allowed is
	// false. The reverse (Allowed=false with Decision="allow") is
	// possible — the MCP gate runs between conditions and the
	// parameter check, so a later check can deny after MCP allows.
	MCPDecision *logical.MCPDecision

	// Condition is populated when a path-level CEL condition was evaluated,
	// carrying the audited decision (expression + sanitized error). nil when
	// the matched permission had no path-level condition.
	Condition *logical.ConditionResult
}

const limitParameterName = "limit"

// NewACL is used to construct a policy based CBP from a set of policies.
func NewCBP(ctx context.Context, policies []*Policy) (*CBP, error) {
	// Initialize. Every index starts nil; the first stanza needing one
	// allocates it.
	a := &CBP{}

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	if ns == nil {
		return nil, namespace.ErrNoNamespace
	}

	// The root policy must stand alone among *grants*. MCP policies are counted
	// out of that: they grant nothing, and AllowOperation's root fast path
	// returns before the MCP gate anyway, so attaching one to a root token is
	// inert rather than contradictory. Counting them would turn a harmless
	// attachment into a compile failure, which surfaces as a 500 on every
	// request the token makes.
	grantingPolicyCount := 0
	stanzas := 0
	for _, policy := range policies {
		if policy != nil && policy.Type == PolicyTypeCBP {
			grantingPolicyCount++
			stanzas += len(policy.Paths)
		}
	}
	if stanzas > 0 {
		a.slab = make([]CBPPermissions, 0, stanzas)
	}

	// Inject each policy
	for _, policy := range policies {
		// Ignore a nil policy object
		if policy == nil {
			continue
		}

		switch policy.Type {
		case PolicyTypeCBP:
		case PolicyTypeMCP:
			// MCP policies go into their own index and never touch the
			// capability trees, the granting-policies map or the deny-collapse
			// path below — they carry no capabilities to collapse.
			if err := a.insertMCPPolicy(policy); err != nil {
				return nil, err
			}
			continue
		default:
			return nil, errors.New("unable to parse policy (wrong type)")
		}

		// Check if this is root
		if policy.Name == "root" {
			if ns.ID != namespace.RootNamespaceID {
				return nil, errors.New("root policy is only allowed in root namespace")
			}

			if grantingPolicyCount != 1 {
				return nil, errors.New("other policies present along with root")
			}
			a.root = true
		}

		for _, pc := range policy.Paths {
			if !pc.Expiration.IsZero() && time.Now().After(pc.Expiration) {
				// Skip adding expired paths.
				continue
			}

			existingPerms, ok := lookupEntry(a.exactRules, a.prefixRules, a.segmentWildcardPaths, pc)
			if !ok {
				// The compiled entry is a copy of the stanza's permissions in
				// this compile's slab, recording the policy that brought them.
				// The copy shares the parsed Conditions backing array; the merge
				// below never appends into it in place (see the full slice
				// expression there).
				a.slab = append(a.slab, *pc.Permissions)
				e := &a.slab[len(a.slab)-1]
				e.owner = policy
				e.ownerCaps = pc.Permissions.CapabilitiesBitmap
				a.store(pc, e, stanzas)
				continue
			}

			// existingPerms is this compile's slab copy: every merge below
			// writes it in place, never the parsed policy.
			switch {
			case existingPerms.CapabilitiesBitmap&DenyCapabilityInt > 0:
				// If we are explicitly denied in the existing capability set,
				// don't save anything else
				continue

			case pc.Permissions.CapabilitiesBitmap&DenyCapabilityInt > 0:
				// If this new policy explicitly denies, only save the deny value
				existingPerms.CapabilitiesBitmap = DenyCapabilityInt
				continue

			default:
				// Insert the capabilities in this new policy into the existing
				// value
				existingPerms.CapabilitiesBitmap = existingPerms.CapabilitiesBitmap | pc.Permissions.CapabilitiesBitmap
				existingPerms.extra = append(existingPerms.extra, grantRef{policy: policy, caps: pc.Permissions.CapabilitiesBitmap})
			}

			// Lowest set pagination limit wins.
			if pc.Permissions.PaginationLimit > 0 {
				if existingPerms.PaginationLimit <= 0 || pc.Permissions.PaginationLimit < existingPerms.PaginationLimit {
					existingPerms.PaginationLimit = pc.Permissions.PaginationLimit
				}
			}

			// If we do not have a ResponseKeysFilterPath value, update our
			// existing permissions to contain it. This means that the first
			// policy which contains non-empty
			// list_scan_response_keys_filter_path value wins.
			if len(pc.Permissions.ResponseKeysFilterPath) > 0 && len(existingPerms.ResponseKeysFilterPath) == 0 {
				existingPerms.ResponseKeysFilterPath = pc.Permissions.ResponseKeysFilterPath
			}

			// CEL conditions merge with "unconditional wins" OR semantics
			// across policies: a merged-in policy without a condition makes the
			// path unconditional (it already permits every request); otherwise
			// the conditions are appended and the gate passes if any one is true.
			switch {
			case existingPerms.Conditions == nil:
				// Path already unconditional; stays unconditional.
			case pc.Permissions.Conditions == nil:
				existingPerms.Conditions = nil
			default:
				// Full slice expression: the first policy's Conditions backing
				// array belongs to the parsed policy, so the append must copy.
				c := existingPerms.Conditions
				existingPerms.Conditions = append(c[:len(c):len(c)], pc.Permissions.Conditions...)
			}
		}
	}
	return a, nil
}

// insertMCPPolicy adds one MCP policy's stanzas to the MCP index.
//
// Stanzas at the same normalized path key merge additively, so several MCP
// policies covering one path contribute several rule-sets and evaluateMCPCall's
// cross-set OR decides between them — the same shape the removed `mcp { }`
// block had when two CBP policies named the same path.
func (a *CBP) insertMCPPolicy(policy *Policy) error {
	for _, pc := range policy.Paths {
		if !pc.Expiration.IsZero() && time.Now().After(pc.Expiration) {
			// Skip expired stanzas, as the capability index does.
			continue
		}
		if pc.Permissions == nil || len(pc.Permissions.MCP) == 0 {
			continue
		}

		existingPerms, ok := lookupEntry(a.mcpExactRules, a.mcpPrefixRules, a.mcpSegmentWildcardPaths, pc)
		if !ok {
			// First stanza at this key: index the parsed CBPPermissions itself.
			// CBP() compiles from *Policy values held in the policy cache and
			// shared across requests, so this entry is never written here: a
			// later stanza at the same key replaces it with an owned copy
			// below. Rule-sets are stamped with their policy's name when the
			// policy is built (finalize); a set that is not gets copied.
			e := pc.Permissions
			if !mcpStamped(e.MCP, policy.Name) {
				e = &CBPPermissions{MCP: stampedMCP(e.MCP, policy.Name)}
				a.ownedMCP = append(a.ownedMCP, e)
			}
			a.storeMCP(pc, e)
			continue
		}

		if !slices.Contains(a.ownedMCP, existingPerms) {
			// A second stanza at one key, from another policy or the same one:
			// the entry becomes this compile's own, holding the rule-sets
			// already indexed and then the new ones.
			merged := &CBPPermissions{MCP: make([]*CBPMCPRules, len(existingPerms.MCP), len(existingPerms.MCP)+len(pc.Permissions.MCP))}
			copy(merged.MCP, existingPerms.MCP)
			a.ownedMCP = append(a.ownedMCP, merged)
			a.storeMCP(pc, merged)
			existingPerms = merged
		}
		for _, m := range pc.Permissions.MCP {
			if m.SourcePolicy != policy.Name {
				c := *m
				c.SourcePolicy = policy.Name
				m = &c
			}
			existingPerms.MCP = append(existingPerms.MCP, m)
		}
	}

	return nil
}

// mcpStamped reports whether every rule-set already names policy name.
func mcpStamped(sets []*CBPMCPRules, name string) bool {
	for _, m := range sets {
		if m.SourcePolicy != name {
			return false
		}
	}
	return true
}

// stampedMCP returns copies of sets naming policy name; sets are not written.
func stampedMCP(sets []*CBPMCPRules, name string) []*CBPMCPRules {
	out := make([]*CBPMCPRules, len(sets))
	for i, m := range sets {
		c := *m
		c.SourcePolicy = name
		out[i] = &c
	}
	return out
}

// mcpRulesForPath returns the rule-sets of the single MCP stanza that wins for
// the given canonicalized request path, or nil when none matches.
//
// Resolution mirrors the capability index: an exact hit wins outright,
// otherwise the shared wildcard resolver picks one candidate by the same
// ranking. The List/Scan trailing-slash retries AllowOperation performs are
// deliberately absent — a populated MCP descriptor only ever exists on a POST,
// because every MCPPolicyEnforced implementer gates on POST.
//
// The returned slice is owned by the compiled index and shared by every request
// evaluated against it. Callers must treat it as read-only: sorting or
// appending would corrupt the CBP for every other caller holding it.
func (a *CBP) mcpRulesForPath(path string) []*CBPMCPRules {
	if e, ok := a.mcpExactRules[path]; ok {
		return e.MCP
	}

	if perms := checkAllowedFromNonExactPaths(
		a.mcpPrefixRules, a.mcpSegmentWildcardPaths, path, false,
	); perms != nil {
		return perms.MCP
	}

	return nil
}

func (a *CBP) Capabilities(ctx context.Context, path string) (pathCapabilities []string) {
	req := &logical.Request{
		Path: path,
		// doesn't matter, but use List to trigger fallback behavior so we can
		// model real behavior
		Operation: logical.ListOperation,
	}

	res := a.AllowOperation(ctx, req, nil, true)
	if res.IsRoot {
		return []string{RootCapability}
	}

	capabilities := res.CapabilitiesBitmap

	if capabilities&SudoCapabilityInt > 0 {
		pathCapabilities = append(pathCapabilities, SudoCapability)
	}
	if capabilities&ReadCapabilityInt > 0 {
		pathCapabilities = append(pathCapabilities, ReadCapability)
	}
	if capabilities&ListCapabilityInt > 0 {
		pathCapabilities = append(pathCapabilities, ListCapability)
	}
	if capabilities&UpdateCapabilityInt > 0 {
		pathCapabilities = append(pathCapabilities, UpdateCapability)
	}
	if capabilities&DeleteCapabilityInt > 0 {
		pathCapabilities = append(pathCapabilities, DeleteCapability)
	}
	if capabilities&CreateCapabilityInt > 0 {
		pathCapabilities = append(pathCapabilities, CreateCapability)
	}
	if capabilities&PatchCapabilityInt > 0 {
		pathCapabilities = append(pathCapabilities, PatchCapability)
	}
	if capabilities&ScanCapabilityInt > 0 {
		pathCapabilities = append(pathCapabilities, ScanCapability)
	}

	// If "deny" is explicitly set or if the path has no capabilities at all,
	// set the path capabilities to "deny"
	if capabilities&DenyCapabilityInt > 0 || len(pathCapabilities) == 0 {
		pathCapabilities = []string{DenyCapability}
	}
	return pathCapabilities
}

// AllowOperation is used to check if the given operation is permitted.
func (a *CBP) AllowOperation(ctx context.Context, req *logical.Request, te *logical.TokenEntry, capCheckOnly bool) (ret *CBPResults) {
	ret = new(CBPResults)

	// Fast-path root.
	//
	// This returns before the MCP gate, so a root token is not subject to tool
	// contracts — deliberately, and consistently with root already bypassing
	// explicit deny capabilities and path conditions. Root is the break-glass
	// path: making it answer to a contract would mean a misconfigured MCP
	// policy could lock an operator out of the mount that has to be used to fix
	// it. Agents hold real tokens, not root.
	if a.root {
		ret.Allowed = true
		ret.RootPrivs = true
		ret.IsRoot = true
		ret.GrantingPolicies = rootGrantingPolicies
		return ret
	}
	op := req.Operation

	// Help is always allowed
	if op == logical.HelpOperation {
		ret.Allowed = true
		return ret
	}

	var permissions *CBPPermissions

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return ret
	}
	path := ns.Path + req.Path

	// The request path should take care of this already but this is useful for
	// tests and as defense in depth
	for {
		if len(path) > 0 && path[0] == '/' {
			path = path[1:]
		} else {
			break
		}
	}

	// Find an exact matching rule, look for prefix if no match
	var capabilities uint32
	if e, ok := a.exactRules[path]; ok {
		permissions = e
		capabilities = permissions.CapabilitiesBitmap
		goto CHECK
	}
	if op == logical.ListOperation || op == logical.ScanOperation {
		if e, ok := a.exactRules[strings.TrimSuffix(path, "/")]; ok {
			permissions = e
			capabilities = permissions.CapabilitiesBitmap
			goto CHECK
		}
	}

	// List and Scan operations need to check without the trailing slash first,
	// because there could be other rules with trailing wildcards that will
	// match the path.
	if op == logical.ListOperation && strings.HasSuffix(path, "/") {
		permissions = a.CheckAllowedFromNonExactPaths(strings.TrimSuffix(path, "/"), false)
		if permissions != nil {
			capabilities = permissions.CapabilitiesBitmap
			goto CHECK
		}
	}
	permissions = a.CheckAllowedFromNonExactPaths(path, false)
	if permissions != nil {
		capabilities = permissions.CapabilitiesBitmap
		goto CHECK
	}

	// No exact, prefix, or segment wildcard paths found, return without
	// setting allowed
	return ret

CHECK:
	// Check if the minimum permissions are met
	// If "deny" has been explicitly set, only deny will be in the map, so we
	// only need to check for the existence of other values
	ret.RootPrivs = capabilities&SudoCapabilityInt > 0

	// This is after the RootPrivs check so we can gate on it being from sudo
	// rather than policy root
	if capCheckOnly {
		ret.CapabilitiesBitmap = capabilities
		return ret
	}

	var grantCap uint32
	switch op {
	case logical.ReadOperation:
		grantCap = ReadCapabilityInt
	case logical.ListOperation:
		grantCap = ListCapabilityInt
	case logical.UpdateOperation:
		grantCap = UpdateCapabilityInt
	case logical.DeleteOperation:
		grantCap = DeleteCapabilityInt
	case logical.CreateOperation:
		grantCap = CreateCapabilityInt
	case logical.PatchOperation:
		grantCap = PatchCapabilityInt
	case logical.ScanOperation:
		grantCap = ScanCapabilityInt
	// These three re-use UpdateCapabilityInt since that's the most appropriate
	// capability/operation mapping
	case logical.RevokeOperation, logical.RenewOperation, logical.RollbackOperation:
		grantCap = UpdateCapabilityInt

	default:
		return ret
	}

	if capabilities&grantCap == 0 {
		return ret
	}

	// now is snapshotted once so the path-level condition and any per-call MCP
	// conditions evaluate against a single, consistent instant.
	now := time.Now()

	// Path-level CEL condition gate, before MCP and parameter validation.
	// Empty/nil Conditions is unconditional. Fail-closed: an erroring or false
	// condition denies; the deciding result is recorded for audit on every
	// branch.
	if len(permissions.Conditions) > 0 {
		allowed, condRes := evaluatePathConditions(permissions.Conditions, req, te, now, ns.Path)
		ret.Condition = condRes
		if !allowed {
			return ret
		}
	}

	// MCP rule-set evaluation, body-authoritative. Runs after
	// conditions (so source-IP / time gates apply first) and before
	// parameter validation. Populates ret.MCPDecision on every branch it
	// takes — including the absence deny below — so the audit layer sees the
	// decision whether the request was allowed or denied.
	//
	// The rule-sets come from the MCP index, a lookup independent of the one
	// that chose `permissions` above: a request's capability grant and its tool
	// contract live in separate documents whose stanzas need not be spelled the
	// same way. The canonicalized `path` is the common key.
	//
	// req.MCPDescriptor is populated by the core/request_handler_mcp
	// extractor on streaming MCP backends that opt into
	// logical.MCPPolicyEnforced. A nil descriptor here means either
	// the routed backend doesn't implement the marker, or it declined
	// the request (wrong method / Content-Type) — fail closed.
	mcpSets := a.mcpRulesForPath(path)
	switch {
	case len(mcpSets) > 0:
		ret.MCPDecision = decideMCP(mcpSets, req, te, now, ns.Path)
		if ret.MCPDecision != nil && ret.MCPDecision.Decision == "deny" {
			return ret
		}
		// The MCP call is allowed. On the real enforcement pass, wire
		// response-side list filtering: attach a keep-filter for a single
		// list request, or fail closed on a batched list (unfilterable).
		if !capCheckOnly && ret.MCPDecision != nil && ret.MCPDecision.Decision == "allow" {
			if d := attachMCPListFilter(req, mcpSets); d != nil {
				sanitizeMCPDecision(d)
				ret.MCPDecision = d
				return ret
			}
		}

	case mcpDescriptorPopulated(req):
		// An MCP-shaped request with no contract in scope. The capability
		// grant said the caller may reach this mount; nothing has said which
		// calls are permitted on it, so none are. Opening a mount deliberately
		// is an explicit wildcard MCP policy, which stays visible in a policy
		// listing and in audit — unlike the absence this replaces, which used
		// to read as "unrestricted" and was indistinguishable from an operator
		// forgetting to attach the contract.
		ret.MCPDecision = &logical.MCPDecision{
			Decision: "deny",
			RuleType: mcpRuleTypeNoMCPPolicy,
		}
		return ret
	}

	ret.GrantingPolicies = permissions.grantingFor(grantCap)

	// Pagination clamping and list-response key filtering for list/scan.
	// (Request-body parameter constraints have been removed; express value
	// rules as a CEL condition over request.data — e.g. has(request.data.x)
	// to require a field, or request.data.tier in [...] to constrain a value.)
	if op == logical.ListOperation || op == logical.ScanOperation {
		if permissions.PaginationLimit > 0 {
			valRaw, ok := req.Data[limitParameterName]
			if !ok {
				// No limit supplied — clamp to the maximum allowed page size.
				if req.Data == nil {
					req.Data = make(map[string]interface{}, 1)
				}
				req.Data[limitParameterName] = strconv.Itoa(permissions.PaginationLimit)
			} else {
				// Limit supplied on a paginated endpoint — parse and clamp.
				val, err := parseutil.SafeParseInt(valRaw)
				if err != nil {
					// Not an integer; only the literal "max" is honored, mapping
					// to the maximum allowed page size. Anything else is denied.
					valStr, ok := valRaw.(string)
					if !ok || valStr != "max" {
						return ret
					}
					req.Data[limitParameterName] = strconv.Itoa(permissions.PaginationLimit)
				} else if val > permissions.PaginationLimit {
					// Deny if we exceed our allotted page size.
					return ret
				}
			}
		} else {
			// No pagination limit configured: honor the "max" sentinel so
			// pagination-aware applications can request all data uniformly.
			if valRaw, ok := req.Data[limitParameterName]; ok {
				if valStr, ok := valRaw.(string); ok && valStr == "max" {
					req.Data[limitParameterName] = "0"
				}
			}
		}

		// Surface the filter path so filterListResponse can evaluate list
		// filtering without knowledge of concrete policies.
		ret.ResponseKeysFilterPath = permissions.ResponseKeysFilterPath
	}

	ret.Allowed = true
	return ret
}

type wcPathDescr struct {
	firstWCOrGlob int
	wildcards     int
	isPrefix      bool
	wcPath        string
	perms         *CBPPermissions
}

// CheckAllowedFromNonExactPaths returns permissions corresponding to a
// matching path with wildcards/globs. If bareMount is true, the path should
// correspond to a mount prefix, and what is returned is either a non-nil set
// of permissions from some allowed path underneath the mount (for use in mount
// access checks), or nil indicating no non-deny permissions were found.
func (a *CBP) CheckAllowedFromNonExactPaths(path string, bareMount bool) *CBPPermissions {
	return checkAllowedFromNonExactPaths(a.prefixRules, a.segmentWildcardPaths, path, bareMount)
}

// anyWildcardCandidate reports whether any of the segment-wildcard paths could
// match path: one does only when path starts with the literal text before its
// first "+", which every matched segment before it must equal. It neither
// allocates nor splits.
func anyWildcardCandidate(segmentWildcardPaths map[string]interface{}, path string) bool {
	for wc := range segmentWildcardPaths {
		lit := wc
		if i := strings.IndexByte(wc, '+'); i >= 0 {
			lit = wc[:i]
		}
		if strings.HasPrefix(path, lit) {
			return true
		}
	}
	return false
}

// checkAllowedFromNonExactPaths is the resolution itself, taking the two
// indexes it reads rather than a receiver so the capability index and the MCP
// index resolve by exactly the same ranking. Duplicating this logic per index
// is how the two would drift apart on which stanza wins a request.
func checkAllowedFromNonExactPaths(
	prefixRules *radix.Tree,
	segmentWildcardPaths map[string]interface{},
	path string,
	bareMount bool,
) *CBPPermissions {
	// Without a segment wildcard that could match there is nothing to rank:
	// the longest prefix wins, or nothing does. Answered before the ranking
	// slice is made, so the common lookup allocates nothing, even when the
	// built-ins attached to every request hold "+" stanzas for paths of their
	// own. A bare-mount check ranks every wildcard, as it may match one deeper
	// than the path. The tree is nil until a prefix stanza is indexed, and a
	// nil *radix.Tree cannot be searched.
	if len(segmentWildcardPaths) == 0 || (!bareMount && !anyWildcardCandidate(segmentWildcardPaths, path)) {
		if prefixRules == nil {
			return nil
		}
		_, raw, ok := prefixRules.LongestPrefix(path)
		if !ok {
			return nil
		}
		return raw.(*CBPPermissions)
	}
	return rankNonExactPaths(prefixRules, segmentWildcardPaths, path, bareMount)
}

// rankNonExactPaths ranks the longest prefix rule against every segment
// wildcard that matches path and returns the winner's permissions, or for a
// bare-mount check the first wildcard under it granting anything.
func rankNonExactPaths(
	prefixRules *radix.Tree,
	segmentWildcardPaths map[string]interface{},
	path string,
	bareMount bool,
) *CBPPermissions {
	wcPathDescrs := make([]wcPathDescr, 0, len(segmentWildcardPaths)+1)

	less := func(i, j int) bool {
		// In the case of multiple matches, we use this priority order,
		// which tries to most closely match longest-prefix:
		//
		// * First glob or wildcard position (prefer foo/a* over foo/+,
		//   foo/bar/+/baz over foo/+/bar/baz)
		// * Whether it's a prefix (prefer foo/+/bar over foo/+/ba*,
		//   foo/+ over foo/*)
		// * Number of wildcard segments (prefer foo/bar/+/baz over foo/+/+/baz)
		// * Length check (prefer foo/+/bar/ba* over foo/+/bar/b*)
		// * Lexicographical ordering (preferring less, arbitrarily)
		//
		// That final case (lexigraphical) should never really come up. It's more
		// of a throwing-up-hands scenario akin to panic("should not be here")
		// statements, but less panicky.

		pdi, pdj := wcPathDescrs[i], wcPathDescrs[j]

		// If the first wildcard (+) or glob (*) occurs earlier in pdi,
		// pdi is lower priority
		if pdi.firstWCOrGlob < pdj.firstWCOrGlob {
			return true
		} else if pdi.firstWCOrGlob > pdj.firstWCOrGlob {
			return false
		}

		// If pdi ends in * and pdj doesn't, pdi is lower priority
		if pdi.isPrefix && !pdj.isPrefix {
			return true
		} else if !pdi.isPrefix && pdj.isPrefix {
			return false
		}

		// If pdi has more wc segs, pdi is lower priority
		if pdi.wildcards > pdj.wildcards {
			return true
		} else if pdi.wildcards < pdj.wildcards {
			return false
		}

		// If pdi is shorter, it is lower priority
		if len(pdi.wcPath) < len(pdj.wcPath) {
			return true
		} else if len(pdi.wcPath) > len(pdj.wcPath) {
			return false
		}

		// If pdi is smaller lexicographically, it is lower priority
		if pdi.wcPath < pdj.wcPath {
			return true
		} else if pdi.wcPath > pdj.wcPath {
			return false
		}
		return false
	}

	// Find a prefix rule if any, to rank against the segment wildcards.
	if prefixRules != nil {
		prefix, raw, ok := prefixRules.LongestPrefix(path)
		if ok {
			wcPathDescrs = append(wcPathDescrs, wcPathDescr{
				firstWCOrGlob: len(prefix),
				wcPath:        prefix,
				isPrefix:      true,
				perms:         raw.(*CBPPermissions),
			})
		}
	}

	pathParts := strings.Split(path, "/")

SWCPATH:
	for fullWCPath := range segmentWildcardPaths {
		if fullWCPath == "" {
			continue
		}
		pd := wcPathDescr{firstWCOrGlob: strings.Index(fullWCPath, "+")}

		currWCPath := fullWCPath
		if currWCPath[len(currWCPath)-1] == '*' {
			pd.isPrefix = true
			currWCPath = currWCPath[0 : len(currWCPath)-1]
		}
		pd.wcPath = currWCPath

		splitCurrWCPath := strings.Split(currWCPath, "/")

		if !bareMount && len(pathParts) < len(splitCurrWCPath) {
			// check if the path coming in is shorter; if so it can't match
			continue
		}
		if !bareMount && !pd.isPrefix && len(splitCurrWCPath) != len(pathParts) {
			// If it's not a prefix we expect the same number of segments
			continue
		}

		segments := make([]string, 0, len(splitCurrWCPath))
		for i, aclPart := range splitCurrWCPath {
			switch {
			case aclPart == "+":
				pd.wildcards++
				segments = append(segments, pathParts[i])

			case aclPart == pathParts[i]:
				segments = append(segments, pathParts[i])

			case pd.isPrefix && i == len(splitCurrWCPath)-1 && strings.HasPrefix(pathParts[i], aclPart):
				segments = append(segments, pathParts[i:]...)

			case !bareMount:
				// Found a mismatch, give up on this segmentWildcardPath
				continue SWCPATH
			}

			// -2 because we're always invoked with a trailing "/" in case bareMount.
			if bareMount && i == len(pathParts)-2 {
				joinedPath := strings.Join(segments, "/") + "/"
				// Check the current joined path so far. If we find a prefix,
				// check permissions. If they're defined but not deny, success.
				if strings.HasPrefix(joinedPath, path) {
					permissions := segmentWildcardPaths[fullWCPath].(*CBPPermissions)
					if permissions.CapabilitiesBitmap&DenyCapabilityInt == 0 && permissions.CapabilitiesBitmap > 0 {
						return permissions
					}
				}
				continue SWCPATH
			}
		}
		pd.perms = segmentWildcardPaths[fullWCPath].(*CBPPermissions)
		wcPathDescrs = append(wcPathDescrs, pd)
	}

	if bareMount || len(wcPathDescrs) == 0 {
		return nil
	}

	// We don't do this in the bare mount check because we don't care about
	// priority, we only care about any capability at all.
	sort.Slice(wcPathDescrs, less)

	return wcPathDescrs[len(wcPathDescrs)-1].perms
}

func (c *Core) performPolicyChecks(ctx context.Context, cbp *CBP, te *logical.TokenEntry, req *logical.Request, opts *PolicyCheckOpts) *AuthzResults {
	ret := new(AuthzResults)

	// Surface the token's verified metadata for token_metadata conditions.
	// It is read per request rather than compiled into the CBP, so a CBP
	// shared across tokens with the same policy set is still matched against
	// each token's own metadata.
	if te != nil {
		req.TokenMetadata = te.Metadata
	}

	// A token that takes its role per request runs only under a role granted
	// to it. Refused in every mode, ahead of the CBP; an unauthenticated check
	// (a login) never evaluates it, as it never evaluates the CBP. The CBP would
	// refuse anyway: an ungranted admission token carries no policies.
	if rg := req.RoleGrant(); !opts.Unauth && rg != nil && !rg.Granted() && !testHookSkipRoleVerdict {
		ret.Error = multierror.Append(ret.Error, roleRefusal(rg, te))
		return ret
	}

	// First, perform normal CBP checks if requested.
	if cbp != nil && !opts.Unauth {
		ret.CBPResults = cbp.AllowOperation(ctx, req, te, false)
		ret.RootPrivs = ret.CBPResults.RootPrivs
		// Root is always allowed; skip other checks
		if ret.CBPResults.IsRoot {
			ret.Allowed = true
			return ret
		}
		if !ret.CBPResults.Allowed {
			return ret
		}
		// Since HelpOperation was fast-pathed inside AllowOperation, RootPrivs will not have been populated in this
		// case, so we need to special-case that here as well, or we'll block HelpOperation on all sudo-protected paths.
		if !ret.RootPrivs && opts.RootPrivsRequired && req.Operation != logical.HelpOperation {
			return ret
		}
	}

	ret.Allowed = true

	return ret
}
