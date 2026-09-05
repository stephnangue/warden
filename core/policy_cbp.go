package core

import (
	"context"
	"errors"
	"fmt"
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
	// exactRules contains the path policies that are exact
	exactRules *radix.Tree

	// prefixRules contains the path policies that are a prefix
	prefixRules *radix.Tree

	segmentWildcardPaths map[string]interface{}

	// The MCP index mirrors the three above for PolicyTypeMCP policies. It is
	// keyed and ranked identically — same normalized path keys, same
	// single-winner resolution — but consulted separately, so a request's
	// capability grant and its tool contract can come from different documents
	// whose stanzas need not be spelled the same way. Values are
	// *CBPPermissions carrying only .MCP.
	mcpExactRules           *radix.Tree
	mcpPrefixRules          *radix.Tree
	mcpSegmentWildcardPaths map[string]interface{}

	// root is enabled if the "root" named policy is present.
	root bool
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
	Allowed                bool
	RootPrivs              bool
	IsRoot                 bool
	CapabilitiesBitmap     uint32
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
	// Initialize
	a := &CBP{
		exactRules:              radix.New(),
		prefixRules:             radix.New(),
		segmentWildcardPaths:    make(map[string]interface{}, len(policies)),
		mcpExactRules:           radix.New(),
		mcpPrefixRules:          radix.New(),
		mcpSegmentWildcardPaths: make(map[string]interface{}, len(policies)),
		root:                    false,
	}

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
	for _, policy := range policies {
		if policy != nil && policy.Type == PolicyTypeCBP {
			grantingPolicyCount++
		}
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
			var raw interface{}
			var ok bool
			var tree *radix.Tree

			if !pc.Expiration.IsZero() && time.Now().After(pc.Expiration) {
				// Skip adding expired paths.
				continue
			}

			switch {
			case pc.HasSegmentWildcards:
				raw, ok = a.segmentWildcardPaths[pc.Path]
			default:
				// Check which tree to use
				tree = a.exactRules
				if pc.IsPrefix {
					tree = a.prefixRules
				}

				// Check for an existing policy
				raw, ok = tree.Get(pc.Path)
			}

			if !ok {
				clonedPerms, err := pc.Permissions.Clone()
				if err != nil {
					return nil, fmt.Errorf("error cloning ACL permissions: %w", err)
				}

				// Store this policy name as the policy that permits these
				// capabilities
				clonedPerms.GrantingPoliciesMap = addGrantingPoliciesToMap(nil, policy, clonedPerms.CapabilitiesBitmap)
				switch {
				case pc.HasSegmentWildcards:
					a.segmentWildcardPaths[pc.Path] = clonedPerms
				default:
					tree.Insert(pc.Path, clonedPerms)
				}
				continue
			}

			// these are the ones already in the tree
			existingPerms := raw.(*CBPPermissions)

			switch {
			case existingPerms.CapabilitiesBitmap&DenyCapabilityInt > 0:
				// If we are explicitly denied in the existing capability set,
				// don't save anything else
				continue

			case pc.Permissions.CapabilitiesBitmap&DenyCapabilityInt > 0:
				// If this new policy explicitly denies, only save the deny value
				existingPerms.CapabilitiesBitmap = DenyCapabilityInt
				goto INSERT

			default:
				// Insert the capabilities in this new policy into the existing
				// value
				existingPerms.CapabilitiesBitmap = existingPerms.CapabilitiesBitmap | pc.Permissions.CapabilitiesBitmap
				existingPerms.GrantingPoliciesMap = addGrantingPoliciesToMap(existingPerms.GrantingPoliciesMap, policy, pc.Permissions.CapabilitiesBitmap)
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
				existingPerms.Conditions = append(existingPerms.Conditions, pc.Permissions.Conditions...)
			}

		INSERT:
			switch {
			case pc.HasSegmentWildcards:
				a.segmentWildcardPaths[pc.Path] = existingPerms
			default:
				tree.Insert(pc.Path, existingPerms)
			}
		}
	}
	return a, nil
}

// insertMCPPolicy adds one MCP policy's stanzas to the MCP index.
//
// Stanzas at the same normalized path key merge additively, so several MCP
// policies covering one path contribute several rule-sets and evaluateMCPCall's
// cross-set OR decides between them — the same shape the mcp { } block had when
// two CBP policies named the same path.
func (a *CBP) insertMCPPolicy(policy *Policy) error {
	for _, pc := range policy.Paths {
		if !pc.Expiration.IsZero() && time.Now().After(pc.Expiration) {
			// Skip expired stanzas, as the capability index does.
			continue
		}
		if pc.Permissions == nil || len(pc.Permissions.MCP) == 0 {
			continue
		}

		var raw interface{}
		var ok bool
		var tree *radix.Tree

		switch {
		case pc.HasSegmentWildcards:
			raw, ok = a.mcpSegmentWildcardPaths[pc.Path]
		default:
			tree = a.mcpExactRules
			if pc.IsPrefix {
				tree = a.mcpPrefixRules
			}
			raw, ok = tree.Get(pc.Path)
		}

		if !ok {
			// Clone before inserting: CBP() compiles from *Policy values held in
			// the LRU and shared across requests, so the index must never hold
			// a CBPPermissions the cached policy still owns — the same-key
			// append below would otherwise grow the cached rule-sets on every
			// compile.
			clonedPerms, err := pc.Permissions.Clone()
			if err != nil {
				return fmt.Errorf("error cloning MCP permissions: %w", err)
			}
			for _, m := range clonedPerms.MCP {
				m.SourcePolicy = policy.Name
			}
			switch {
			case pc.HasSegmentWildcards:
				a.mcpSegmentWildcardPaths[pc.Path] = clonedPerms
			default:
				tree.Insert(pc.Path, clonedPerms)
			}
			continue
		}

		existingPerms, castOK := raw.(*CBPPermissions)
		if !castOK {
			return errors.New("error type casting MCP permissions")
		}
		for _, m := range pc.Permissions.MCP {
			clone := m.Clone()
			clone.SourcePolicy = policy.Name
			existingPerms.MCP = append(existingPerms.MCP, clone)
		}
	}

	return nil
}

// mcpRulesForPath returns the rule-sets of the single MCP stanza that wins for
// the given canonicalized request path, or nil when none matches.
//
// Resolution mirrors the capability index: an exact hit wins outright,
// otherwise the shared wildcard resolver picks one candidate by the same
// ranking. The List/Scan trailing-slash retries AllowOperation performs are
// deliberately absent — a populated MCP descriptor only ever exists on a POST,
// because every MCPPolicyEnforced implementer gates on POST plus a JSON
// content type.
//
// The returned slice is owned by the compiled index and shared by every request
// evaluated against it. Callers must treat it as read-only: sorting or
// appending would corrupt the CBP for every other caller holding it.
func (a *CBP) mcpRulesForPath(path string) []*CBPMCPRules {
	if raw, ok := a.mcpExactRules.Get(path); ok {
		return raw.(*CBPPermissions).MCP
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
		ret.GrantingPolicies = []sdklogical.PolicyInfo{{
			Name:          "root",
			NamespaceId:   "root",
			NamespacePath: "",
			Type:          "cbp",
		}}
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
	raw, ok := a.exactRules.Get(path)
	if ok {
		permissions = raw.(*CBPPermissions)
		capabilities = permissions.CapabilitiesBitmap
		goto CHECK
	}
	if op == logical.ListOperation || op == logical.ScanOperation {
		raw, ok = a.exactRules.Get(strings.TrimSuffix(path, "/"))
		if ok {
			permissions = raw.(*CBPPermissions)
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

	var grantingPolicies []sdklogical.PolicyInfo
	operationAllowed := false
	switch op {
	case logical.ReadOperation:
		operationAllowed = capabilities&ReadCapabilityInt > 0
		grantingPolicies = permissions.GrantingPoliciesMap[ReadCapabilityInt]
	case logical.ListOperation:
		operationAllowed = capabilities&ListCapabilityInt > 0
		grantingPolicies = permissions.GrantingPoliciesMap[ListCapabilityInt]
	case logical.UpdateOperation:
		operationAllowed = capabilities&UpdateCapabilityInt > 0
		grantingPolicies = permissions.GrantingPoliciesMap[UpdateCapabilityInt]
	case logical.DeleteOperation:
		operationAllowed = capabilities&DeleteCapabilityInt > 0
		grantingPolicies = permissions.GrantingPoliciesMap[DeleteCapabilityInt]
	case logical.CreateOperation:
		operationAllowed = capabilities&CreateCapabilityInt > 0
		grantingPolicies = permissions.GrantingPoliciesMap[CreateCapabilityInt]
	case logical.PatchOperation:
		operationAllowed = capabilities&PatchCapabilityInt > 0
		grantingPolicies = permissions.GrantingPoliciesMap[PatchCapabilityInt]
	case logical.ScanOperation:
		operationAllowed = capabilities&ScanCapabilityInt > 0
		grantingPolicies = permissions.GrantingPoliciesMap[ScanCapabilityInt]
	// These three re-use UpdateCapabilityInt since that's the most appropriate
	// capability/operation mapping
	case logical.RevokeOperation, logical.RenewOperation, logical.RollbackOperation:
		operationAllowed = capabilities&UpdateCapabilityInt > 0
		grantingPolicies = permissions.GrantingPoliciesMap[UpdateCapabilityInt]

	default:
		return ret
	}

	if !operationAllowed {
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

	ret.GrantingPolicies = grantingPolicies

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

	// Find a prefix rule if any.
	{
		prefix, raw, ok := prefixRules.LongestPrefix(path)
		if ok {
			if len(segmentWildcardPaths) == 0 {
				return raw.(*CBPPermissions)
			}
			wcPathDescrs = append(wcPathDescrs, wcPathDescr{
				firstWCOrGlob: len(prefix),
				wcPath:        prefix,
				isPrefix:      true,
				perms:         raw.(*CBPPermissions),
			})
		}
	}

	if len(segmentWildcardPaths) == 0 {
		return nil
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
