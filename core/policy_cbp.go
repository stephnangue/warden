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

	// MCPDecision is populated whenever an mcp { } rule-set was
	// consulted during AllowOperation, on every branch (allow and
	// deny) so the audit and deny-response layers can render the
	// decision unconditionally. Nil when no rule-set applied (the
	// vast majority of requests — every non-MCP provider).
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
		exactRules:           radix.New(),
		prefixRules:          radix.New(),
		segmentWildcardPaths: make(map[string]interface{}, len(policies)),
		root:                 false,
	}

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	if ns == nil {
		return nil, namespace.ErrNoNamespace
	}

	// Inject each policy
	for _, policy := range policies {
		// Ignore a nil policy object
		if policy == nil {
			continue
		}

		switch policy.Type {
		case PolicyTypeCBP:
		default:
			return nil, errors.New("unable to parse policy (wrong type)")
		}

		// Check if this is root
		if policy.Name == "root" {
			if ns.ID != namespace.RootNamespaceID {
				return nil, errors.New("root policy is only allowed in root namespace")
			}

			if len(policies) != 1 {
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

			// MCP rule-set merging: additive OR across policies. Unlike
			// conditions, an absent mcp block in one source does NOT
			// disable enforcement contributed by another source — each
			// stanza's mcp { } adds one entry to the slice and the
			// per-set OR in evaluateMCPDescriptor means more entries
			// can only admit more requests (never fewer). The clone
			// protects against later mutation of the shared underlying
			// slices.
			if len(pc.Permissions.MCP) > 0 {
				for _, m := range pc.Permissions.MCP {
					existingPerms.MCP = append(existingPerms.MCP, m.Clone())
				}
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

	// Fast-path root
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
		allowed, condRes := evaluatePathConditions(permissions.Conditions, req, te, now)
		ret.Condition = condRes
		if !allowed {
			return ret
		}
	}

	// MCP rule-set evaluation, body-authoritative. Runs after
	// conditions (so source-IP / time gates apply first) and before
	// parameter validation. Populates ret.MCPDecision on every branch
	// when an mcp block was consulted, so the audit layer sees the
	// decision whether the request was allowed or denied.
	//
	// req.MCPDescriptor is populated by the core/request_handler_mcp
	// extractor on streaming MCP backends that opt into
	// logical.MCPPolicyEnforced. A nil descriptor here means either
	// the routed backend doesn't implement the marker, or it declined
	// the request (wrong method / Content-Type) — fail closed.
	if len(permissions.MCP) > 0 {
		ret.MCPDecision = decideMCP(permissions.MCP, req, te, now)
		if ret.MCPDecision != nil && ret.MCPDecision.Decision == "deny" {
			return ret
		}
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
	wcPathDescrs := make([]wcPathDescr, 0, len(a.segmentWildcardPaths)+1)

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
		prefix, raw, ok := a.prefixRules.LongestPrefix(path)
		if ok {
			if len(a.segmentWildcardPaths) == 0 {
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

	if len(a.segmentWildcardPaths) == 0 {
		return nil
	}

	pathParts := strings.Split(path, "/")

SWCPATH:
	for fullWCPath := range a.segmentWildcardPaths {
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
					permissions := a.segmentWildcardPaths[fullWCPath].(*CBPPermissions)
					if permissions.CapabilitiesBitmap&DenyCapabilityInt == 0 && permissions.CapabilitiesBitmap > 0 {
						return permissions
					}
				}
				continue SWCPATH
			}
		}
		pd.perms = a.segmentWildcardPaths[fullWCPath].(*CBPPermissions)
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
