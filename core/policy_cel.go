// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter"

	"github.com/stephnangue/warden/logical"
)

// This file is the CEL evaluation layer for policy conditions: it builds the
// evaluation environment(s), compiles and cost-bounds condition expressions,
// and builds the per-request / per-call activations consumed by the policy
// evaluator.
//
// Design notes:
//   - Two envs: a base env (request/agent/now) for path-level conditions and an
//     MCP env (base + call) for MCP policies conditions. Two envs make a path-level
//     condition that references call.* a COMPILE error, not a silent runtime
//     deny.
//   - request/agent/call are map(string, dyn): the env is shared across every
//     tool/path and cannot know an arbitrary argument's type. Type discipline is
//     achieved at activation-build time (values typed from their source); a
//     type-mismatched comparison surfaces as a runtime error → fail-closed deny.
//   - Top-level containers are always bound as non-nil (possibly empty) maps, so
//     has(request.data.x) is false rather than a nil-deref, and absent nested
//     keys fail closed (deny).
//
// Namespaces exposed to expressions (all populated before policy evaluation in
// handleNonLoginRequest — mount fields and request body are set before
// CheckToken):
//
//	request.path, request.operation, request.client_ip,
//	  request.mount_point, request.mount_type, request.mount_class,
//	  request.mount_accessor, request.transparent, request.namespace,
//	  request.data.<k>
//	agent.present, agent.principal, agent.role, agent.namespace,
//	  agent.policies (list), agent.metadata.<k>, agent.actors (list of
//	  {subject}), agent.token_type, agent.token_ttl_seconds,
//	  agent.token_expires_at
//	user.<same, minus policies>
//	now (timestamp)
//	call.method, call.tool, call.args.<k>, call.batch_index   (MCP policy only)
//
// `agent` is the request's authenticating principal and the sole authorizer.
// `user` is the optional second principal it acts for, resolved before the
// policy decision and identity-only — it never authorizes, which is why
// user.policies is not exposed. user.present is false when no user credential
// rode the request; that is tolerated by design, so a condition wanting one
// must say `user.present && …`. Note a condition must evaluate to bool while a
// dyn-map field types as dyn, so a bare `user.present` is rejected at write
// time — use it as a guard (as above) or compare it explicitly.
//
// The three token_-prefixed fields describe the credential a principal
// authenticated with, not the principal itself — token_type carries values like
// jwt_role/cert_role, which name how it authenticated rather than a kind of
// principal.
//
// Two caveats worth knowing before writing a `user` condition: the user leg is
// resolved only for gateway (streaming) requests, so user.present is always
// false elsewhere; and user.role is the auth-mount role fixed by the mount's
// user_auth_role — not the person's organisational role — while
// user.namespace always equals request.namespace. Gate on user.metadata.<k>.
//
// Secret material (token value, accessor, client token) is never exposed.

const (
	// maxConditionCost bounds a single CEL evaluation in cel-go's abstract cost
	// units. It serves two distinct roles:
	//   - Runtime backstop (the real DoS guard): attached as cel.CostLimit to
	//     every input-size-dependent expression, it caps the work of one Eval
	//     regardless of the actual input size — a comprehension over an
	//     adversary-sized request.data/call.args aborts (→ fail-closed deny) once
	//     it exceeds this budget. This is what bounds per-request cost; it does
	//     not depend on celInputSizeBound.
	//   - Write-time rejection: an expression whose worst-case estimate at
	//     celInputSizeBound already exceeds this is rejected when the policy is
	//     written (operator gets a directed error instead of a runtime deny).
	maxConditionCost uint64 = 1_000_000

	// celInputSizeBound is the size (map entries / string length) the cost
	// estimator assumes for the dynamic-map variables (request/agent/call) that
	// cel-go cannot size itself. It is a heuristic for the *write-time* check —
	// large enough to admit reasonable expressions, small enough to reject
	// pathological ones (e.g. nested comprehensions, ~size² cost). It is
	// deliberately NOT the real body cap (framework.DefaultMaxBodySize, 10MB →
	// far more entries): the runtime cel.CostLimit above is the actual per-eval
	// guard, so this only tunes which expressions fail fast at write time rather
	// than fail closed at request time.
	celInputSizeBound uint64 = 8192
)

// celRequestInput is the request context mapped into the `request` namespace.
// Decoupled from *logical.Request so the activation builder stays unit-testable;
// the wiring layer adapts the request into this.
type celRequestInput struct {
	Path          string
	Operation     string
	ClientIP      string
	MountPoint    string
	MountType     string
	MountClass    string
	MountAccessor string
	Transparent   bool
	Namespace     string
	Data          map[string]any
}

// celPrincipalInput is the non-secret principal context mapped into the `agent`
// and `user` namespaces. Decoupled from *logical.TokenEntry so the activation
// builder stays unit-testable; the wiring layer adapts the token entry into this.
type celPrincipalInput struct {
	// Present is false when no principal occupied this leg. It exists so an
	// operator can write `user.present && …`: a user credential is optional on
	// a protected-resource mount, and without this field its absence would be a
	// missing-key deny that reads as a bug rather than a policy decision. On the
	// agent leg it is always true wherever a condition evaluates, since
	// CheckToken has a token entry by then.
	Present       bool
	Principal     string
	Role          string
	Type          string
	NamespacePath string
	Policies      []string
	Metadata      map[string]string
	Actors        []logical.ActorRef
	TTLSeconds    int64
	ExpiresAtUnix int64
}

// principalLeg distinguishes the two principals that share buildPrincipalNS. It
// gates the fields that exist on only one of them.
//
// Named legAgent/legUser rather than agentLeg/userLeg because this package
// already uses `userLeg bool` for a different thing — whether a mount is a
// protected resource, so Authorization carries the user (see ExtractTokens).
type principalLeg bool

const (
	legAgent principalLeg = false
	legUser  principalLeg = true
)

// buildCELEnv constructs a CEL environment. When mcp is true the env also
// declares the per-call `call` namespace, producing the MCP env; otherwise it
// is the base (path-level) env.
func buildCELEnv(mcp bool) (*cel.Env, error) {
	opts := []cel.EnvOption{
		// request-wide namespaces; dyn maps (see design note).
		cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("agent", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("user", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("now", cel.TimestampType),

		// Optional types for concise optional-arg access: call.args.?x.orValue(d).
		cel.OptionalTypes(),
		// Allow numeric comparisons to mix int/double so `call.args.amount <= 1500`
		// works whether the arg arrived as an integer or a decimal.
		cel.CrossTypeNumericComparisons(true),

		// source_ip replacement: cidrContains(cidr, ip) bool.
		celCIDRContainsFunc(),
	}
	if mcp {
		opts = append(opts, cel.Variable("call", cel.MapType(cel.StringType, cel.DynType)))
	}
	return cel.NewEnv(opts...)
}

// celCIDRContainsFunc declares cidrContains(cidr, ip) bool — reports whether ip
// falls within the CIDR. A malformed cidr or ip yields a CEL error, which the
// caller treats as a fail-closed deny.
func celCIDRContainsFunc() cel.EnvOption {
	return cel.Function("cidrContains",
		cel.Overload("cidr_contains_string_string",
			[]*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
			cel.BinaryBinding(func(lhs, rhs ref.Val) ref.Val {
				cidrStr, ok := lhs.Value().(string)
				if !ok {
					return types.NewErr("cidrContains: cidr argument is not a string")
				}
				ipStr, ok := rhs.Value().(string)
				if !ok {
					return types.NewErr("cidrContains: ip argument is not a string")
				}
				_, ipNet, err := net.ParseCIDR(cidrStr)
				if err != nil {
					return types.NewErr("cidrContains: invalid cidr")
				}
				ip := net.ParseIP(ipStr)
				if ip == nil {
					return types.NewErr("cidrContains: invalid ip")
				}
				return types.Bool(ipNet.Contains(ip))
			}),
		),
	)
}

// celCostEstimator supplies input size bounds for our dynamic-map variables so
// env.EstimateCost can bound an expression's worst-case cost at compile time.
// Every dynamic-map root must appear in EstimateSize below. A root omitted here
// gets no size from us, and cel-go falls through to UnknownSizeEstimate
// (max = MaxUint64) — so any size-dependent expression over that root estimates
// as effectively infinite and is REJECTED at write time, even when it is
// perfectly reasonable. The failure is a spurious rejection, not a missed bound.
// cel-go owns the per-operation base costs; this only feeds the sizes cel-go
// cannot infer.
type celCostEstimator struct {
	maxSize uint64
}

func (e celCostEstimator) EstimateSize(node checker.AstNode) *checker.SizeEstimate {
	if path := node.Path(); len(path) > 0 {
		switch path[0] {
		case "request", "agent", "user", "call":
			return &checker.SizeEstimate{Min: 0, Max: e.maxSize}
		}
	}
	return nil
}

func (e celCostEstimator) EstimateCallCost(function, overloadID string, target *checker.AstNode, args []checker.AstNode) *checker.CallEstimate {
	return nil
}

// compileCELCondition compiles, type-checks, and cost-bounds a condition
// expression against env, returning an executable program. It is the single
// policy-write-time validation path: a syntax error, a non-bool result, an
// undeclared reference (e.g. call.* in a path-level condition), or an
// over-budget cost are all rejected here with a directed error.
func compileCELCondition(env *cel.Env, src string) (*compiledCondition, error) {
	return compileCELConditionWithLimits(env, src, maxConditionCost, celInputSizeBound)
}

// compileCELConditionWithLimits is compileCELCondition parameterized by the cost
// budget and estimator size bound. Production always uses the package constants;
// tests inject small limits to exercise the compile-time rejection and the
// runtime CostLimit deterministically without building giant activations.
func compileCELConditionWithLimits(env *cel.Env, src string, maxCost, sizeBound uint64) (*compiledCondition, error) {
	ast, iss := env.Compile(src)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("condition does not compile: %w", celRenameHint(iss.Err()))
	}
	if !ast.OutputType().IsExactType(cel.BoolType) {
		return nil, fmt.Errorf("condition must evaluate to bool, got %s", ast.OutputType())
	}

	est, err := env.EstimateCost(ast, celCostEstimator{maxSize: sizeBound})
	if err != nil {
		return nil, fmt.Errorf("condition cost estimation failed: %w", err)
	}
	if est.Max > maxCost {
		return nil, fmt.Errorf("condition worst-case cost %d exceeds limit %d", est.Max, maxCost)
	}

	// The runtime cost tracker (cel.CostLimit) allocates per eval and wraps the
	// program in an observable interpretable — a real hot-path cost. It is only
	// a backstop for inputs larger than the static estimate assumed, so attach
	// it only when the expression's cost is input-size-dependent.
	var progOpts []cel.ProgramOption
	sizeDependent, err := celCostIsSizeDependent(env, ast, sizeBound)
	if err != nil {
		return nil, err
	}
	if sizeDependent {
		progOpts = append(progOpts, cel.CostLimit(maxCost))
	}

	prg, err := env.Program(ast, progOpts...)
	if err != nil {
		return nil, fmt.Errorf("condition program construction failed: %w", err)
	}
	paths, segs, reqF, agtF, usrF, callF := celAnalyzeRefs(ast)
	return &compiledCondition{
		Source:     src,
		Program:    prg,
		RefPaths:   paths,
		RefSegs:    segs,
		ReqFields:  reqF,
		AgtFields:  agtF,
		UsrFields:  usrF,
		CallFields: callF,
	}, nil
}

// celRenameHint appends migration guidance when a compile failure is an
// undeclared reference to `token` — the namespace `agent` replaced. Both the
// policy-write path and the policy-load path surface compile errors, so an
// operator upgrading with stored `token.*` conditions meets this error at the
// moment they most need to be told what changed, rather than a bare
// "undeclared reference".
func celRenameHint(err error) error {
	if err == nil {
		return nil
	}
	s := err.Error()
	if !strings.Contains(s, "undeclared reference to 'token'") {
		return err
	}
	return fmt.Errorf("%w (the `token` namespace was renamed to `agent`: "+
		"token.principal/role/namespace/policies/metadata/actors are now agent.*, "+
		"and token.type/ttl_seconds/expires_at are now "+
		"agent.token_type/token_ttl_seconds/token_expires_at)", err)
}

// celCostIsSizeDependent reports whether an expression's worst-case cost grows
// with input size — detected by re-estimating at a doubled size bound and
// checking whether the worst-case changes. A size-independent (constant-cost)
// expression is already capped by the compile-time estimate and needs no
// per-eval CostLimit; a size-dependent one does.
func celCostIsSizeDependent(env *cel.Env, ast *cel.Ast, sizeBound uint64) (bool, error) {
	est, err := env.EstimateCost(ast, celCostEstimator{maxSize: sizeBound})
	if err != nil {
		return false, fmt.Errorf("condition cost estimation failed: %w", err)
	}
	est2, err := env.EstimateCost(ast, celCostEstimator{maxSize: sizeBound * 2})
	if err != nil {
		return false, fmt.Errorf("condition cost estimation failed: %w", err)
	}
	return est2.Max != est.Max, nil
}

// fieldSet is the set of top-level namespace fields (e.g. "data", "metadata")
// an expression reads under one root. all=true means the whole namespace is
// needed (a degenerate bare-root reference); it is the safe fallback that
// disables pruning for that root.
type fieldSet struct {
	fields map[string]bool
	all    bool
}

// has reports whether field name must be built. A nil/empty set with all=false
// means the namespace is unreferenced and its builder is never invoked.
func (f fieldSet) has(name string) bool { return f.all || f.fields[name] }

// unionFieldSets merges two field-sets (used only for the rare multi-condition
// merge; the common single-condition path reuses a compiledCondition's set
// directly with no allocation).
func unionFieldSets(a, b fieldSet) fieldSet {
	if a.all || b.all {
		return fieldSet{all: true}
	}
	if len(a.fields) == 0 {
		return b
	}
	if len(b.fields) == 0 {
		return a
	}
	m := make(map[string]bool, len(a.fields)+len(b.fields))
	for k := range a.fields {
		m[k] = true
	}
	for k := range b.fields {
		m[k] = true
	}
	return fieldSet{fields: m}
}

// celAnalyzeRefs walks the checked AST once and returns both (a) the dotted
// audit paths an expression reads — e.g. agent.metadata.env — and (b) the
// top-level field-sets per root used to prune the activation.
//
// Audit paths capture only clean, Ident-rooted field-selection chains; has()
// test-only selects and index/optional access contribute no path, and now.* is
// intentionally excluded (the expression text carries the bound).
//
// Field-sets are a superset of what eval touches: for every Select whose operand
// is a root Ident, the field name is recorded (this catches has(), index, and
// optional access, whose innermost select on the root ident is always the top
// field — and comprehensions, since cel-go's visit() descends into IterRange).
// A bare root Ident that is not a Select operand sets all=true for that root, so
// pruning never drops a field the expression needs (an under-built field would
// be a missing key → fail-closed deny).
func celAnalyzeRefs(a *cel.Ast) (paths []string, segs [][]string, req, agt, usr, call fieldSet) {
	req, agt, usr, call = fieldSet{fields: map[string]bool{}}, fieldSet{fields: map[string]bool{}}, fieldSet{fields: map[string]bool{}}, fieldSet{fields: map[string]bool{}}
	native := a.NativeRep()
	if native == nil || native.Expr() == nil {
		return
	}

	var selects []celast.Expr
	consumed := map[int64]bool{}     // operand of some Select — an intermediate node
	skip := map[int64]bool{}         // container of an index/optional access — not a field path
	identCovered := map[int64]bool{} // root-Ident IDs that are a Select operand
	var rootIdents []celast.Expr     // Idents named request/agent/user/call
	celast.PostOrderVisit(native.Expr(), celast.NewExprVisitor(func(e celast.Expr) {
		switch e.Kind() {
		case celast.SelectKind:
			s := e.AsSelect()
			selects = append(selects, e)
			op := s.Operand()
			consumed[op.ID()] = true
			if op.Kind() == celast.IdentKind {
				switch op.AsIdent() {
				case "request":
					req.fields[s.FieldName()] = true
					identCovered[op.ID()] = true
				case "agent":
					agt.fields[s.FieldName()] = true
					identCovered[op.ID()] = true
				case "user":
					usr.fields[s.FieldName()] = true
					identCovered[op.ID()] = true
				case "call":
					call.fields[s.FieldName()] = true
					identCovered[op.ID()] = true
				}
			}
		case celast.IdentKind:
			switch e.AsIdent() {
			case "request", "agent", "user", "call":
				rootIdents = append(rootIdents, e)
			}
		case celast.CallKind:
			c := e.AsCall()
			switch c.FunctionName() {
			case "_?._", "_[_]", "optional_index":
				if args := c.Args(); len(args) > 0 {
					skip[args[0].ID()] = true
				}
			}
		}
	}))

	// Audit paths: maximal Ident-rooted select chains.
	pset := map[string]bool{}
	for _, e := range selects {
		if consumed[e.ID()] || skip[e.ID()] {
			continue
		}
		if p, ok := celSelectPath(e); ok {
			pset[p] = true
		}
	}
	if len(pset) > 0 {
		paths = make([]string, 0, len(pset))
		for p := range pset {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		segs = make([][]string, len(paths))
		for i, p := range paths {
			segs[i] = strings.Split(p, ".")
		}
	}

	// Bare root references (not a Select operand) disable pruning for that root.
	for _, id := range rootIdents {
		if identCovered[id.ID()] {
			continue
		}
		switch id.AsIdent() {
		case "request":
			req.all = true
		case "agent":
			agt.all = true
		case "user":
			usr.all = true
		case "call":
			call.all = true
		}
	}
	return
}

// celSelectPath reconstructs the dotted path for a Select chain top (e.g.
// agent.metadata.env). Returns ok=false if the chain contains a test-only
// select (has()) or does not bottom out on a request/agent/user/call Ident.
//
// The returned path is the operator's own spelling and is what lands in
// ConditionResult.Inputs — and therefore what an audit device's salt_fields
// entry must match verbatim. Renaming a namespace or field here renames the
// audit key with it.
func celSelectPath(e celast.Expr) (string, bool) {
	var fields []string
	cur := e
	for cur.Kind() == celast.SelectKind {
		sel := cur.AsSelect()
		if sel.IsTestOnly() {
			return "", false
		}
		fields = append(fields, sel.FieldName())
		cur = sel.Operand()
	}
	if cur.Kind() != celast.IdentKind {
		return "", false
	}
	switch cur.AsIdent() {
	case "request", "agent", "user", "call":
	default:
		return "", false
	}
	parts := make([]string, 0, len(fields)+1)
	parts = append(parts, cur.AsIdent())
	for i := len(fields) - 1; i >= 0; i-- {
		parts = append(parts, fields[i])
	}
	return strings.Join(parts, "."), true
}

// evalCELCondition evaluates a compiled condition against an activation.
// It is fail-closed: any evaluation error (type mismatch, missing key,
// runtime cost-limit) returns (false, err) so callers deny. The error is for
// audit categorization only and must not be surfaced to clients verbatim.
func evalCELCondition(prg cel.Program, activation any) (bool, error) {
	out, _, err := prg.Eval(activation)
	if err != nil {
		return false, err
	}
	b, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("condition did not evaluate to bool")
	}
	return b, nil
}

// buildRequestNS builds the `request` namespace, including only the fields f
// marks as referenced (all fields when f.all). data is always non-nil so
// has(request.data.x) is false rather than a nil-deref.
func buildRequestNS(req celRequestInput, f fieldSet) map[string]any {
	m := make(map[string]any, len(f.fields))
	if f.has("path") {
		m["path"] = req.Path
	}
	if f.has("operation") {
		m["operation"] = req.Operation
	}
	if f.has("client_ip") {
		m["client_ip"] = req.ClientIP
	}
	if f.has("mount_point") {
		m["mount_point"] = req.MountPoint
	}
	if f.has("mount_type") {
		m["mount_type"] = req.MountType
	}
	if f.has("mount_class") {
		m["mount_class"] = req.MountClass
	}
	if f.has("mount_accessor") {
		m["mount_accessor"] = req.MountAccessor
	}
	if f.has("transparent") {
		m["transparent"] = req.Transparent
	}
	if f.has("namespace") {
		m["namespace"] = req.Namespace
	}
	if f.has("data") {
		data := req.Data
		if data == nil {
			data = map[string]any{}
		}
		m["data"] = data
	}
	return m
}

// emptyStringMap is a shared, never-mutated empty map bound to agent.metadata
// when a principal carries none — non-nil (so absent-key access fails closed)
// without a per-request allocation.
var emptyStringMap = map[string]string{}

// buildPrincipalNS builds a principal namespace, including only the fields f
// marks as referenced (all fields when f.all). The expensive fields (metadata
// copy, actors/policies slices) are built only when referenced. metadata is
// non-nil.
//
// The token_-prefixed keys describe the credential rather than the principal:
// token_type carries values like jwt_role/cert_role, which name how the
// principal authenticated, not a kind of principal.
func buildPrincipalNS(p celPrincipalInput, f fieldSet, leg principalLeg) map[string]any {
	m := make(map[string]any, len(f.fields))
	if f.has("present") {
		m["present"] = p.Present
	}
	if f.has("principal") {
		m["principal"] = p.Principal
	}
	if f.has("role") {
		m["role"] = p.Role
	}
	if f.has("token_type") {
		m["token_type"] = p.Type
	}
	if f.has("namespace") {
		m["namespace"] = p.NamespacePath
	}
	if f.has("metadata") {
		// Bind the string map by reference — CEL adapts it via reflection — rather
		// than copying into a map[string]any. emptyStringMap keeps it non-nil (so
		// has(agent.metadata.x) is false and absent-key access fails closed)
		// without allocating.
		//
		// Safe only because a TokenEntry's Metadata is never mutated post-mint:
		// the entry is a shared cached pointer, so a post-mint write would be a
		// data race against concurrent evaluations.
		if p.Metadata != nil {
			m["metadata"] = p.Metadata
		} else {
			m["metadata"] = emptyStringMap
		}
	}
	if f.has("actors") {
		acts := make([]any, 0, len(p.Actors))
		for _, a := range p.Actors {
			acts = append(acts, map[string]any{
				"subject": a.Subject,
			})
		}
		m["actors"] = acts
	}
	// The user principal never authorizes — CBP is evaluated against the agent's
	// token alone — so `"admin" in user.policies` would read like an authorization
	// check that it is not. Suppressed at the builder rather than by withholding
	// the field from the caller's fieldSet, so a future field-set path cannot
	// reintroduce it by forgetting. Absent means a runtime no-such-key deny, not a
	// compile error: `user` is a dyn map.
	if f.has("policies") && leg != legUser {
		policies := make([]any, 0, len(p.Policies))
		for _, pol := range p.Policies {
			policies = append(policies, pol)
		}
		m["policies"] = policies
	}
	if f.has("token_ttl_seconds") {
		m["token_ttl_seconds"] = p.TTLSeconds
	}
	if f.has("token_expires_at") {
		m["token_expires_at"] = p.ExpiresAtUnix
	}
	return m
}

// buildBaseActivation eagerly builds the full activation map. Retained for unit
// tests; the request path uses celActivation (lazy) to avoid building
// namespaces an expression never references.
func buildBaseActivation(req celRequestInput, agt, usr celPrincipalInput, now time.Time) map[string]any {
	return map[string]any{
		"request": buildRequestNS(req, fieldSet{all: true}),
		"agent":   buildPrincipalNS(agt, fieldSet{all: true}, legAgent),
		"user":    buildPrincipalNS(usr, fieldSet{all: true}, legUser),
		"now":     now,
	}
}

// celActivation is a lazy interpreter.Activation: it builds each top-level
// namespace (request/agent/call) only when the expression resolves it, so an
// expression touching only one namespace doesn't allocate the others. One
// activation is built per evaluation (never shared), so the memoization is not
// a concurrency concern.
type celActivation struct {
	req        celRequestInput
	reqFields  fieldSet
	agt        celPrincipalInput
	agtFields  fieldSet
	usr        celPrincipalInput
	usrFields  fieldSet
	callFields fieldSet // used when building the per-call namespace (MCP)
	now        time.Time
	call       map[string]any // nil for path-level conditions

	reqNS map[string]any
	agtNS map[string]any
	usrNS map[string]any
}

func newCELActivation(req celRequestInput, reqFields fieldSet, agt celPrincipalInput, agtFields fieldSet, usr celPrincipalInput, usrFields fieldSet, now time.Time, call map[string]any) *celActivation {
	return &celActivation{req: req, reqFields: reqFields, agt: agt, agtFields: agtFields, usr: usr, usrFields: usrFields, now: now, call: call}
}

func (a *celActivation) Parent() interpreter.Activation { return nil }

func (a *celActivation) ResolveName(name string) (any, bool) {
	switch name {
	case "request":
		if a.reqNS == nil {
			a.reqNS = buildRequestNS(a.req, a.reqFields)
		}
		return a.reqNS, true
	case "agent":
		if a.agtNS == nil {
			a.agtNS = buildPrincipalNS(a.agt, a.agtFields, legAgent)
		}
		return a.agtNS, true
	case "user":
		if a.usrNS == nil {
			a.usrNS = buildPrincipalNS(a.usr, a.usrFields, legUser)
		}
		return a.usrNS, true
	case "now":
		return a.now, true
	case "call":
		if a.call != nil {
			return a.call, true
		}
		return nil, false
	default:
		return nil, false
	}
}

// addCallToActivation layers the per-call `call` namespace onto a base
// activation for an MCP Policy condition. args are typed from ParamValue.Kind;
// non-scalar / null / missing values are omitted so absent-key access fails
// closed. Mutates and returns base.
func addCallToActivation(base map[string]any, method, tool string, matchArgs map[string]logical.ParamValue, batchIndex int) map[string]any {
	base["call"] = buildCallNS(method, tool, matchArgs, batchIndex, fieldSet{all: true})
	return base
}

// buildCallNS builds the per-call `call` namespace, including only the fields f
// marks as referenced (all fields when f.all). args are typed from
// ParamValue.Kind; non-scalar / null / missing values are omitted so absent-key
// access fails closed.
func buildCallNS(method, tool string, matchArgs map[string]logical.ParamValue, batchIndex int, f fieldSet) map[string]any {
	m := make(map[string]any, len(f.fields))
	if f.has("method") {
		m["method"] = method
	}
	if f.has("tool") {
		m["tool"] = tool
	}
	if f.has("args") {
		args := make(map[string]any, len(matchArgs))
		for k, pv := range matchArgs {
			if v, ok := paramValueToCEL(pv); ok {
				args[k] = v
			}
		}
		m["args"] = args
	}
	if f.has("batch_index") {
		m["batch_index"] = batchIndex
	}
	return m
}

// paramValueToCEL converts a parsed MCP argument to a typed CEL value. Only
// scalars are bound (number→float64, bool, string); null/object/array/missing
// return ok=false so the argument is absent in the activation and any access
// fails closed.
func paramValueToCEL(pv logical.ParamValue) (any, bool) {
	switch pv.Kind {
	case logical.ParamNumber:
		f, err := strconv.ParseFloat(pv.Str, 64)
		if err != nil {
			return nil, false
		}
		return f, true
	case logical.ParamBool:
		return pv.Str == "true", true
	case logical.ParamString:
		return pv.Str, true
	default:
		return nil, false
	}
}

// compiledCondition is a CEL condition compiled at policy-parse time, ready to
// evaluate. Program is immutable and safe for concurrent Eval, so it is shared
// (not deep-copied) when merged into a CBP.
type compiledCondition struct {
	Source  string
	Program cel.Program
	// RefPaths are the dotted request/agent/user/call variable paths the expression
	// reads, snapshotted into the audited ConditionResult.Inputs at eval time.
	// RefSegs is the pre-split form (compile-time) so eval avoids strings.Split.
	RefPaths []string
	RefSegs  [][]string
	// ReqFields/AgtFields/UsrFields/CallFields are the top-level namespace fields
	// the expression reads, used to build only the referenced parts of the activation.
	ReqFields  fieldSet
	AgtFields  fieldSet
	UsrFields  fieldSet
	CallFields fieldSet
}

// Package-level envs, built once and reused. The base env compiles path-level
// conditions; the MCP env (base + call.*) compiles MCP policy conditions.
var (
	baseEnvOnce sync.Once
	baseEnv     *cel.Env
	baseEnvErr  error

	mcpEnvOnce sync.Once
	mcpEnv     *cel.Env
	mcpEnvErr  error
)

func baseCELEnv() (*cel.Env, error) {
	baseEnvOnce.Do(func() { baseEnv, baseEnvErr = buildCELEnv(false) })
	return baseEnv, baseEnvErr
}

func mcpCELEnv() (*cel.Env, error) {
	mcpEnvOnce.Do(func() { mcpEnv, mcpEnvErr = buildCELEnv(true) })
	return mcpEnv, mcpEnvErr
}

// celRequestInputFromRequest adapts a *logical.Request into the request context
// exposed to expressions. All fields are populated before policy evaluation.
// nsPath is the request's target namespace (namespace.FromContext at eval),
// exposed as request.namespace — distinct from agent.namespace (where the token
// was minted). It is not derivable from mount_point, which concatenates the
// namespace prefix with the mount path.
func celRequestInputFromRequest(req *logical.Request, nsPath string) celRequestInput {
	if req == nil {
		return celRequestInput{Namespace: nsPath}
	}
	return celRequestInput{
		Path:          req.Path,
		Operation:     string(req.Operation),
		ClientIP:      req.ClientIP,
		MountPoint:    req.MountPoint,
		MountType:     req.MountType,
		MountClass:    req.MountClass,
		MountAccessor: req.MountAccessor,
		Transparent:   req.Transparent,
		Namespace:     nsPath,
		Data:          req.Data,
	}
}

// celPrincipalInputFromEntry adapts a *logical.TokenEntry into the non-secret
// principal context exposed to expressions. now is the once-per-request
// snapshot used to derive the remaining TTL.
func celPrincipalInputFromEntry(te *logical.TokenEntry, now time.Time) celPrincipalInput {
	if te == nil {
		return celPrincipalInput{}
	}
	var ttl, expires int64
	if !te.ExpireAt.IsZero() {
		ttl = int64(te.ExpireAt.Sub(now).Seconds())
		expires = te.ExpireAt.Unix()
	}
	return celPrincipalInput{
		Present:       true,
		Principal:     te.PrincipalID,
		Role:          te.RoleName,
		Type:          te.Type,
		NamespacePath: te.NamespacePath,
		Policies:      te.Policies,
		Metadata:      te.Metadata,
		Actors:        te.Actors,
		TTLSeconds:    ttl,
		ExpiresAtUnix: expires,
	}
}

// celUserInputFromPrincipal adapts a *logical.UserPrincipal into the non-secret
// principal context exposed as `user`. A nil principal — or one carrying no
// validated token entry — yields {Present: false} rather than a zero value that
// would read as an anonymous user.
//
// UserPrincipal.RawToken is deliberately not read: it is a bearer secret, kept
// off audit serialization, and must never reach an activation.
func celUserInputFromPrincipal(up *logical.UserPrincipal, now time.Time) celPrincipalInput {
	if up == nil {
		return celPrincipalInput{}
	}
	return celPrincipalInputFromEntry(up.TokenEntry, now)
}

// celUserInputFromRequest is celUserInputFromPrincipal over a request that may
// itself be nil — the condition evaluators tolerate a nil request (see
// celRequestInputFromRequest), so reading req.User bare would panic there.
func celUserInputFromRequest(req *logical.Request, now time.Time) celPrincipalInput {
	if req == nil {
		return celPrincipalInput{}
	}
	return celUserInputFromPrincipal(req.User, now)
}

// celErrorKind maps a CEL evaluation error to a coarse, sanitized category for
// audit. It never embeds the raw error string or any adversary-controlled value.
func celErrorKind(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "no such key"), strings.Contains(s, "no such attribute"):
		return "no_such_key"
	case strings.Contains(s, "operation cancelled: actual cost limit exceeded"), strings.Contains(s, "cost limit"):
		return "cost_exceeded"
	case strings.Contains(s, "no such overload"):
		return "type_mismatch"
	default:
		return "eval_error"
	}
}

// evaluatePathConditions evaluates the merged path-level conditions with OR
// semantics: the gate passes if any condition is true. An empty list is
// unconditional. Evaluation is fail-closed — an erroring condition denies, and
// if no condition passes the deciding result is recorded for audit (Sanitized).
func evaluatePathConditions(conds []*compiledCondition, req *logical.Request, te *logical.TokenEntry, now time.Time, nsPath string) (bool, *logical.ConditionResult) {
	if len(conds) == 0 {
		return true, nil
	}
	// Build the activation pruned to the union of fields the conditions read.
	// The common single-condition case reuses its field-sets with no allocation.
	reqF, agtF, usrF := conds[0].ReqFields, conds[0].AgtFields, conds[0].UsrFields
	for _, c := range conds[1:] {
		reqF = unionFieldSets(reqF, c.ReqFields)
		agtF = unionFieldSets(agtF, c.AgtFields)
		usrF = unionFieldSets(usrF, c.UsrFields)
	}
	act := newCELActivation(
		celRequestInputFromRequest(req, nsPath), reqF,
		celPrincipalInputFromEntry(te, now), agtF,
		celUserInputFromRequest(req, now), usrF,
		now, nil)

	var deciding *logical.ConditionResult
	for _, c := range conds {
		ok, err := evalCELCondition(c.Program, act)
		if err != nil {
			if deciding == nil {
				deciding = &logical.ConditionResult{Decision: "deny", Expression: c.Source, ErrorKind: celErrorKind(err), Inputs: resolveConditionInputs(c.RefPaths, c.RefSegs, act)}
			}
			continue
		}
		if ok {
			res := &logical.ConditionResult{Decision: "allow", Expression: c.Source, Inputs: resolveConditionInputs(c.RefPaths, c.RefSegs, act)}
			res.Sanitize()
			return true, res
		}
		if deciding == nil {
			deciding = &logical.ConditionResult{Decision: "deny", Expression: c.Source, Inputs: resolveConditionInputs(c.RefPaths, c.RefSegs, act)}
		}
	}
	deciding.Sanitize()
	return false, deciding
}

// resolveConditionInputs snapshots the values of the expression's referenced
// paths from the evaluation activation into a map for audit. Values are
// formatted to strings in clear (sensitive keys are protected by optional
// salt_fields at the audit format layer, not here). Absent keys — the
// fail-closed case — are omitted. Returns nil when nothing resolved.
func resolveConditionInputs(refPaths []string, refSegs [][]string, act *celActivation) map[string]string {
	if len(refSegs) == 0 || act == nil {
		return nil
	}
	out := make(map[string]string, len(refSegs))
	for i, segs := range refSegs {
		cur, ok := act.ResolveName(segs[0])
		if !ok {
			continue
		}
		for _, s := range segs[1:] {
			switch mm := cur.(type) {
			case map[string]any:
				cur, ok = mm[s]
			case map[string]string:
				// agent.metadata is bound as a string map (see buildPrincipalNS).
				cur, ok = mm[s]
			default:
				cur, ok = nil, false
			}
			if !ok {
				break
			}
		}
		if !ok {
			continue
		}
		out[refPaths[i]] = formatCELValue(cur)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// formatCELValue renders a resolved activation value as an audit string.
// Scalars format precisely; non-scalars (lists/maps such as agent.policies /
// agent.actors) fall back to %v.
func formatCELValue(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64)
	case int64:
		return strconv.FormatInt(t, 10)
	case int:
		return strconv.Itoa(t)
	default:
		return fmt.Sprintf("%v", t)
	}
}
