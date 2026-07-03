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
//   - Two envs: a base env (request/token/now) for path-level conditions and an
//     MCP env (base + call) for mcp{} conditions. Two envs make a path-level
//     condition that references call.* a COMPILE error, not a silent runtime
//     deny.
//   - request/token/call are map(string, dyn): the env is shared across every
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
//	token.principal, token.role, token.type, token.namespace,
//	  token.policies (list), token.metadata.<k>, token.actors (list of
//	  {subject, verified}), token.ttl_seconds, token.expires_at
//	now (timestamp)
//	call.method, call.tool, call.args.<k>, call.batch_index   (mcp{} only)
//
// Secret material (token value, accessor, client token) is never exposed.

const (
	// maxConditionCost bounds a single CEL evaluation, both statically (rejected
	// at policy-write time) and at runtime (cel.CostLimit backstop). Units are
	// cel-go's abstract cost units.
	maxConditionCost uint64 = 1_000_000

	// celInputSizeBound is the conservative size (entries / characters) the cost
	// estimator assumes for our dynamic-map variables, so comprehensions/string
	// ops over adversary-sized inputs are cost-bounded at compile time. Sized to
	// the request/body cap; tightened when wired to the real cap.
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

// celTokenInput is the non-secret token context mapped into the `token`
// namespace. Decoupled from *logical.TokenEntry so the activation builder stays
// unit-testable; the wiring layer adapts the token entry into this.
type celTokenInput struct {
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

// buildCELEnv constructs a CEL environment. When mcp is true the env also
// declares the per-call `call` namespace, producing the MCP env; otherwise it
// is the base (path-level) env.
func buildCELEnv(mcp bool) (*cel.Env, error) {
	opts := []cel.EnvOption{
		// request-wide namespaces; dyn maps (see design note).
		cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("token", cel.MapType(cel.StringType, cel.DynType)),
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
// cel-go owns the per-operation base costs; this only feeds the sizes cel-go
// cannot infer.
type celCostEstimator struct {
	maxSize uint64
}

func (e celCostEstimator) EstimateSize(node checker.AstNode) *checker.SizeEstimate {
	if path := node.Path(); len(path) > 0 {
		switch path[0] {
		case "request", "token", "call":
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
func compileCELCondition(env *cel.Env, src string) (cel.Program, []string, error) {
	ast, iss := env.Compile(src)
	if iss != nil && iss.Err() != nil {
		return nil, nil, fmt.Errorf("condition does not compile: %w", iss.Err())
	}
	if !ast.OutputType().IsExactType(cel.BoolType) {
		return nil, nil, fmt.Errorf("condition must evaluate to bool, got %s", ast.OutputType())
	}

	est, err := env.EstimateCost(ast, celCostEstimator{maxSize: celInputSizeBound})
	if err != nil {
		return nil, nil, fmt.Errorf("condition cost estimation failed: %w", err)
	}
	if est.Max > maxConditionCost {
		return nil, nil, fmt.Errorf("condition worst-case cost %d exceeds limit %d", est.Max, maxConditionCost)
	}

	// The runtime cost tracker (cel.CostLimit) allocates per eval and wraps
	// the program in an observable interpretable — a real hot-path cost. It is
	// only a backstop for inputs larger than the static estimate assumed, so
	// it is only needed when the expression's cost is input-size-dependent.
	// Detect that by re-estimating with a larger size bound: if the worst-case
	// cost is unchanged, the cost is input-independent and already capped by
	// the static bound above, so the per-eval tracker is omitted.
	est2, err := env.EstimateCost(ast, celCostEstimator{maxSize: celInputSizeBound * 2})
	if err != nil {
		return nil, nil, fmt.Errorf("condition cost estimation failed: %w", err)
	}
	var progOpts []cel.ProgramOption
	if est2.Max != est.Max {
		progOpts = append(progOpts, cel.CostLimit(maxConditionCost))
	}

	prg, err := env.Program(ast, progOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("condition program construction failed: %w", err)
	}
	return prg, celReferencedPaths(ast), nil
}

// celReferencedPaths reconstructs the dotted variable paths an expression reads
// — e.g. token.metadata.env, call.args.amount — so the deciding condition can
// record its inputs for audit. Only clean, Ident-rooted field-selection chains
// under request/token/call are captured; has() test-only selects and
// index/optional access (request.data["k"], call.args.?x) contribute no path,
// and now.* time predicates are intentionally not captured (the expression text
// carries the bound). The result is deduped and sorted.
func celReferencedPaths(a *cel.Ast) []string {
	native := a.NativeRep()
	if native == nil {
		return nil
	}
	root := native.Expr()
	if root == nil {
		return nil
	}

	var selects []celast.Expr
	consumed := map[int64]bool{} // operand of some Select — an intermediate node
	skip := map[int64]bool{}     // container of an index/optional access — not a field path
	celast.PostOrderVisit(root, celast.NewExprVisitor(func(e celast.Expr) {
		switch e.Kind() {
		case celast.SelectKind:
			selects = append(selects, e)
			consumed[e.AsSelect().Operand().ID()] = true
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

	set := map[string]bool{}
	for _, e := range selects {
		if consumed[e.ID()] || skip[e.ID()] {
			continue
		}
		if p, ok := celSelectPath(e); ok {
			set[p] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// celSelectPath reconstructs the dotted path for a Select chain top (e.g.
// token.metadata.env). Returns ok=false if the chain contains a test-only
// select (has()) or does not bottom out on a request/token/call Ident.
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
	case "request", "token", "call":
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

// buildRequestNS builds the `request` namespace. data is always non-nil so
// has(request.data.x) is false rather than a nil-deref.
func buildRequestNS(req celRequestInput) map[string]any {
	data := req.Data
	if data == nil {
		data = map[string]any{}
	}
	return map[string]any{
		"path":           req.Path,
		"operation":      req.Operation,
		"client_ip":      req.ClientIP,
		"mount_point":    req.MountPoint,
		"mount_type":     req.MountType,
		"mount_class":    req.MountClass,
		"mount_accessor": req.MountAccessor,
		"transparent":    req.Transparent,
		"namespace":      req.Namespace,
		"data":           data,
	}
}

// buildTokenNS builds the `token` namespace. metadata is always non-nil.
func buildTokenNS(tok celTokenInput) map[string]any {
	md := make(map[string]any, len(tok.Metadata))
	for k, v := range tok.Metadata {
		md[k] = v
	}
	acts := make([]any, 0, len(tok.Actors))
	for _, a := range tok.Actors {
		acts = append(acts, map[string]any{
			"subject":  a.Subject,
			"verified": a.Verified,
		})
	}
	policies := make([]any, 0, len(tok.Policies))
	for _, p := range tok.Policies {
		policies = append(policies, p)
	}
	return map[string]any{
		"principal":   tok.Principal,
		"role":        tok.Role,
		"type":        tok.Type,
		"namespace":   tok.NamespacePath,
		"policies":    policies,
		"metadata":    md,
		"actors":      acts,
		"ttl_seconds": tok.TTLSeconds,
		"expires_at":  tok.ExpiresAtUnix,
	}
}

// buildBaseActivation eagerly builds the full activation map. Retained for unit
// tests; the request path uses celActivation (lazy) to avoid building
// namespaces an expression never references.
func buildBaseActivation(req celRequestInput, tok celTokenInput, now time.Time) map[string]any {
	return map[string]any{
		"request": buildRequestNS(req),
		"token":   buildTokenNS(tok),
		"now":     now,
	}
}

// celActivation is a lazy interpreter.Activation: it builds each top-level
// namespace (request/token/call) only when the expression resolves it, so an
// expression touching only one namespace doesn't allocate the others. One
// activation is built per evaluation (never shared), so the memoization is not
// a concurrency concern.
type celActivation struct {
	req  celRequestInput
	tok  celTokenInput
	now  time.Time
	call map[string]any // nil for path-level conditions

	reqNS map[string]any
	tokNS map[string]any
}

func newCELActivation(req celRequestInput, tok celTokenInput, now time.Time, call map[string]any) *celActivation {
	return &celActivation{req: req, tok: tok, now: now, call: call}
}

func (a *celActivation) Parent() interpreter.Activation { return nil }

func (a *celActivation) ResolveName(name string) (any, bool) {
	switch name {
	case "request":
		if a.reqNS == nil {
			a.reqNS = buildRequestNS(a.req)
		}
		return a.reqNS, true
	case "token":
		if a.tokNS == nil {
			a.tokNS = buildTokenNS(a.tok)
		}
		return a.tokNS, true
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
// activation for an mcp{} condition. args are typed from ParamValue.Kind;
// non-scalar / null / missing values are omitted so absent-key access fails
// closed. Mutates and returns base.
func addCallToActivation(base map[string]any, method, tool string, matchArgs map[string]logical.ParamValue, batchIndex int) map[string]any {
	base["call"] = buildCallNS(method, tool, matchArgs, batchIndex)
	return base
}

// buildCallNS builds the per-call `call` namespace. args are typed from
// ParamValue.Kind; non-scalar / null / missing values are omitted so absent-key
// access fails closed.
func buildCallNS(method, tool string, matchArgs map[string]logical.ParamValue, batchIndex int) map[string]any {
	args := make(map[string]any, len(matchArgs))
	for k, pv := range matchArgs {
		if v, ok := paramValueToCEL(pv); ok {
			args[k] = v
		}
	}
	return map[string]any{
		"method":      method,
		"tool":        tool,
		"args":        args,
		"batch_index": batchIndex,
	}
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
	// RefPaths are the dotted request/token/call variable paths the expression
	// reads (from celReferencedPaths), snapshotted into the audited
	// ConditionResult.Inputs at eval time.
	RefPaths []string
}

// Package-level envs, built once and reused. The base env compiles path-level
// conditions; the MCP env (base + call.*) compiles mcp{} conditions.
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
// exposed as request.namespace — distinct from token.namespace (where the token
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

// celTokenInputFromEntry adapts a *logical.TokenEntry into the non-secret token
// context exposed to expressions. now is the once-per-request snapshot used to
// derive the remaining TTL.
func celTokenInputFromEntry(te *logical.TokenEntry, now time.Time) celTokenInput {
	if te == nil {
		return celTokenInput{}
	}
	var ttl, expires int64
	if !te.ExpireAt.IsZero() {
		ttl = int64(te.ExpireAt.Sub(now).Seconds())
		expires = te.ExpireAt.Unix()
	}
	return celTokenInput{
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
	act := newCELActivation(celRequestInputFromRequest(req, nsPath), celTokenInputFromEntry(te, now), now, nil)

	var deciding *logical.ConditionResult
	for _, c := range conds {
		ok, err := evalCELCondition(c.Program, act)
		if err != nil {
			if deciding == nil {
				deciding = &logical.ConditionResult{Decision: "deny", Expression: c.Source, ErrorKind: celErrorKind(err), Inputs: resolveConditionInputs(c.RefPaths, act)}
			}
			continue
		}
		if ok {
			res := &logical.ConditionResult{Decision: "allow", Expression: c.Source, Inputs: resolveConditionInputs(c.RefPaths, act)}
			res.Sanitize()
			return true, res
		}
		if deciding == nil {
			deciding = &logical.ConditionResult{Decision: "deny", Expression: c.Source, Inputs: resolveConditionInputs(c.RefPaths, act)}
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
func resolveConditionInputs(refPaths []string, act *celActivation) map[string]string {
	if len(refPaths) == 0 || act == nil {
		return nil
	}
	out := make(map[string]string, len(refPaths))
	for _, p := range refPaths {
		segs := strings.Split(p, ".")
		cur, ok := act.ResolveName(segs[0])
		if !ok {
			continue
		}
		for _, s := range segs[1:] {
			m, isMap := cur.(map[string]any)
			if !isMap {
				cur = nil
				ok = false
				break
			}
			if cur, ok = m[s]; !ok {
				break
			}
		}
		if !ok {
			continue
		}
		out[p] = formatCELValue(cur)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// formatCELValue renders a resolved activation value as an audit string.
// Scalars format precisely; non-scalars (lists/maps such as token.policies /
// token.actors) fall back to %v.
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
