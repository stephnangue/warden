// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

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
//	  request.mount_accessor, request.transparent, request.data.<k>
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
func compileCELCondition(env *cel.Env, src string) (cel.Program, error) {
	ast, iss := env.Compile(src)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("condition does not compile: %w", iss.Err())
	}
	if !ast.OutputType().IsExactType(cel.BoolType) {
		return nil, fmt.Errorf("condition must evaluate to bool, got %s", ast.OutputType())
	}

	est, err := env.EstimateCost(ast, celCostEstimator{maxSize: celInputSizeBound})
	if err != nil {
		return nil, fmt.Errorf("condition cost estimation failed: %w", err)
	}
	if est.Max > maxConditionCost {
		return nil, fmt.Errorf("condition worst-case cost %d exceeds limit %d", est.Max, maxConditionCost)
	}

	prg, err := env.Program(ast, cel.CostLimit(maxConditionCost))
	if err != nil {
		return nil, fmt.Errorf("condition program construction failed: %w", err)
	}
	return prg, nil
}

// evalCELCondition evaluates a compiled condition against an activation.
// It is fail-closed: any evaluation error (type mismatch, missing key,
// runtime cost-limit) returns (false, err) so callers deny. The error is for
// audit categorization only and must not be surfaced to clients verbatim.
func evalCELCondition(prg cel.Program, activation map[string]any) (bool, error) {
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

// buildBaseActivation assembles the request-wide activation shared by path-level
// and mcp{} conditions. Containers are always non-nil so has() works and absent
// nested keys fail closed. now is the once-per-request snapshot.
func buildBaseActivation(req celRequestInput, tok celTokenInput, now time.Time) map[string]any {
	data := req.Data
	if data == nil {
		data = map[string]any{}
	}

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
		"request": map[string]any{
			"path":           req.Path,
			"operation":      req.Operation,
			"client_ip":      req.ClientIP,
			"mount_point":    req.MountPoint,
			"mount_type":     req.MountType,
			"mount_class":    req.MountClass,
			"mount_accessor": req.MountAccessor,
			"transparent":    req.Transparent,
			"data":           data,
		},
		"token": map[string]any{
			"principal":   tok.Principal,
			"role":        tok.Role,
			"type":        tok.Type,
			"namespace":   tok.NamespacePath,
			"policies":    policies,
			"metadata":    md,
			"actors":      acts,
			"ttl_seconds": tok.TTLSeconds,
			"expires_at":  tok.ExpiresAtUnix,
		},
		"now": now,
	}
}

// addCallToActivation layers the per-call `call` namespace onto a base
// activation for an mcp{} condition. args are typed from ParamValue.Kind;
// non-scalar / null / missing values are omitted so absent-key access fails
// closed. Mutates and returns base.
func addCallToActivation(base map[string]any, method, tool string, matchArgs map[string]logical.ParamValue, batchIndex int) map[string]any {
	args := make(map[string]any, len(matchArgs))
	for k, pv := range matchArgs {
		if v, ok := paramValueToCEL(pv); ok {
			args[k] = v
		}
	}
	base["call"] = map[string]any{
		"method":      method,
		"tool":        tool,
		"args":        args,
		"batch_index": batchIndex,
	}
	return base
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
