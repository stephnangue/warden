// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/cel-go/cel"

	"github.com/stephnangue/warden/logical"
)

// mustAst compiles src to a checked AST or fails the test.
func mustAst(t *testing.T, env *cel.Env, src string) *cel.Ast {
	t.Helper()
	ast, iss := env.Compile(src)
	if iss != nil && iss.Err() != nil {
		t.Fatalf("compile %q: %v", src, iss.Err())
	}
	return ast
}

// bigStringKeyMap builds a request.data map with n distinct keys, used to drive
// a size-dependent condition past a (test-injected) runtime cost limit.
func bigStringKeyMap(n int) map[string]any {
	m := make(map[string]any, n)
	for i := 0; i < n; i++ {
		m["k"+strconv.Itoa(i)] = i
	}
	return m
}

// mustEnv builds the base or MCP env or fails the test.
func mustEnv(t *testing.T, mcp bool) *cel.Env {
	t.Helper()
	env, err := buildCELEnv(mcp)
	if err != nil {
		t.Fatalf("buildCELEnv(mcp=%v): %v", mcp, err)
	}
	return env
}

// mustCompile compiles src against env or fails the test.
func mustCompile(t *testing.T, env *cel.Env, src string) cel.Program {
	t.Helper()
	c, err := compileCELCondition(env, src)
	if err != nil {
		t.Fatalf("compile %q: %v", src, err)
	}
	return c.Program
}

// baseAct is a minimal request/token activation for path-level tests.
func baseAct(req celRequestInput, tok celTokenInput, now time.Time) map[string]any {
	return buildBaseActivation(req, tok, now)
}

// mcpAct is a base activation plus a single call namespace.
func mcpAct(now time.Time, tool string, args map[string]logical.ParamValue) map[string]any {
	base := buildBaseActivation(celRequestInput{Path: "mcp/x", Operation: "update"}, celTokenInput{}, now)
	return addCallToActivation(base, "tools/call", tool, args, 0)
}

func num(s string) logical.ParamValue { return logical.ParamValue{Kind: logical.ParamNumber, Str: s} }
func str(s string) logical.ParamValue { return logical.ParamValue{Kind: logical.ParamString, Str: s} }

func TestCEL_PathLevelEnvRejectsCallReference(t *testing.T) {
	// A path-level (base) env must NOT know call.* — referencing it is a
	// compile-time error, never a silent runtime deny.
	if _, err := compileCELCondition(mustEnv(t, false), "call.args.amount <= 1500"); err == nil {
		t.Fatal("expected compile error for call.* in path-level env, got nil")
	}
	// The MCP env accepts the same expression.
	mustCompile(t, mustEnv(t, true), "call.args.amount <= 1500")
}

func TestCEL_NonBoolRejected(t *testing.T) {
	if _, err := compileCELCondition(mustEnv(t, false), "1 + 1"); err == nil {
		t.Fatal("expected rejection of non-bool condition")
	}
}

// TestCEL_CostRejectedAtCompile confirms an expression whose worst-case cost
// exceeds the budget at the estimator size bound is rejected at policy-write
// time (a nested comprehension is ~size², well over the limit at 8192).
func TestCEL_CostRejectedAtCompile(t *testing.T) {
	_, err := compileCELCondition(mustEnv(t, true),
		"call.args.all(k, call.args.all(j, k == j))")
	if err == nil {
		t.Fatal("expected compile-time cost rejection for a nested comprehension")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("expected a cost-limit error, got: %v", err)
	}
}

// TestCEL_CostIsSizeDependent locks the decision that gates the runtime
// CostLimit: comprehensions/size-scaling ops are size-dependent, scalar
// comparisons are not.
func TestCEL_CostIsSizeDependent(t *testing.T) {
	mcp := mustEnv(t, true)
	dep, err := celCostIsSizeDependent(mcp, mustAst(t, mcp, "call.args.all(k, k != '')"), 8192)
	if err != nil || !dep {
		t.Fatalf("comprehension should be size-dependent: dep=%v err=%v", dep, err)
	}
	base := mustEnv(t, false)
	dep, err = celCostIsSizeDependent(base, mustAst(t, base, "request.mount_type == 'vault'"), 8192)
	if err != nil || dep {
		t.Fatalf("scalar comparison should be size-independent: dep=%v err=%v", dep, err)
	}
}

// TestCEL_RuntimeCostLimitDenies exercises the runtime cel.CostLimit backstop:
// a size-dependent expression compiles under a small injected budget (its
// estimate at the small size bound fits), then a larger activation drives eval
// past the budget → fail-closed error. Uses the compile-with-limits seam so the
// test is deterministic without a million-entry activation.
func TestCEL_RuntimeCostLimitDenies(t *testing.T) {
	env := mustEnv(t, false)
	c, err := compileCELConditionWithLimits(env, "request.data.all(k, k != '')", 100, 5)
	if err != nil {
		t.Fatalf("expected the expression to compile under the injected bound: %v", err)
	}
	now := time.Unix(0, 0).UTC()
	act := buildBaseActivation(celRequestInput{Data: bigStringKeyMap(500)}, celTokenInput{}, now)
	ok, err := evalCELCondition(c.Program, act)
	if ok {
		t.Fatal("cost-exceeded eval must not allow")
	}
	if err == nil {
		t.Fatal("expected a runtime cost-limit error")
	}
	if got := celErrorKind(err); got != "cost_exceeded" {
		t.Fatalf("error kind = %q, want cost_exceeded (err: %v)", got, err)
	}
}

// TestCEL_ErrorKind pins celErrorKind's categorization (it substring-matches
// cel-go v0.28.1 error text — a table test guards against silent reclassification
// on upgrade).
func TestCEL_ErrorKind(t *testing.T) {
	now := time.Unix(0, 0).UTC()
	mcp := mustEnv(t, true)
	base := mustEnv(t, false)

	mustErrKind := func(label string, err error, want string) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: expected an eval error, got none", label)
		}
		if got := celErrorKind(err); got != want {
			t.Fatalf("%s: kind=%q want %q (err: %v)", label, got, want, err)
		}
	}

	// no_such_key — missing argument.
	_, err := evalCELCondition(mustCompile(t, mcp, "call.args.amount <= 1500"),
		mcpAct(now, "pay", nil))
	mustErrKind("missing arg", err, "no_such_key")

	// type_mismatch — string argument against a numeric comparison.
	_, err = evalCELCondition(mustCompile(t, mcp, "call.args.amount <= 1500"),
		mcpAct(now, "pay", map[string]logical.ParamValue{"amount": str("x")}))
	mustErrKind("string vs numeric", err, "type_mismatch")

	// cost_exceeded — runtime cost-limit trip (via the seam).
	c, err := compileCELConditionWithLimits(base, "request.data.all(k, k != '')", 100, 5)
	if err != nil {
		t.Fatalf("seam compile: %v", err)
	}
	_, err = evalCELCondition(c.Program,
		buildBaseActivation(celRequestInput{Data: bigStringKeyMap(500)}, celTokenInput{}, now))
	mustErrKind("cost limit", err, "cost_exceeded")

	// eval_error — any error outside the known categories maps to the catch-all.
	if got := celErrorKind(errors.New("unexpected internal failure")); got != "eval_error" {
		t.Fatalf("generic error: kind=%q want eval_error", got)
	}
}

// TestCEL_ReferencedPaths locks in the dotted request/token/call paths captured
// for audit Inputs: clean field-selection chains are captured; has(),
// index/optional access, and now.* are not.
func TestCEL_ReferencedPaths(t *testing.T) {
	cases := []struct {
		name string
		mcp  bool
		src  string
		want []string
	}{
		{"token+call scalars", true,
			"token.metadata.env == 'prod' && call.args.amount <= 1500",
			[]string{"call.args.amount", "token.metadata.env"}},
		{"has and index and optional contribute nothing", true,
			`has(request.data.x) && request.data["k"] == "v" && call.args.?y.orValue(0) <= 3`,
			nil},
		{"nested token + list arg", false,
			"token.principal == 'a' && size(token.policies) > 0",
			[]string{"token.policies", "token.principal"}},
		{"now not captured", false,
			`now.getHours("UTC") < 18 && token.metadata.env == "prod"`,
			[]string{"token.metadata.env"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := compileCELCondition(mustEnv(t, tc.mcp), tc.src)
			if err != nil {
				t.Fatalf("compile %q: %v", tc.src, err)
			}
			if !reflect.DeepEqual(c.RefPaths, tc.want) {
				t.Fatalf("paths = %v, want %v", c.RefPaths, tc.want)
			}
		})
	}
}

// TestCEL_FieldRefs locks in the top-level field-sets used to prune the
// activation. The invariant is a superset: has(), index, optional access, and
// comprehensions must all still record the top field they touch, and a bare
// root reference must trip the all-fields fallback — an under-built field would
// be a missing key at eval → fail-closed deny.
func TestCEL_FieldRefs(t *testing.T) {
	fs := func(names ...string) map[string]bool {
		m := map[string]bool{}
		for _, n := range names {
			m[n] = true
		}
		return m
	}
	cases := []struct {
		name           string
		mcp            bool
		src            string
		req, tok, cal  map[string]bool
		reqAll, tokAll bool
	}{
		{name: "scalar select", src: "token.metadata.env == 'prod'", tok: fs("metadata")},
		{name: "has()", src: "has(request.data.x)", req: fs("data")},
		{name: "index", src: `request.data["k"] == "v"`, req: fs("data")},
		{name: "optional", mcp: true, src: "call.args.?amount.orValue(0) <= 3", cal: fs("args")},
		{name: "comprehension", src: "size(token.actors) > 0 && token.actors.all(a, a.verified)", tok: fs("actors")},
		{name: "multi-field", src: "request.data.x <= 1 && request.namespace == token.namespace", req: fs("data", "namespace"), tok: fs("namespace")},
		{name: "bare root -> all", src: "size(token) > 0 || token.metadata.env == 'x'", tok: fs("metadata"), tokAll: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := compileCELCondition(mustEnv(t, tc.mcp), tc.src)
			if err != nil {
				t.Fatalf("compile %q: %v", tc.src, err)
			}
			check := func(label string, got fieldSet, wantAll bool, want map[string]bool) {
				if want == nil {
					want = map[string]bool{}
				}
				if got.all != wantAll || !reflect.DeepEqual(got.fields, want) {
					t.Errorf("%s: got {all=%v %v}, want {all=%v %v}", label, got.all, got.fields, wantAll, want)
				}
			}
			check("request", c.ReqFields, tc.reqAll, tc.req)
			check("token", c.TokFields, tc.tokAll, tc.tok)
			check("call", c.CallFields, false, tc.cal)
		})
	}
}

func TestCEL_NumericComparison(t *testing.T) {
	prg := mustCompile(t, mustEnv(t, true), "call.args.amount <= 1500")
	now := time.Unix(0, 0).UTC()

	got, err := evalCELCondition(prg, mcpAct(now, "create_payment", map[string]logical.ParamValue{"amount": num("1200")}))
	if err != nil || !got {
		t.Fatalf("amount=1200: got=%v err=%v, want true", got, err)
	}
	got, err = evalCELCondition(prg, mcpAct(now, "create_payment", map[string]logical.ParamValue{"amount": num("2000")}))
	if err != nil || got {
		t.Fatalf("amount=2000: got=%v err=%v, want false", got, err)
	}
}

func TestCEL_MissingArgFailsClosed(t *testing.T) {
	prg := mustCompile(t, mustEnv(t, true), "call.args.amount <= 1500")
	got, err := evalCELCondition(prg, mcpAct(time.Unix(0, 0).UTC(), "create_payment", nil))
	if err == nil {
		t.Fatal("missing arg: expected eval error (fail-closed deny), got nil")
	}
	if got {
		t.Fatal("missing arg: must not allow")
	}
}

func TestCEL_OptionalArgPasses(t *testing.T) {
	prg := mustCompile(t, mustEnv(t, true), "call.args.?amount.orValue(0.0) <= 1500")
	now := time.Unix(0, 0).UTC()

	got, err := evalCELCondition(prg, mcpAct(now, "create_payment", nil))
	if err != nil || !got {
		t.Fatalf("absent optional: got=%v err=%v, want true", got, err)
	}
	got, err = evalCELCondition(prg, mcpAct(now, "create_payment", map[string]logical.ParamValue{"amount": num("2000")}))
	if err != nil || got {
		t.Fatalf("present-and-over: got=%v err=%v, want false", got, err)
	}
}

func TestCEL_StringVsNumericFailsClosed(t *testing.T) {
	// A string argument against a numeric comparison must NOT silently match;
	// it surfaces as a runtime error → deny.
	prg := mustCompile(t, mustEnv(t, true), "call.args.amount <= 1500")
	got, err := evalCELCondition(prg, mcpAct(time.Unix(0, 0).UTC(), "create_payment", map[string]logical.ParamValue{"amount": str("2000")}))
	if err == nil {
		t.Fatal("string vs numeric: expected eval error, got nil")
	}
	if got {
		t.Fatal("string vs numeric: must not allow")
	}
}

func TestCEL_TokenMetadataSet(t *testing.T) {
	prg := mustCompile(t, mustEnv(t, false), "token.metadata.env in ['dev', 'staging']")
	now := time.Unix(0, 0).UTC()

	got, err := evalCELCondition(prg, baseAct(celRequestInput{}, celTokenInput{Metadata: map[string]string{"env": "dev"}}, now))
	if err != nil || !got {
		t.Fatalf("env=dev: got=%v err=%v, want true", got, err)
	}
	got, err = evalCELCondition(prg, baseAct(celRequestInput{}, celTokenInput{Metadata: map[string]string{"env": "prod"}}, now))
	if err != nil || got {
		t.Fatalf("env=prod: got=%v err=%v, want false", got, err)
	}
	// Absent key fails closed (matches the old token_metadata semantics).
	if _, err := evalCELCondition(prg, baseAct(celRequestInput{}, celTokenInput{}, now)); err == nil {
		t.Fatal("absent metadata key: expected eval error (fail-closed)")
	}
}

func TestCEL_PoliciesMembership(t *testing.T) {
	prg := mustCompile(t, mustEnv(t, false), "'admin' in token.policies")
	now := time.Unix(0, 0).UTC()

	got, err := evalCELCondition(prg, baseAct(celRequestInput{}, celTokenInput{Policies: []string{"admin", "reader"}}, now))
	if err != nil || !got {
		t.Fatalf("admin present: got=%v err=%v, want true", got, err)
	}
	got, err = evalCELCondition(prg, baseAct(celRequestInput{}, celTokenInput{Policies: []string{"reader"}}, now))
	if err != nil || got {
		t.Fatalf("admin absent: got=%v err=%v, want false", got, err)
	}
}

func TestCEL_CIDRContains(t *testing.T) {
	prg := mustCompile(t, mustEnv(t, false), "cidrContains('10.0.0.0/8', request.client_ip)")
	now := time.Unix(0, 0).UTC()

	got, err := evalCELCondition(prg, baseAct(celRequestInput{ClientIP: "10.1.2.3"}, celTokenInput{}, now))
	if err != nil || !got {
		t.Fatalf("in-range: got=%v err=%v, want true", got, err)
	}
	got, err = evalCELCondition(prg, baseAct(celRequestInput{ClientIP: "192.168.1.1"}, celTokenInput{}, now))
	if err != nil || got {
		t.Fatalf("out-of-range: got=%v err=%v, want false", got, err)
	}
	// A malformed client IP yields an error (fail-closed).
	if _, err := evalCELCondition(prg, baseAct(celRequestInput{ClientIP: "not-an-ip"}, celTokenInput{}, now)); err == nil {
		t.Fatal("invalid ip: expected eval error")
	}
}

func TestCEL_TimeFunctions(t *testing.T) {
	prg := mustCompile(t, mustEnv(t, false), `now.getHours("UTC") >= 8 && now.getHours("UTC") < 18`)

	inHours := time.Date(2026, 6, 30, 9, 0, 0, 0, time.UTC)
	got, err := evalCELCondition(prg, baseAct(celRequestInput{}, celTokenInput{}, inHours))
	if err != nil || !got {
		t.Fatalf("09:00 UTC: got=%v err=%v, want true", got, err)
	}
	outHours := time.Date(2026, 6, 30, 22, 0, 0, 0, time.UTC)
	got, err = evalCELCondition(prg, baseAct(celRequestInput{}, celTokenInput{}, outHours))
	if err != nil || got {
		t.Fatalf("22:00 UTC: got=%v err=%v, want false", got, err)
	}
}

func TestCEL_RequestMountFields(t *testing.T) {
	prg := mustCompile(t, mustEnv(t, false), `request.mount_type == "aws" && request.transparent`)
	now := time.Unix(0, 0).UTC()

	got, err := evalCELCondition(prg, baseAct(celRequestInput{MountType: "aws", Transparent: true}, celTokenInput{}, now))
	if err != nil || !got {
		t.Fatalf("aws+transparent: got=%v err=%v, want true", got, err)
	}
	got, err = evalCELCondition(prg, baseAct(celRequestInput{MountType: "vault", Transparent: true}, celTokenInput{}, now))
	if err != nil || got {
		t.Fatalf("vault: got=%v err=%v, want false", got, err)
	}
}
