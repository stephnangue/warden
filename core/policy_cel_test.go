// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"errors"
	"fmt"
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

// baseAct is a minimal request/agent activation for path-level tests. The user
// leg is absent (Present false), which is the common shape.
func baseAct(req celRequestInput, agt celPrincipalInput, now time.Time) map[string]any {
	return buildBaseActivation(req, agt, celPrincipalInput{}, now)
}

// userAct is baseAct with both legs occupied.
func userAct(req celRequestInput, agt, usr celPrincipalInput, now time.Time) map[string]any {
	return buildBaseActivation(req, agt, usr, now)
}

// mcpAct is a base activation plus a single call namespace.
func mcpAct(now time.Time, tool string, args map[string]logical.ParamValue) map[string]any {
	base := buildBaseActivation(celRequestInput{Path: "mcp/x", Operation: "update"}, celPrincipalInput{}, celPrincipalInput{}, now)
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
	act := buildBaseActivation(celRequestInput{Data: bigStringKeyMap(500)}, celPrincipalInput{}, celPrincipalInput{}, now)
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
		buildBaseActivation(celRequestInput{Data: bigStringKeyMap(500)}, celPrincipalInput{}, celPrincipalInput{}, now))
	mustErrKind("cost limit", err, "cost_exceeded")

	// eval_error — any error outside the known categories maps to the catch-all.
	if got := celErrorKind(errors.New("unexpected internal failure")); got != "eval_error" {
		t.Fatalf("generic error: kind=%q want eval_error", got)
	}
}

// TestCEL_ActorVerifiedKeyDenies locks in the breaking change: the actor object
// no longer carries a `verified` field (all actors are verified), so a policy
// still referencing a.verified errors at evaluation (no_such_key) and fails
// closed — a deny — rather than silently passing. The new-shape a.subject works.
func TestCEL_ActorVerifiedKeyDenies(t *testing.T) {
	base := mustEnv(t, false)
	now := time.Unix(0, 0).UTC()
	act := baseAct(celRequestInput{}, celPrincipalInput{Actors: []logical.ActorRef{{Subject: "agent"}}}, now)

	_, err := evalCELCondition(mustCompile(t, base, "agent.actors.all(a, a.verified)"), act)
	if err == nil {
		t.Fatal("referencing the removed a.verified key must error at eval, not pass")
	}
	if got := celErrorKind(err); got != "no_such_key" {
		t.Fatalf("kind=%q want no_such_key (err: %v)", got, err)
	}

	// The surviving field still evaluates cleanly.
	got, err := evalCELCondition(mustCompile(t, base, "agent.actors.all(a, a.subject != '')"), act)
	if err != nil || !got {
		t.Fatalf("a.subject must evaluate true: got=%v err=%v", got, err)
	}
}

// TestCEL_ReferencedPaths locks in the dotted request/agent/call paths captured
// for audit Inputs: clean field-selection chains are captured; has(),
// index/optional access, and now.* are not.
func TestCEL_ReferencedPaths(t *testing.T) {
	cases := []struct {
		name string
		mcp  bool
		src  string
		want []string
	}{
		{"agent+call scalars", true,
			"agent.metadata.env == 'prod' && call.args.amount <= 1500",
			[]string{"agent.metadata.env", "call.args.amount"}},
		{"has and index and optional contribute nothing", true,
			`has(request.data.x) && request.data["k"] == "v" && call.args.?y.orValue(0) <= 3`,
			nil},
		{"nested token + list arg", false,
			"agent.principal == 'a' && size(agent.policies) > 0",
			[]string{"agent.policies", "agent.principal"}},
		{"now not captured", false,
			`now.getHours("UTC") < 18 && agent.metadata.env == "prod"`,
			[]string{"agent.metadata.env"}},
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
		req, agt, cal  map[string]bool
		reqAll, agtAll bool
	}{
		{name: "scalar select", src: "agent.metadata.env == 'prod'", agt: fs("metadata")},
		{name: "has()", src: "has(request.data.x)", req: fs("data")},
		{name: "index", src: `request.data["k"] == "v"`, req: fs("data")},
		{name: "optional", mcp: true, src: "call.args.?amount.orValue(0) <= 3", cal: fs("args")},
		{name: "comprehension", src: "size(agent.actors) > 0 && agent.actors.all(a, a.subject != '')", agt: fs("actors")},
		{name: "multi-field", src: "request.data.x <= 1 && request.namespace == agent.namespace", req: fs("data", "namespace"), agt: fs("namespace")},
		{name: "bare root -> all", src: "size(agent) > 0 || agent.metadata.env == 'x'", agt: fs("metadata"), agtAll: true},
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
			check("agent", c.AgtFields, tc.agtAll, tc.agt)
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
	prg := mustCompile(t, mustEnv(t, false), "agent.metadata.env in ['dev', 'staging']")
	now := time.Unix(0, 0).UTC()

	got, err := evalCELCondition(prg, baseAct(celRequestInput{}, celPrincipalInput{Metadata: map[string]string{"env": "dev"}}, now))
	if err != nil || !got {
		t.Fatalf("env=dev: got=%v err=%v, want true", got, err)
	}
	got, err = evalCELCondition(prg, baseAct(celRequestInput{}, celPrincipalInput{Metadata: map[string]string{"env": "prod"}}, now))
	if err != nil || got {
		t.Fatalf("env=prod: got=%v err=%v, want false", got, err)
	}
	// Absent key fails closed (matches the old token_metadata semantics).
	if _, err := evalCELCondition(prg, baseAct(celRequestInput{}, celPrincipalInput{}, now)); err == nil {
		t.Fatal("absent metadata key: expected eval error (fail-closed)")
	}
}

func TestCEL_PoliciesMembership(t *testing.T) {
	prg := mustCompile(t, mustEnv(t, false), "'admin' in agent.policies")
	now := time.Unix(0, 0).UTC()

	got, err := evalCELCondition(prg, baseAct(celRequestInput{}, celPrincipalInput{Policies: []string{"admin", "reader"}}, now))
	if err != nil || !got {
		t.Fatalf("admin present: got=%v err=%v, want true", got, err)
	}
	got, err = evalCELCondition(prg, baseAct(celRequestInput{}, celPrincipalInput{Policies: []string{"reader"}}, now))
	if err != nil || got {
		t.Fatalf("admin absent: got=%v err=%v, want false", got, err)
	}
}

func TestCEL_CIDRContains(t *testing.T) {
	prg := mustCompile(t, mustEnv(t, false), "cidrContains('10.0.0.0/8', request.client_ip)")
	now := time.Unix(0, 0).UTC()

	got, err := evalCELCondition(prg, baseAct(celRequestInput{ClientIP: "10.1.2.3"}, celPrincipalInput{}, now))
	if err != nil || !got {
		t.Fatalf("in-range: got=%v err=%v, want true", got, err)
	}
	got, err = evalCELCondition(prg, baseAct(celRequestInput{ClientIP: "192.168.1.1"}, celPrincipalInput{}, now))
	if err != nil || got {
		t.Fatalf("out-of-range: got=%v err=%v, want false", got, err)
	}
	// A malformed client IP yields an error (fail-closed).
	if _, err := evalCELCondition(prg, baseAct(celRequestInput{ClientIP: "not-an-ip"}, celPrincipalInput{}, now)); err == nil {
		t.Fatal("invalid ip: expected eval error")
	}
}

func TestCEL_TimeFunctions(t *testing.T) {
	prg := mustCompile(t, mustEnv(t, false), `now.getHours("UTC") >= 8 && now.getHours("UTC") < 18`)

	inHours := time.Date(2026, 6, 30, 9, 0, 0, 0, time.UTC)
	got, err := evalCELCondition(prg, baseAct(celRequestInput{}, celPrincipalInput{}, inHours))
	if err != nil || !got {
		t.Fatalf("09:00 UTC: got=%v err=%v, want true", got, err)
	}
	outHours := time.Date(2026, 6, 30, 22, 0, 0, 0, time.UTC)
	got, err = evalCELCondition(prg, baseAct(celRequestInput{}, celPrincipalInput{}, outHours))
	if err != nil || got {
		t.Fatalf("22:00 UTC: got=%v err=%v, want false", got, err)
	}
}

func TestCEL_RequestMountFields(t *testing.T) {
	prg := mustCompile(t, mustEnv(t, false), `request.mount_type == "aws" && request.transparent`)
	now := time.Unix(0, 0).UTC()

	got, err := evalCELCondition(prg, baseAct(celRequestInput{MountType: "aws", Transparent: true}, celPrincipalInput{}, now))
	if err != nil || !got {
		t.Fatalf("aws+transparent: got=%v err=%v, want true", got, err)
	}
	got, err = evalCELCondition(prg, baseAct(celRequestInput{MountType: "vault", Transparent: true}, celPrincipalInput{}, now))
	if err != nil || got {
		t.Fatalf("vault: got=%v err=%v, want false", got, err)
	}
}

// TestCEL_TokenNamespaceRemoved pins the hard cut. `token` is no longer a
// declared namespace, so every stored condition using it fails to compile —
// which, because policies are re-parsed on load, is what makes the upgrade
// breaking. The error must name the replacement: an operator meets it at policy
// load with no other signal about what changed.
func TestCEL_TokenNamespaceRemoved(t *testing.T) {
	for _, src := range []string{
		"token.metadata.env == 'prod'",
		"token.principal == 'x'",
		"size(token.actors) > 0",
		"token.type == 'jwt_role'",
		"size(token) > 0",
	} {
		t.Run(src, func(t *testing.T) {
			_, err := compileCELCondition(mustEnv(t, false), src)
			if err == nil {
				t.Fatalf("compile %q: want error, got none", src)
			}
			if !strings.Contains(err.Error(), "renamed to `agent`") {
				t.Errorf("compile %q: error does not name the rename: %v", src, err)
			}
		})
	}
}

// TestCEL_AgentFieldNames pins the field set exactly. The three token_-prefixed
// names are the half-rename an implementer is most likely to leave behind, and
// a stale name is not a compile error — `agent` is a dyn map, so it resolves to
// a runtime no-such-key and a fail-closed deny that reads as a policy decision
// rather than a bug.
func TestCEL_AgentFieldNames(t *testing.T) {
	now := time.Unix(1_757_404_800, 0)
	agt := celPrincipalInput{
		Principal:     "agent-gateway",
		Role:          "gw",
		Type:          "cert_role",
		NamespacePath: "team-a/",
		Policies:      []string{"p"},
		Metadata:      map[string]string{"team": "platform"},
		Actors:        []logical.ActorRef{{Subject: "broker"}},
		TTLSeconds:    60,
		ExpiresAtUnix: now.Add(time.Minute).Unix(),
	}
	// all:true deliberately: this asserts the builder's key set in isolation.
	// It cannot catch a fieldSet-key/map-key disagreement, because has() short
	// -circuits on all — TestCBP_PathCondition_RenamedFields drives the pruned
	// path for that.
	ns := buildPrincipalNS(agt, fieldSet{all: true}, legAgent)

	for _, k := range []string{
		"principal", "role", "namespace", "policies", "metadata", "actors",
		"token_type", "token_ttl_seconds", "token_expires_at",
	} {
		if _, ok := ns[k]; !ok {
			t.Errorf("agent.%s missing", k)
		}
	}
	// The pre-rename spellings must be gone, not merely aliased.
	for _, k := range []string{"type", "ttl_seconds", "expires_at"} {
		if _, ok := ns[k]; ok {
			t.Errorf("agent.%s still built — half-rename", k)
		}
	}
	// Assert values, not just presence: the two time fields are adjacent
	// int64s, so a builder that swapped them would pass a presence-only check.
	if got := ns["token_type"]; got != "cert_role" {
		t.Errorf("agent.token_type = %v, want cert_role", got)
	}
	if got := ns["token_ttl_seconds"]; got != int64(60) {
		t.Errorf("agent.token_ttl_seconds = %v, want 60", got)
	}
	if got := ns["token_expires_at"]; got != now.Add(time.Minute).Unix() {
		t.Errorf("agent.token_expires_at = %v, want %v", got, now.Add(time.Minute).Unix())
	}
}

// TestCEL_UserNamespace covers the user leg's field set: what it exposes, what
// it deliberately does not, and how absence reads.
func TestCEL_UserNamespace(t *testing.T) {
	base := mustEnv(t, false)
	now := time.Unix(1_757_404_800, 0)
	agt := celPrincipalInput{
		Present: true, Principal: "agent-gateway", Type: "cert_role",
		Policies: []string{"vault-gw-bound"},
		Metadata: map[string]string{"team": "platform"},
	}
	usr := celPrincipalInput{
		Present: true, Principal: "user-8f21c3", Role: "human", Type: "jwt_role",
		Policies: []string{"should-never-surface"},
		Metadata: map[string]string{"team": "platform"},
	}

	t.Run("fields resolve and mirror the agent leg", func(t *testing.T) {
		act := userAct(celRequestInput{}, agt, usr, now)
		for _, src := range []string{
			"user.present == true",
			"user.principal == 'user-8f21c3'",
			"user.role == 'human'",
			"user.token_type == 'jwt_role'",
			"user.metadata.team == agent.metadata.team",
		} {
			ok, err := evalCELCondition(mustCompile(t, base, src), act)
			if err != nil || !ok {
				t.Errorf("%q: ok=%v err=%v", src, ok, err)
			}
		}
	})

	// The user never authorizes, so exposing its policy list would invite
	// `"admin" in user.policies` — a condition that reads like an authorization
	// check and is not one. Suppression is at the builder, so it holds even
	// under all:true.
	t.Run("policies suppressed on the user leg only", func(t *testing.T) {
		if _, ok := buildPrincipalNS(usr, fieldSet{all: true}, legUser)["policies"]; ok {
			t.Error("user.policies must not be built")
		}
		if _, ok := buildPrincipalNS(agt, fieldSet{all: true}, legAgent)["policies"]; !ok {
			t.Error("agent.policies must still be built")
		}
		// It is a runtime no-such-key deny, not a compile error: `user` is a
		// dyn map, so the checker cannot reject the field.
		act := userAct(celRequestInput{}, agt, usr, now)
		ok, err := evalCELCondition(mustCompile(t, base, "'admin' in user.policies"), act)
		if ok {
			t.Error("user.policies must not evaluate true")
		}
		if got := celErrorKind(err); got != "no_such_key" {
			t.Errorf("error kind = %q, want no_such_key (err: %v)", got, err)
		}
	})

	// The user's raw credential is a bearer secret. celPrincipalInput has no
	// field to carry it, so today this is structural — the assertion exists to
	// fail loudly if someone ever adds one and wires it into the namespace.
	t.Run("raw user credential cannot reach the namespace", func(t *testing.T) {
		const secret = "eyJ.super.secret"
		in := celUserInputFromPrincipal(&logical.UserPrincipal{
			TokenEntry: &logical.TokenEntry{
				PrincipalID: "user-8f21c3",
				Metadata:    map[string]string{"team": "platform"},
			},
			RawToken: secret,
		}, now)
		for k, v := range buildPrincipalNS(in, fieldSet{all: true}, legUser) {
			if strings.Contains(fmt.Sprint(v), secret) {
				t.Errorf("raw user credential surfaced at user.%s", k)
			}
		}
	})

	t.Run("absent user leg is present=false, not an error", func(t *testing.T) {
		act := baseAct(celRequestInput{}, agt, now) // user leg empty
		ok, err := evalCELCondition(mustCompile(t, base, "user.present == true"), act)
		if err != nil {
			t.Fatalf("user.present must resolve even with no user: %v", err)
		}
		if ok {
			t.Error("user.present should be false with no user credential")
		}
		// agent.present is always true wherever a condition evaluates.
		ok, err = evalCELCondition(mustCompile(t, base, "agent.present == true"), act)
		if err != nil || !ok {
			t.Errorf("agent.present: ok=%v err=%v", ok, err)
		}
	})

	// A condition must evaluate to bool, and a dyn-map field types as dyn — so a
	// bare `user.present` is rejected at write time while the guard form that
	// operators actually write compiles, because `_&&_` yields bool. This is
	// pre-existing for every dyn-map boolean (request.transparent behaves the
	// same); pinned here so the guard idiom cannot regress.
	t.Run("guard idiom compiles, bare field does not", func(t *testing.T) {
		if _, err := compileCELCondition(base, "user.present && user.metadata.team == 'platform'"); err != nil {
			t.Errorf("guard idiom must compile: %v", err)
		}
		_, err := compileCELCondition(base, "user.present")
		if err == nil {
			t.Error("a bare dyn field is not a bool condition; expected rejection")
		} else if !strings.Contains(err.Error(), "must evaluate to bool") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("absent metadata key fails closed", func(t *testing.T) {
		act := userAct(celRequestInput{}, agt, usr, now)
		ok, err := evalCELCondition(mustCompile(t, base, "user.metadata.nope == 'x'"), act)
		if ok {
			t.Error("absent metadata key must not allow")
		}
		if got := celErrorKind(err); got != "no_such_key" {
			t.Errorf("error kind = %q, want no_such_key", got)
		}
	})
}

// TestCEL_UserCostEstimated proves `user` is wired into celCostEstimator.
//
// The discriminating assertion is the ACCEPTANCE one. A root missing from
// EstimateSize gets no size from us and cel-go falls back to
// UnknownSizeEstimate (MaxUint64), so a single comprehension over user.metadata
// would estimate as infinite and be rejected at write time. Asserting that a
// pathological expression is rejected proves nothing — that happens either way.
func TestCEL_UserCostEstimated(t *testing.T) {
	env := mustEnv(t, false)

	// Fails iff `user` is dropped from EstimateSize.
	if _, err := compileCELCondition(env, "user.metadata.exists(k, k == 'team')"); err != nil {
		t.Fatalf("a single comprehension over user.metadata must compile: %v", err)
	}

	// The budget still bites for genuinely pathological input.
	_, err := compileCELCondition(env, "user.metadata.all(k, user.metadata.all(j, k == j))")
	if err == nil {
		t.Fatal("nested comprehension over user.metadata should be rejected at write time")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("expected a cost-limit error, got: %v", err)
	}
}
