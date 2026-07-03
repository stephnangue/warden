// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"reflect"
	"testing"
	"time"

	"github.com/google/cel-go/cel"

	"github.com/stephnangue/warden/logical"
)

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
	prg, _, err := compileCELCondition(env, src)
	if err != nil {
		t.Fatalf("compile %q: %v", src, err)
	}
	return prg
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
	if _, _, err := compileCELCondition(mustEnv(t, false), "call.args.amount <= 1500"); err == nil {
		t.Fatal("expected compile error for call.* in path-level env, got nil")
	}
	// The MCP env accepts the same expression.
	mustCompile(t, mustEnv(t, true), "call.args.amount <= 1500")
}

func TestCEL_NonBoolRejected(t *testing.T) {
	if _, _, err := compileCELCondition(mustEnv(t, false), "1 + 1"); err == nil {
		t.Fatal("expected rejection of non-bool condition")
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
			_, paths, err := compileCELCondition(mustEnv(t, tc.mcp), tc.src)
			if err != nil {
				t.Fatalf("compile %q: %v", tc.src, err)
			}
			if !reflect.DeepEqual(paths, tc.want) {
				t.Fatalf("paths = %v, want %v", paths, tc.want)
			}
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
