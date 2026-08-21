//go:build e2e

package fullchain

import (
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// A credential carries api_key plus whatever its source declares in
// credential_fields. Everything here is about the boundary of that declaration:
// what an operator can put in it, and what happens to a field nobody declared.
//
// The rows drive the public API rather than the parser, because the interesting
// question is not whether the parser filters correctly — unit tests settle that,
// including a declaration forged into a fetched secret payload — but whether an
// operator can reach a state where a credential is quietly missing a field. The
// symptom of that is a provider taking its fallback branch, which from outside
// looks exactly like a working mount.

// TestCarriage_ReservedNameIsRejectedOnTheSource: a source cannot declare a mint
// locator as a credential field.
//
// A typo guard rather than a security boundary — nothing travels unless an
// operator writes its name down — but a locator copied into credential data would
// be sent upstream by whichever provider reads that field name, so it is refused
// where it is written instead of skipped silently at mint.
func TestCarriage_ReservedNameIsRejectedOnTheSource(t *testing.T) {
	ensureEnv(t)

	const name = "fc-carriage-reserved-src"
	t.Cleanup(func() { h.APIRequest(t, "DELETE", "sys/cred/sources/"+name, leaderPort, "") })

	for _, field := range []string{"secret_path", "mint_method", "secret_spec", "__adjunct_fields"} {
		status, body := h.APIRequest(t, "POST", "sys/cred/sources/"+name, leaderPort,
			`{"type":"apikey","config":{"credential_fields":"`+field+`"}}`)
		if status < 400 || status >= 500 {
			t.Errorf("declaring %q as a credential field: got status %d, want a 4xx (body: %s)", field, status, body)
			h.APIRequest(t, "DELETE", "sys/cred/sources/"+name, leaderPort, "")
		}
	}
}

// TestCarriage_UndeclaredAdjunctIsRejectedOnTheSpec is the guard that makes the
// declaration discoverable, and the round trip that shows the error is actionable:
// reject, follow the advice, accept.
func TestCarriage_UndeclaredAdjunctIsRejectedOnTheSpec(t *testing.T) {
	ensureEnv(t)

	const (
		srcName  = "fc-carriage-undeclared-src"
		specName = "fc-carriage-undeclared-spec"
	)
	t.Cleanup(func() {
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+specName, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+srcName, leaderPort, "")
	})

	mustWrite := func(method, path, body, what string) {
		t.Helper()
		switch status, resp := h.APIRequest(t, method, path, leaderPort, body); status {
		case 200, 201, 204:
		default:
			t.Fatalf("%s (status %d): %s", what, status, resp)
		}
	}

	// An apikey source declaring nothing.
	mustWrite("POST", "sys/cred/sources/"+srcName, `{"type":"apikey"}`, "create source")

	specBody := `{"type":"api_key","source":"` + srcName + `","config":{"api_key":"k","organization_id":"org-1"}}`
	status, body := h.APIRequest(t, "POST", "sys/cred/specs/"+specName, leaderPort, specBody)
	if status < 400 || status >= 500 {
		t.Fatalf("spec with an uncarried credential field: got status %d, want a 4xx (body: %s)", status, body)
	}

	// Following the advice makes the same spec valid.
	mustWrite("PUT", "sys/cred/sources/"+srcName,
		`{"config":{"credential_fields":"organization_id"}}`, "declare organization_id on the source")
	mustWrite("POST", "sys/cred/specs/"+specName, specBody, "spec with a declared credential field")
}

// TestCarriage_NarrowingASourceStrandsNothing closes the way round the spec-level
// guard.
//
// That guard runs when a spec is written. Removing a name from the source's
// credential_fields touches no spec at all, so every spec that set the field would
// quietly start minting without it — the guard's own failure mode, reached through
// the front door. Widening stays free; only a disappearing name can strand anything.
func TestCarriage_NarrowingASourceStrandsNothing(t *testing.T) {
	ensureEnv(t)

	const (
		srcName  = "fc-carriage-narrow-src"
		specName = "fc-carriage-narrow-spec"
	)
	t.Cleanup(func() {
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+specName, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+srcName, leaderPort, "")
	})

	mustWrite := func(method, path, body, what string) {
		t.Helper()
		switch status, resp := h.APIRequest(t, method, path, leaderPort, body); status {
		case 200, 201, 204:
		default:
			t.Fatalf("%s (status %d): %s", what, status, resp)
		}
	}

	mustWrite("POST", "sys/cred/sources/"+srcName,
		`{"type":"apikey","config":{"credential_fields":"organization_id"}}`, "create source")
	mustWrite("POST", "sys/cred/specs/"+specName,
		`{"type":"api_key","source":"`+srcName+`","config":{"api_key":"k","organization_id":"org-1"}}`,
		"create spec")

	// Dropping the declaration the spec depends on.
	status, body := h.APIRequest(t, "PUT", "sys/cred/sources/"+srcName, leaderPort,
		`{"config":{"credential_fields":""}}`)
	if status < 400 || status >= 500 {
		t.Fatalf("narrowing credential_fields under a bound spec: got status %d, want a 4xx (body: %s)", status, body)
	}
	if !strings.Contains(string(body), specName) {
		t.Errorf("the error must name the spec left stranded, got: %s", body)
	}

	// Widening is unaffected.
	mustWrite("PUT", "sys/cred/sources/"+srcName,
		`{"config":{"credential_fields":"organization_id,project_id"}}`, "widen credential_fields")
}

// TestCarriage_NonAPIKeySourceCannotCarryAdjuncts covers the failure the guard
// would otherwise describe wrongly.
//
// Only the apikey driver resolves credential_fields and tells the parser what it
// carried. A local source has no such mechanism, so a credential field set beside
// api_key can never travel — and an error pointing that operator at
// credential_fields would send them to add a key that changes nothing, which is
// the same silent divergence one layer up. The rejection has to name the source
// type, and a declaration on such a source must not satisfy it.
func TestCarriage_NonAPIKeySourceCannotCarryAdjuncts(t *testing.T) {
	ensureEnv(t)

	const (
		srcName  = "fc-carriage-local-src"
		specName = "fc-carriage-local-spec"
	)
	t.Cleanup(func() {
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+specName, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+srcName, leaderPort, "")
	})

	// A local source that declares the field anyway. The declaration is inert
	// here, and the spec must still be refused.
	status, body := h.APIRequest(t, "POST", "sys/cred/sources/"+srcName, leaderPort,
		`{"type":"local","config":{"credential_fields":"organization_id"}}`)
	switch status {
	case 200, 201, 204:
	default:
		t.Fatalf("create local source (status %d): %s", status, body)
	}

	status, body = h.APIRequest(t, "POST", "sys/cred/specs/"+specName, leaderPort,
		`{"type":"api_key","source":"`+srcName+`","config":{"api_key":"k","organization_id":"org-1"}}`)
	if status < 400 || status >= 500 {
		t.Fatalf("local-source spec with a credential field: got status %d, want a 4xx (body: %s)", status, body)
	}
	if !strings.Contains(string(body), "apikey source") {
		t.Errorf("the error must say which source type to use, got: %s", body)
	}

	// The same spec without the field is fine: api_key alone always travels.
	status, body = h.APIRequest(t, "POST", "sys/cred/specs/"+specName, leaderPort,
		`{"type":"api_key","source":"`+srcName+`","config":{"api_key":"k"}}`)
	switch status {
	case 200, 201, 204:
	default:
		t.Fatalf("local-source spec carrying only api_key (status %d): %s", status, body)
	}
}
