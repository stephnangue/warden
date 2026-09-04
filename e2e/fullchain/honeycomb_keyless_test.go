//go:build e2e

package fullchain

import (
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// Keyless honeycomb: the key lives in the vault, is fetched per request as the
// calling agent, and Warden stores none of it.
//
// Honeycomb has no assertion grant to federate against and no short-lived-token
// flow, so keyless here means chaining rather than exchange — an apikey source
// naming a spec that yields the key. There is no honeycomb source driver to do it
// any other way: the one that minted keys through the V2 key management API was
// removed, because the keys it minted carried no expiry and, chained, could never
// have been revoked.
//
// What only a full chain can show is the join. The mount's own rows next door in
// honeycomb_test.go prove the extractor against a spec that carries the key
// inline; these prove the same two branches when the key arrives from a Vault
// read over federation, through MintFromSecret, through the declaration that
// decides which fields survive Parse. Each layer is correct alone in its unit
// tests; a provider reading a credential field nothing can supply is what happens
// when they are wrong together.
//
// The mode selector is the interesting part. key_id does not add a header, it
// changes which header is sent — so one source serves both branches here, and the
// only thing choosing between them is whether the Vault payload has a key_id in
// it. A declaration that carried key_id when the payload had none would silently
// switch an ingest mount to management mode.

const (
	// Written to secret/data/e2e/honeycomb-* by setup.sh. None of these values
	// appears in any spec config, so an assertion on one can only pass if the
	// whole chain ran.
	honeycombVaultIngestKey = "hcxik_e2e-honeycomb-not-a-real-ingest-key"
	honeycombVaultKeySecret = "e2e-honeycomb-not-a-real-key-secret"
	honeycombVaultKeyID     = "hcxmk_e2e-key-id"
	honeycombVaultOddKey    = "hcxik_e2e-honeycomb-odd-not-a-real-key"

	// The companion field of the odd-named secret. It is in the payload the
	// driver is handed and must reach no header, whatever its name.
	honeycombVaultUnvendable = "must-not-be-vended"

	// Test-local, the source included, for the reason credential_chaining_test.go
	// gives at length: a killed run skips t.Cleanup, and a spec left hanging off
	// a shared source would block that source from being deleted, failing the
	// next run's setup before it reaches the cleanup that would have cleared it.
	honeycombIngestSecretSpec = "fc-hc-ingest-from-vault"
	honeycombMgmtSecretSpec   = "fc-hc-mgmt-from-vault"
	honeycombOddSecretSpec    = "fc-hc-odd-from-vault"

	// One source for every branch. It declares key_id, which is what lets a
	// management payload reach the mount whole — and, on the ingest payload that
	// has no key_id, carries nothing.
	honeycombKeylessSource = "fc-hc-keyless-src"

	honeycombIngestSpec   = "fc-hc-keyless-ingest"
	honeycombMgmtSpec     = "fc-hc-keyless-mgmt"
	honeycombOddSpec      = "fc-hc-keyless-odd"
	honeycombBadFieldSpec = "fc-hc-keyless-badfield"

	// The spec that must never exist: a chain and an inline key at once.
	honeycombBothSpec = "fc-hc-keyless-both"

	honeycombIngestRole   = "fc-hc-keyless-ingest-agent"
	honeycombMgmtRole     = "fc-hc-keyless-mgmt-agent"
	honeycombOddRole      = "fc-hc-keyless-odd-agent"
	honeycombBadFieldRole = "fc-hc-keyless-badfield-agent"
)

func honeycombMustWrite(t *testing.T, method, path, body, what string) {
	t.Helper()
	switch status, resp := h.APIRequest(t, method, path, leaderPort, body); status {
	case 200, 201, 204:
	default:
		t.Fatalf("%s (status %d): %s", what, status, resp)
	}
}

// setupHoneycombKeyless stands up every chain this file drives: one source
// holding no key, three referenced specs over the three Vault payloads, the specs
// that consume them, and a role each.
//
// All of it is rebuilt per subject because the referenced spec's own source
// differs between them — agent_identity federates the agent's inbound JWT,
// warden_identity an assertion Warden signs.
func setupHoneycombKeyless(t *testing.T, subj scalewaySubject) {
	t.Helper()

	// The referenced spec is minted as the calling agent, and both subjects derive
	// that agent from an inbound JWT. This mount's default agent leg is a client
	// certificate, which carries neither.
	useJWTAgentLeg(t, honeycombEnv)

	// Consumers first, then what they reference: a referenced spec cannot be
	// deleted while a consumer still names it. Run before the creates too, so a
	// killed run's leftovers cannot 409 them.
	clear := func() {
		for _, role := range []string{honeycombIngestRole, honeycombMgmtRole, honeycombOddRole, honeycombBadFieldRole} {
			h.APIRequest(t, "DELETE", "auth/jwt/role/"+role, leaderPort, "")
		}
		// honeycombBothSpec is only ever created by a regression — the write that
		// makes it is supposed to be refused. Cleared anyway: if it ever does get
		// written and the run is killed before its own cleanup, it holds a
		// reference to a spec below and blocks that deletion, which is the 409
		// cascade the naming scheme above is meant to rule out.
		for _, spec := range []string{honeycombIngestSpec, honeycombMgmtSpec, honeycombOddSpec, honeycombBadFieldSpec, honeycombBothSpec} {
			h.APIRequest(t, "DELETE", "sys/cred/specs/"+spec, leaderPort, "")
		}
		for _, spec := range []string{honeycombIngestSecretSpec, honeycombMgmtSecretSpec, honeycombOddSecretSpec} {
			h.APIRequest(t, "DELETE", "sys/cred/specs/"+spec, leaderPort, "")
		}
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+honeycombKeylessSource, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	referenced := []struct {
		name string
		path string
	}{
		{honeycombIngestSecretSpec, "e2e/honeycomb-ingest-key"},
		{honeycombMgmtSecretSpec, "e2e/honeycomb-mgmt-key"},
		{honeycombOddSecretSpec, "e2e/honeycomb-odd-key"},
	}
	for _, ref := range referenced {
		honeycombMustWrite(t, "POST", "sys/cred/specs/"+ref.name, `{
			"type":"key_value","source":"`+subj.source+`","config":{
				"mint_method":"kv2_read","kv2_mount":"secret","secret_path":"`+ref.path+`",
				"subject_token_source":"`+subj.name+`"}}`,
			"create the referenced secret spec "+ref.name)
	}

	// No api_key anywhere on this source — an apikey source keeps the key on its
	// specs, and each of those names a chain instead of holding one.
	// credential_fields is the whole management-mode story: the driver carries
	// api_key plus the fields named here, and nothing else from the payload.
	honeycombMustWrite(t, "POST", "sys/cred/sources/"+honeycombKeylessSource,
		`{"type":"apikey","config":{"display_name":"Honeycomb","credential_fields":"key_id"}}`,
		"create the keyless honeycomb source")

	consuming := []struct {
		name  string
		ref   string
		field string
		what  string
	}{
		// secret_field is explicit on both key-shaped payloads. The fallback
		// would find api_key by name anyway, but a row should not lean on a
		// fallback to choose which secret it spends.
		{honeycombIngestSpec, honeycombIngestSecretSpec, "api_key", "the ingest spec"},
		{honeycombMgmtSpec, honeycombMgmtSecretSpec, "api_key", "the management spec"},
		// The odd payload holds the key under a name no driver looks for, so
		// naming it is the only way to reach it.
		{honeycombOddSpec, honeycombOddSecretSpec, "hc_key", "the renamed-secret spec"},
		// A field naming nothing, over the payload whose key sits under the
		// conventional name. The pairing is the whole point: the fallback this
		// row exists to pin reads api_key and nothing else, so aiming it at a
		// payload without one would leave the guard untestable — the mint would
		// fail for want of anything to fall back TO, guard or no guard.
		{honeycombBadFieldSpec, honeycombIngestSecretSpec, "no_such_field", "the misnamed-secret spec"},
	}
	for _, c := range consuming {
		honeycombMustWrite(t, "POST", "sys/cred/specs/"+c.name, `{
			"type":"api_key","source":"`+honeycombKeylessSource+`","config":{
				"secret_spec":"`+c.ref+`","secret_field":"`+c.field+`"}}`,
			"create "+c.what)
	}

	roles := map[string]string{
		honeycombIngestRole:   honeycombIngestSpec,
		honeycombMgmtRole:     honeycombMgmtSpec,
		honeycombOddRole:      honeycombOddSpec,
		honeycombBadFieldRole: honeycombBadFieldSpec,
	}
	for role, spec := range roles {
		honeycombMustWrite(t, "POST", "auth/jwt/role/"+role, `{
			"token_policies":["`+honeycombEnv.Policy()+`"],"cred_spec_name":"`+spec+`",
			"user_claim":"sub","token_ttl":3600}`,
			"create the agent role for "+spec)
	}
}

// TestHoneycombKeyless_ModeFollowsTheVaultPayload is the feature in one row: the
// spec stores no key, the referenced spec yields one from the vault, and the
// header the mount injects is the one that key's shape calls for.
//
// Each branch asserts the other's header absent, which is where the value is. An
// extractor emitting both would satisfy an injection-only assertion while sending
// an ingest key to an endpoint that must never receive it.
func TestHoneycombKeyless_ModeFollowsTheVaultPayload(t *testing.T) {
	ensureEnv(t)

	for _, subj := range scalewaySubjects {
		t.Run(subj.name, func(t *testing.T) {
			setupHoneycombKeyless(t, subj)

			for _, tc := range []struct {
				name   string
				role   string
				want   map[string]string
				absent []string
			}{
				{
					name:   "ingest, the payload carries no key_id",
					role:   honeycombIngestRole,
					want:   map[string]string{"X-Honeycomb-Team": honeycombVaultIngestKey},
					absent: []string{"Authorization"},
				},
				{
					name: "management, key_id rides beside the secret",
					role: honeycombMgmtRole,
					want: map[string]string{
						"Authorization": "Bearer " + honeycombVaultKeyID + ":" + honeycombVaultKeySecret,
					},
					absent: []string{"X-Honeycomb-Team"},
				},
			} {
				t.Run(tc.name, func(t *testing.T) {
					upstream.Reset()

					status, body, _ := h.ChainRequest(t, leaderPort, honeycombEnv, h.ChainOpts{
						AgentToken: h.GetDefaultJWT(t),
						Bearer:     h.FullChainUserJWT(t),
						Role:       tc.role,
						Path:       h.ProbePath("honeycomb-keyless"),
					})

					h.AssertChain(t, upstream, status, body, h.ChainWant{
						Status:        200,
						Injected:      tc.want,
						Absent:        h.AlwaysAbsent(tc.absent...),
						UpstreamCalls: 1,
					})
				})
			}
		})
	}
}

// There is deliberately no keyless twin of
// TestHoneycomb_ClientSuppliedTeamHeaderIsStripped next door. The strip is one
// unconditional loop over the spec's ExtraHeadersToRemove in prepareHeaders,
// with no branch anywhere near it on where the credential came from — so a row
// here could not fail unless the inline one failed identically, and a row that
// can only fail in company with another is coverage in name only.
//
// TestHoneycombKeyless_SecretFieldNamesTheKeyAndNothingElse drives a payload
// whose key sits under a name no driver looks for, which is how a vault holds one
// filed by whoever put it there rather than by Warden's conventions.
//
// The companion field is the point of the second half: it is in the material the
// driver is handed, and the source declares only key_id, so it must reach no
// header at all. A driver that passed the payload through wholesale would leak
// every unrelated secret filed beside the one being spent.
func TestHoneycombKeyless_SecretFieldNamesTheKeyAndNothingElse(t *testing.T) {
	ensureEnv(t)
	setupHoneycombKeyless(t, scalewaySubjects[0])
	upstream.Reset()

	status, body, _ := h.ChainRequest(t, leaderPort, honeycombEnv, h.ChainOpts{
		AgentToken: h.GetDefaultJWT(t),
		Bearer:     h.FullChainUserJWT(t),
		Role:       honeycombOddRole,
		Path:       h.ProbePath("honeycomb-keyless-renamed"),
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"X-Honeycomb-Team": honeycombVaultOddKey},
		Absent:        h.AlwaysAbsent("Authorization"),
		UpstreamCalls: 1,
	})

	// By value, not by header name: a leak of this field would arrive under a
	// name no assertion thought to list.
	for _, req := range upstream.Requests() {
		for name, values := range req.Header {
			for _, v := range values {
				if strings.Contains(v, honeycombVaultUnvendable) {
					t.Errorf("header %s carried the undeclared companion field: %q", name, v)
				}
			}
		}
	}
}

// TestHoneycombKeyless_UnresolvedSecretFieldIsRefusedBeforeTheUpstream pins that
// a secret_field naming nothing in the payload fails the mint rather than falling
// back to some other value in it.
//
// Discriminating because of what the payload holds: hc_key is right there, and a
// resolver that fell back after a field resolved to nothing would authenticate
// with it and this row would go green while secret_field silently meant nothing.
// Nothing may reach the upstream either — there was no credential to inject, and
// forwarding an uncredentialed request would put the caller's own headers in
// front of Honeycomb under the mount's identity.
func TestHoneycombKeyless_UnresolvedSecretFieldIsRefusedBeforeTheUpstream(t *testing.T) {
	ensureEnv(t)
	setupHoneycombKeyless(t, scalewaySubjects[0])
	upstream.Reset()

	status, body, _ := h.ChainRequest(t, leaderPort, honeycombEnv, h.ChainOpts{
		AgentToken: h.GetDefaultJWT(t),
		Bearer:     h.FullChainUserJWT(t),
		Role:       honeycombBadFieldRole,
		Path:       h.ProbePath("honeycomb-keyless-badfield"),
	})

	if status == 200 {
		t.Fatalf("the request succeeded on material the field names nothing in: %s", string(body))
	}
	// Both halves are checked because either alone is weak: the reason without
	// the field name would pass for a different misconfiguration, and the field
	// name without the reason would pass for a failure that merely mentioned it.
	// Matched apart rather than as one phrase — the field is quoted with %q and
	// the body is JSON, so the quotes around it arrive escaped.
	//
	// This driver reports an unresolved field in its own words rather than
	// wrapping credential.ErrChainedSecretIncomplete the way elastic, grafana and
	// ovh do, so the sentinel's text is not what arrives here.
	for _, want := range []string{"no_such_field", "is empty or absent in the fetched secret material"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("the refusal did not mention %q: %s", want, string(body))
		}
	}
	if n := len(upstream.Requests()); n != 0 {
		t.Errorf("the upstream saw %d request(s) for a credential that was never minted, want 0", n)
	}
}

// TestHoneycombKeyless_SpecHoldsNoKeyOfItsOwn is the keyless claim stated as a
// refusal: a spec that names a chain may not also carry the key inline. Without
// it "keyless" would be a convention rather than a property — a spec could keep a
// key beside the reference, and which one it spent would be the driver's
// resolution order rather than the operator's intent.
func TestHoneycombKeyless_SpecHoldsNoKeyOfItsOwn(t *testing.T) {
	ensureEnv(t)
	setupHoneycombKeyless(t, scalewaySubjects[0])

	t.Cleanup(func() { h.APIRequest(t, "DELETE", "sys/cred/specs/"+honeycombBothSpec, leaderPort, "") })

	status, resp := h.APIRequest(t, "POST", "sys/cred/specs/"+honeycombBothSpec, leaderPort, `{
		"type":"api_key","source":"`+honeycombKeylessSource+`","config":{
			"secret_spec":"`+honeycombIngestSecretSpec+`","api_key":"hcxik_inline-key-beside-a-chain"}}`)
	if status < 400 || status >= 500 {
		t.Fatalf("a spec carrying both a chain and an inline key: status %d, want a 4xx refusal (body: %s)", status, resp)
	}
	if !strings.Contains(string(resp), "mutually exclusive") {
		t.Errorf("the refusal did not say the two are mutually exclusive: %s", resp)
	}
}
