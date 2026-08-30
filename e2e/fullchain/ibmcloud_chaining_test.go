//go:build e2e

package fullchain

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// IBM chains at both levels, and the level says which secret is meant.
//
// IBM Cloud IAM trusts no external OIDC issuer — trusted profiles federate only
// IBM-managed compute — so the assertion-based keyless path the other cloud
// drivers take has nothing to exchange against here. What is achievable is
// removing the key from Warden, which is what these rows drive:
//
//   - a SOURCE-level reference yields the api key the IAM token grant is made
//     with. The source stores none, and the key is fetched per request as the
//     calling agent.
//   - a SPEC-level reference yields the COS HMAC pair an access_keys spec serves.
//     That pair IS the spec's credential; it authenticates nothing of the
//     source's, and the path calls IBM for nothing.
//
// Putting a reference on the wrong level is refused, and the rows below drive
// that too — a misplaced one would otherwise mint from the wrong secret entirely.

const (
	// Written to secret/data/e2e/ibm-api-key by setup.sh. Stored under a name that
	// is neither of the driver's conventional ones (api_key, apikey), so the
	// referenced spec must project it with json_key_map for the mint to work at
	// all. ibmChainedUnrelatedField shares that path and must never be vended:
	// json_key_map drops what it does not name.
	ibmChainedAPIKey         = "e2e-ibm-chained-api-key"
	ibmChainedStoredField    = "ibmcloud_api_key"
	ibmChainedUnrelatedValue = "must-not-be-vended"

	// Written to secret/data/e2e/ibm-cos-hmac by setup.sh. Both halves, because
	// for access_keys the pair IS the credential.
	ibmChainedAccessKeyID     = "E2EIBMCOSACCESSKEY00"
	ibmChainedSecretAccessKey = "e2e-ibm-cos-not-a-real-secret"

	// Test-local, the sources included, for the reason gitlab_test.go gives: a
	// killed run skips t.Cleanup, and a spec left hanging off a shared source
	// would block that source from being deleted, failing the next run's setup
	// before it reaches the cleanup that would have cleared it.
	ibmAPIKeySecretSpec = "fc-ibm-api-key-from-vault"
	ibmChainSource      = "fc-ibm-keyless-src"
	ibmChainSpec        = "fc-ibm-chain-cred"
	ibmChainAgentRole   = "fc-ibm-chain-agent"
	ibmPairSecretSpec   = "fc-ibm-pair-from-vault"
	ibmAccessSource     = "fc-ibm-access-src"
	ibmAccessSpec       = "fc-ibm-access-cred"
)

// ibmGrantKeys records every api key the IAM stub was handed, so a row can assert
// which secret was actually spent rather than inferring it from a header alone.
var (
	ibmGrantMu   sync.Mutex
	ibmGrantKeys []string
)

func ibmRecordGrantKey(key string) {
	ibmGrantMu.Lock()
	defer ibmGrantMu.Unlock()
	ibmGrantKeys = append(ibmGrantKeys, key)
}

func ibmResetGrantKeys() {
	ibmGrantMu.Lock()
	defer ibmGrantMu.Unlock()
	ibmGrantKeys = nil
}

func ibmObservedGrantKeys() []string {
	ibmGrantMu.Lock()
	defer ibmGrantMu.Unlock()
	return append([]string(nil), ibmGrantKeys...)
}

// ibmMustWrite is the local provisioning helper the chained rows share.
func ibmMustWrite(t *testing.T, method, path, body, what string) {
	t.Helper()
	switch status, resp := h.APIRequest(t, method, path, leaderPort, body); status {
	case 200, 201, 204:
	default:
		t.Fatalf("%s (status %d): %s", what, status, resp)
	}
}

// ibmMustRefuse asserts a write is rejected and that the reason names what the
// operator has to change. "not 200" would also pass for a 500, which would mean
// something else entirely.
func ibmMustRefuse(t *testing.T, path, body, wantIn, what string) {
	t.Helper()
	status, resp := h.APIRequest(t, "POST", path, leaderPort, body)
	if status < 400 || status >= 500 {
		t.Fatalf("%s: status %d, want a 4xx refusal (body: %s)", what, status, resp)
	}
	if !strings.Contains(string(resp), wantIn) {
		t.Errorf("%s: refusal did not mention %q: %s", what, wantIn, resp)
	}
}

// ibmReferencedSpec creates the key_value spec a chain points at. json_key_map is
// what makes the stored payload readable: the api key is filed under a name the
// driver does not look for, and the projection also drops the companion field, so
// a shared path does not vend more than this spec needs.
func ibmReferencedSpec(t *testing.T, name, secretPath, keyMap string, subj scalewaySubject) {
	t.Helper()
	cfg := fmt.Sprintf(`"mint_method":"kv2_read","kv2_mount":"secret","secret_path":%q,"subject_token_source":%q`,
		secretPath, subj.name)
	if keyMap != "" {
		cfg += fmt.Sprintf(`,"json_key_map":%q`, keyMap)
	}
	ibmMustWrite(t, "POST", "sys/cred/specs/"+name,
		fmt.Sprintf(`{"type":"key_value","source":%q,"config":{%s}}`, subj.source, cfg),
		"create the referenced secret spec "+name)
}

// setupIBMAPIKeyChain builds the SOURCE-level chain: a source holding no api key,
// and a bearer spec that inherits the chain from it.
func setupIBMAPIKeyChain(t *testing.T, subj scalewaySubject) {
	t.Helper()

	// The referenced spec is minted as the calling agent, and both subjects in the
	// matrix derive that agent from an inbound JWT — agent_identity forwards it,
	// warden_identity signs an assertion from the principal it established. This
	// mount's default agent leg is a client certificate, which carries neither, so
	// the leg is switched for these rows the way every other chained row does it.
	useJWTAgentLeg(t, ibmcloudEnv)

	clear := func() {
		h.APIRequest(t, "DELETE", "auth/jwt/role/"+ibmChainAgentRole, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+ibmChainSpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+ibmChainSource, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+ibmAPIKeySecretSpec, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	ibmReferencedSpec(t, ibmAPIKeySecretSpec, "e2e/ibm-api-key",
		ibmChainedStoredField+"=api_key", subj)

	// No api_key: validation refuses a source that keeps one while also naming a
	// chain, because it would read as keyless while storing the very secret
	// chaining removes.
	ibmMustWrite(t, "POST", "sys/cred/sources/"+ibmChainSource, fmt.Sprintf(`{
		"type":"ibm","config":{
			"iam_endpoint":%q,"tls_skip_verify":"true","secret_spec":%q}}`,
		ibmIAMStub.URL, ibmAPIKeySecretSpec),
		"create the keyless ibm source")

	// Ordinary: it inherits the chain from its source and carries no chaining
	// config of its own, which is what source-level chaining means.
	ibmMustWrite(t, "POST", "sys/cred/specs/"+ibmChainSpec,
		`{"type":"ibmcloud_keys","source":"`+ibmChainSource+`","config":{}}`,
		"create the chained bearer spec")

	ibmMustWrite(t, "POST", "auth/jwt/role/"+ibmChainAgentRole, `{
		"token_policies":["`+ibmcloudEnv.Policy()+`"],"cred_spec_name":"`+ibmChainSpec+`",
		"user_claim":"sub","token_ttl":3600}`,
		"create the chained agent role")
}

// TestIBMCloudChaining_SourceFetchesTheAPIKeyPerRequest is the whole feature in one
// row: the source stores no key, the referenced spec yields one, and the token the
// gateway injects names it.
func TestIBMCloudChaining_SourceFetchesTheAPIKeyPerRequest(t *testing.T) {
	ensureEnv(t)

	for _, subj := range scalewaySubjects {
		t.Run(subj.name, func(t *testing.T) {
			setupIBMAPIKeyChain(t, subj)
			upstream.Reset()
			ibmResetGrantKeys()

			status, body, _ := h.ChainRequest(t, leaderPort, ibmcloudEnv, h.ChainOpts{
				AgentToken: h.GetDefaultJWT(t),
				Bearer:     h.FullChainUserJWT(t),
				Role:       ibmChainAgentRole,
				Path:       "resource-controller.cloud.ibm.com/v2/resource_instances",
			})
			if status != 200 {
				t.Fatalf("status %d, body %s", status, string(body))
			}

			// The stub derives its token from the key it was handed, so this header
			// is the end-to-end proof that the FETCHED key performed the grant — not
			// the inline one the other mount on this suite holds.
			h.AssertChain(t, upstream, status, body, h.ChainWant{
				Status:        200,
				Injected:      map[string]string{"Authorization": "Bearer " + ibmTokenPrefix + ibmChainedAPIKey},
				Absent:        h.AlwaysAbsent(),
				UpstreamCalls: 1,
			})

			// And the stub's own record agrees, which distinguishes a genuine chain
			// from a header that merely looks right.
			keys := ibmObservedGrantKeys()
			if len(keys) == 0 {
				t.Fatal("the IAM stub saw no grant at all")
			}
			for _, k := range keys {
				if k != ibmChainedAPIKey {
					t.Errorf("grant used api key %q, want the chained %q", k, ibmChainedAPIKey)
				}
			}

			// The companion value sharing that Vault path must never be what the
			// grant spent. json_key_map drops what it does not name, so the driver
			// never sees it — but the projection is also what makes the mint work at
			// all here, since the key is stored under neither conventional name.
			// Asserting on the value, not the field name: the name never travels.
			for _, k := range keys {
				if k == ibmChainedUnrelatedValue {
					t.Errorf("the companion value from the referenced secret was spent as the api key")
				}
			}
		})
	}
}

// setupIBMAccessKeysChain builds the SPEC-level chain. The source holds nothing at
// all — not even a chain — because for access_keys the reference belongs to the
// spec whose credential it yields, and the source performs no grant.
func setupIBMAccessKeysChain(t *testing.T, subj scalewaySubject) {
	t.Helper()

	clear := func() {
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+ibmAccessSpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+ibmAccessSource, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+ibmPairSecretSpec, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	// No json_key_map: the pair is stored under IBM's own names for it — the
	// cos_hmac_keys fields of a service credential — which is exactly what the
	// driver reads, so nothing needs projecting.
	ibmReferencedSpec(t, ibmPairSecretSpec, "e2e/ibm-cos-hmac", "", subj)

	// No api_key: a source serving only access_keys specs never performs the grant,
	// so it is not asked for one. This is the shape the dropped Required() admits.
	ibmMustWrite(t, "POST", "sys/cred/sources/"+ibmAccessSource, fmt.Sprintf(`{
		"type":"ibm","config":{"iam_endpoint":%q,"tls_skip_verify":"true"}}`, ibmIAMStub.URL),
		"create the grant-free ibm source")

	// No secret_field: it names a single secret, and a pair is not one — both
	// halves are read by name, and the spec is refused a field for that reason.
	ibmMustWrite(t, "POST", "sys/cred/specs/"+ibmAccessSpec, `{
		"type":"ibmcloud_keys","source":"`+ibmAccessSource+`","config":{
			"mint_method":"access_keys","secret_spec":"`+ibmPairSecretSpec+`"}}`,
		"create the spec-chained access_keys spec")
}

// TestIBMCloudChaining_AccessKeysSpecWritesWithoutTouchingIBM covers what this
// suite can reach: an access_keys spec and its grant-free source are accepted, and
// standing the pair up costs no IBM call.
//
// It deliberately does NOT claim to exercise the serving path. An earlier version
// did, on the reasoning that "the store test-mints it" — it does not: a chained
// spec is excluded from both the test-mint and VerifySpec, so spec creation runs
// schema and placement validation only, and the zero-call assertion below is
// nearly free. Driving a real COS request needs the gateway's S3 leg pointed at a
// local listener, and this provider exposes only cos_endpoint_type, whose three
// values all resolve to real IBM hostnames — provider/ovh solves the same problem
// with an s3_url host override, which is what makes its S3 rows possible. So
// mintAccessKeysFromSecret and ExtractS3Credentials are covered by unit tests on
// each side, agreeing on access_key_id and secret_access_key, but nothing checks
// that agreement on a live request.
func TestIBMCloudChaining_AccessKeysSpecWritesWithoutTouchingIBM(t *testing.T) {
	ensureEnv(t)

	for _, subj := range scalewaySubjects {
		t.Run(subj.name, func(t *testing.T) {
			ibmResetGrantKeys()
			setupIBMAccessKeysChain(t, subj)

			if keys := ibmObservedGrantKeys(); len(keys) != 0 {
				t.Errorf("the IAM stub was called %d time(s) standing up an access_keys spec, want 0: %v", len(keys), keys)
			}
		})
	}
}

// TestIBMCloudChaining_ReferencePlacementIsEnforced drives the refusals. A
// reference on the wrong level would mint from the wrong secret entirely: an
// access_keys spec riding the source's chain would be handed the api key, and a
// bearer spec naming its own would describe a secret it never spends.
func TestIBMCloudChaining_ReferencePlacementIsEnforced(t *testing.T) {
	ensureEnv(t)

	subj := scalewaySubjects[0]
	setupIBMAPIKeyChain(t, subj)

	t.Run("an access_keys spec may not ride the source-level reference", func(t *testing.T) {
		ibmMustRefuse(t, "sys/cred/specs/fc-ibm-access-inheriting",
			`{"type":"ibmcloud_keys","source":"`+ibmChainSource+`","config":{"mint_method":"access_keys"}}`,
			"secret_spec",
			"an access_keys spec inheriting the source's api-key reference")
		t.Cleanup(func() {
			h.APIRequest(t, "DELETE", "sys/cred/specs/fc-ibm-access-inheriting", leaderPort, "")
		})
	})

	t.Run("a bearer spec may not carry a reference of its own", func(t *testing.T) {
		ibmMustRefuse(t, "sys/cred/specs/fc-ibm-bearer-chained",
			`{"type":"ibmcloud_keys","source":"`+ibmChainSource+`","config":{"secret_spec":"`+ibmAPIKeySecretSpec+`"}}`,
			"secret_spec",
			"a bearer spec naming its own reference")
		t.Cleanup(func() {
			h.APIRequest(t, "DELETE", "sys/cred/specs/fc-ibm-bearer-chained", leaderPort, "")
		})
	})

	t.Run("a chained source may not also store an api key", func(t *testing.T) {
		ibmMustRefuse(t, "sys/cred/sources/fc-ibm-half-keyless",
			fmt.Sprintf(`{"type":"ibm","config":{"iam_endpoint":%q,"tls_skip_verify":"true","secret_spec":%q,"api_key":"still-here"}}`,
				ibmIAMStub.URL, ibmAPIKeySecretSpec),
			"api_key",
			"a source keeping an inline key beside a reference")
		t.Cleanup(func() {
			h.APIRequest(t, "DELETE", "sys/cred/sources/fc-ibm-half-keyless", leaderPort, "")
		})
	})

	// A chained source holds no secret of its own, so there is nothing here to
	// rotate — that passes to whoever owns the referenced spec.
	t.Run("a chained source may not carry a rotation period", func(t *testing.T) {
		ibmMustRefuse(t, "sys/cred/sources/fc-ibm-rotating",
			fmt.Sprintf(`{"type":"ibm","rotation_period":3600,"config":{"iam_endpoint":%q,"tls_skip_verify":"true","secret_spec":%q}}`,
				ibmIAMStub.URL, ibmAPIKeySecretSpec),
			"rotation_period",
			"a chained source asking to rotate")
		t.Cleanup(func() {
			h.APIRequest(t, "DELETE", "sys/cred/sources/fc-ibm-rotating", leaderPort, "")
		})
	})
}

// TestIBMCloudChaining_IAMWithCOSIsRefusedAtCreate pins the migration the breaking
// change promised: the removed method is refused on the next write, rather than
// accepted and quietly behaving as something else.
func TestIBMCloudChaining_IAMWithCOSIsRefusedAtCreate(t *testing.T) {
	ensureEnv(t)

	ibmMustRefuse(t, "sys/cred/specs/fc-ibm-iamwithcos",
		fmt.Sprintf(`{"type":"ibmcloud_keys","source":%q,"config":{"mint_method":"iam_with_cos"}}`, ibmcloudEnv.Source()),
		"mint_method",
		"a spec still using the removed iam_with_cos method")
	t.Cleanup(func() {
		h.APIRequest(t, "DELETE", "sys/cred/specs/fc-ibm-iamwithcos", leaderPort, "")
	})
}
