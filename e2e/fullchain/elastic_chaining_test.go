//go:build e2e

package fullchain

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// An elastic source chains the cluster key that authenticates its own Security
// API calls. Elasticsearch's own API-key creation has no assertion grant to
// federate against, so as with ibm, keyless here means removing the key from
// Warden rather than exchanging an identity for one.
//
// Chaining is a SOURCE concern for this driver, and only that. There is one mint
// method and no second reading of the fetched material — every spec creates a
// fresh cluster key rather than serving a stored one — so a spec-level reference
// means nothing and is refused, with the guidance to move it to the source.
//
// The inline half of this driver is next door in elastic_source_test.go. Neither
// is reached by the mount in elastic_test.go, which drives the *provider* off a
// local source and never enters the driver at all.

const (
	// Written to secret/data/e2e/elastic-cluster-key and -pair by setup.sh, in
	// the two shapes a vault holds an Elasticsearch key in.
	elasticChainedClusterID  = "e2e-es-cluster-id"
	elasticChainedClusterKey = "e2e-es-cluster-not-a-real-secret"

	// Test-local, the source included, for the reason the other chained suites
	// give: a killed run skips t.Cleanup, and a spec left hanging off a shared
	// source would block that source from being deleted, failing the next run's
	// setup before it reaches the cleanup that would have cleared it.
	elasticEncodedSecretSpec = "fc-es-key-from-vault"
	elasticPairSecretSpec    = "fc-es-pair-from-vault"
	elasticChainSource       = "fc-es-keyless-src"
	elasticChainSpec         = "fc-es-chain-cred"
	elasticChainAgentRole    = "fc-es-chain-agent"
)

// elasticChainedClusterEncoded is the wire form of the cluster key: the base64
// of "id:api_key" the cluster hands out. Both stored shapes must arrive at the
// cluster as exactly this, which is what makes the two rows below comparable.
var elasticChainedClusterEncoded = base64.StdEncoding.EncodeToString(
	[]byte(elasticChainedClusterID + ":" + elasticChainedClusterKey))

func elasticMustWrite(t *testing.T, method, path, body, what string) {
	t.Helper()
	switch status, resp := h.APIRequest(t, method, path, leaderPort, body); status {
	case 200, 201, 204:
	default:
		t.Fatalf("%s (status %d): %s", what, status, resp)
	}
}

// elasticMustRefuse asserts a write is rejected and that the reason names what
// the operator has to change. "not 200" would also pass for a 500, which would
// mean something else entirely.
func elasticMustRefuse(t *testing.T, path, body, wantIn, what string) {
	t.Helper()
	status, resp := h.APIRequest(t, "POST", path, leaderPort, body)
	if status < 400 || status >= 500 {
		t.Fatalf("%s: status %d, want a 4xx refusal (body: %s)", what, status, resp)
	}
	if !strings.Contains(string(resp), wantIn) {
		t.Errorf("%s: refusal did not mention %q: %s", what, wantIn, resp)
	}
	t.Cleanup(func() { h.APIRequest(t, "DELETE", path, leaderPort, "") })
}

// setupElasticChain stands up one chain: a referenced spec over the given Vault
// secret, a source holding no key that names it, an ordinary spec, and a role
// selecting that spec.
func setupElasticChain(t *testing.T, subj scalewaySubject, secretSpec, secretPath, secretField string, stub *elasticClusterStub) {
	t.Helper()

	// The referenced spec is minted as the calling agent, and both subjects derive
	// that agent from an inbound JWT — agent_identity forwards it, warden_identity
	// signs an assertion from the principal it established. This mount's default
	// agent leg is a client certificate, which carries neither.
	useJWTAgentLeg(t, elasticEnv)

	clear := func() {
		h.APIRequest(t, "DELETE", "auth/jwt/role/"+elasticChainAgentRole, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+elasticChainSpec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+elasticChainSource, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+secretSpec, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	elasticMustWrite(t, "POST", "sys/cred/specs/"+secretSpec, fmt.Sprintf(`{
		"type":"key_value","source":%q,"config":{
			"mint_method":"kv2_read","kv2_mount":"secret","secret_path":%q,
			"subject_token_source":%q}}`, subj.source, secretPath, subj.name),
		"create the referenced secret spec "+secretSpec)

	// No api_key and no api_key_id: validation refuses a source that keeps either
	// while naming a chain. tls_skip_verify because the stub listens on http, the
	// same allowance every other stubbed source in this suite takes.
	elasticMustWrite(t, "POST", "sys/cred/sources/"+elasticChainSource, fmt.Sprintf(`{
		"type":"elastic","config":{
			"elastic_url":%q,"tls_skip_verify":"true",
			"secret_spec":%q,"secret_field":%q}}`,
		stub.URL, secretSpec, secretField),
		"create the keyless elastic source")

	// Ordinary: it inherits the chain from its source and carries no chaining
	// config of its own, which is what source-level chaining means.
	elasticMustWrite(t, "POST", "sys/cred/specs/"+elasticChainSpec,
		`{"type":"api_key","source":"`+elasticChainSource+`","config":{"expiration":"1h"}}`,
		"create the chained elastic spec")

	elasticMustWrite(t, "POST", "auth/jwt/role/"+elasticChainAgentRole, `{
		"token_policies":["`+elasticEnv.Policy()+`"],"cred_spec_name":"`+elasticChainSpec+`",
		"user_claim":"sub","token_ttl":3600}`,
		"create the chained agent role")
}

// TestElasticChaining_SourceFetchesTheClusterKeyPerRequest is the whole feature
// in one row: the source stores no key, the referenced spec yields one, and the
// key the gateway injects is the one this cluster minted for exactly that key.
//
// Both stored shapes are driven, and both must arrive at the cluster as the same
// wire value — which is the point of resolving them by whether an id travels
// alongside rather than by testing what the value decodes to.
func TestElasticChaining_SourceFetchesTheClusterKeyPerRequest(t *testing.T) {
	ensureEnv(t)

	shapes := []struct {
		name       string
		secretSpec string
		secretPath string
		field      string
	}{
		{"pre_encoded", elasticEncodedSecretSpec, "e2e/elastic-cluster-key", "encoded"},
		{"raw_half_beside_its_id", elasticPairSecretSpec, "e2e/elastic-cluster-pair", "api_key"},
	}

	for _, subj := range scalewaySubjects {
		for _, shape := range shapes {
			t.Run(subj.name+"/"+shape.name, func(t *testing.T) {
				stub := startElasticClusterStub(t)
				setupElasticChain(t, subj, shape.secretSpec, shape.secretPath, shape.field, stub)
				upstream.Reset()

				status, body, _ := h.ChainRequest(t, leaderPort, elasticEnv, h.ChainOpts{
					AgentToken: h.GetDefaultJWT(t),
					Bearer:     h.FullChainUserJWT(t),
					Role:       elasticChainAgentRole,
					Path:       h.ProbePath("elastic-chained-" + shape.name),
				})
				if status != 200 {
					t.Fatalf("status %d, body %s", status, string(body))
				}

				// The stub derives what it issues from the key it was handed, so this
				// header is the end-to-end proof that the FETCHED key performed the
				// create — not an inline one a routing regression fell back to.
				h.AssertChain(t, upstream, status, body, h.ChainWant{
					Status:        200,
					Injected:      map[string]string{"Authorization": "ApiKey " + elasticMintedFor(elasticChainedClusterEncoded)},
					Absent:        h.AlwaysAbsent(),
					UpstreamCalls: 1,
				})

				// And the cluster's own record agrees, which distinguishes a genuine
				// chain from a header that merely looks right.
				presented := stub.observed()
				if len(presented) == 0 {
					t.Fatal("the cluster stub saw no key creation at all")
				}
				for _, key := range presented {
					if key != elasticChainedClusterEncoded {
						t.Errorf("the create authenticated with %q, want the chained cluster key", key)
					}
				}
			})
		}
	}
}

// TestElasticChaining_PlacementAndShapeAreEnforced drives the refusals. A
// reference on the spec would describe a secret the spec never spends, and a
// source keeping a key beside a chain reads as keyless while storing the very
// secret chaining removes.
func TestElasticChaining_PlacementAndShapeAreEnforced(t *testing.T) {
	ensureEnv(t)

	stub := startElasticClusterStub(t)
	setupElasticChain(t, scalewaySubjects[0], elasticEncodedSecretSpec,
		"e2e/elastic-cluster-key", "encoded", stub)

	t.Run("a spec may not carry a reference of its own", func(t *testing.T) {
		elasticMustRefuse(t, "sys/cred/specs/fc-es-spec-chained",
			`{"type":"api_key","source":"`+elasticChainSource+`","config":{"secret_spec":"`+elasticEncodedSecretSpec+`"}}`,
			"set secret_spec on the source",
			"a spec naming its own reference")
	})

	t.Run("a chained source may not also store a cluster key", func(t *testing.T) {
		elasticMustRefuse(t, "sys/cred/sources/fc-es-half-keyless",
			fmt.Sprintf(`{"type":"elastic","config":{"elastic_url":%q,"tls_skip_verify":"true","secret_spec":%q,"api_key":"still-here"}}`,
				stub.URL, elasticEncodedSecretSpec),
			"api_key",
			"a source keeping an inline key beside a reference")
	})

	// The id is derived from the key; one kept here beside a fetched key would
	// name one key while presenting another's.
	t.Run("a chained source may not keep the key id either", func(t *testing.T) {
		elasticMustRefuse(t, "sys/cred/sources/fc-es-keeps-id",
			fmt.Sprintf(`{"type":"elastic","config":{"elastic_url":%q,"tls_skip_verify":"true","secret_spec":%q,"api_key_id":"still-here"}}`,
				stub.URL, elasticEncodedSecretSpec),
			"api_key_id",
			"a source keeping the key id beside a reference")
	})

	// A chained source holds no secret of its own, so there is nothing here to
	// rotate — that passes to whoever owns the referenced spec.
	t.Run("a chained source may not carry a rotation period", func(t *testing.T) {
		elasticMustRefuse(t, "sys/cred/sources/fc-es-rotating",
			fmt.Sprintf(`{"type":"elastic","rotation_period":3600,"config":{"elastic_url":%q,"tls_skip_verify":"true","secret_spec":%q}}`,
				stub.URL, elasticEncodedSecretSpec),
			"rotation_period",
			"a chained source asking to rotate")
	})
}

// TestElasticChaining_InlineSourceStillNeedsAKey pins the other half of the
// dropped Required(): a source naming no chain must still be refused without a
// key, rather than being accepted and failing at the first mint.
func TestElasticChaining_InlineSourceStillNeedsAKey(t *testing.T) {
	ensureEnv(t)

	stub := startElasticClusterStub(t)
	elasticMustRefuse(t, "sys/cred/sources/fc-es-no-key",
		fmt.Sprintf(`{"type":"elastic","config":{"elastic_url":%q,"tls_skip_verify":"true"}}`, stub.URL),
		"api_key",
		"a source with neither a key nor a reference")
}
