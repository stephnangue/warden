//go:build e2e

package fullchain

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// The elastic source driver on its inline path: a source holding its own cluster
// key, creating a scoped key per request.
//
// Nothing drove this code end to end before. The mount in elastic_test.go looks
// like elastic coverage but runs off a LOCAL source, so it exercises the
// provider's scheme dispatch and never enters the driver; the chaining suite
// next door drives only the keyless path. What is left uncovered is most of what
// the driver actually does: the authentication probe at source create, the mint,
// revocation when a session ends, and the whole rotation cycle.

const (
	// The cluster key an inline source holds. Assembled rather than written out,
	// for the reason elastic_test.go gives: a literal base64 blob of this length
	// reads as a real credential to a secret scanner however synthetic it is.
	elasticInlineKeyID  = "fc-es-inline-id"
	elasticInlineSecret = "fc-es-inline-not-a-real-secret"

	// Everything is test-local, the source included. A killed run skips
	// t.Cleanup, and a spec left hanging off a shared source would block that
	// source from being deleted, failing the next run's setup before it reaches
	// the cleanup that would have cleared it. The rotation row needs its own for
	// a second reason: rotation destroys keys.
	elasticInlineSource    = "fc-es-inline-src"
	elasticInlineSpec      = "fc-es-inline-cred"
	elasticInlineAgentRole = "fc-es-inline-agent"

	elasticRevokeSource    = "fc-es-revoke-src"
	elasticRevokeSpec      = "fc-es-revoke-cred"
	elasticRevokeAgentRole = "fc-es-revoke-agent"

	elasticRotSource = "fc-es-rot-src"
	elasticRotSpec   = "fc-es-rot-cred"

	// The scoped key an inline spec asks for. key_name is the load-bearing one:
	// it is also a credential field on an apikey source, so until the adjunct
	// check learned that an elastic source spends it on the mint instead, a spec
	// setting it was refused outright.
	elasticSpecKeyName = "fc-es-ingest-writer"
	elasticSpecRoles   = `{"reader":{"indices":[{"names":["logs-*"],"privileges":["read"]}]}}`
)

var elasticInlineEncoded = base64.StdEncoding.EncodeToString(
	[]byte(elasticInlineKeyID + ":" + elasticInlineSecret))

// setupElasticInlineSource stands up a source holding its own cluster key, a
// spec naming the key to create, and a role selecting it.
//
// Creating the source is itself a test: validation builds the driver, which
// authenticates against the cluster and checks that the key it configured is the
// one the cluster says authenticated. A stub answering with a different identity
// would fail here rather than at first use.
func setupElasticInlineSource(t *testing.T, stub *elasticClusterStub, source, spec, role string, tokenTTL int, topLevel, extraConfig string) {
	t.Helper()

	useJWTAgentLeg(t, elasticEnv)

	clear := func() {
		h.APIRequest(t, "DELETE", "auth/jwt/role/"+role, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+spec, leaderPort, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+source, leaderPort, "")
	}
	clear()
	t.Cleanup(clear)

	elasticMustWrite(t, "POST", "sys/cred/sources/"+source, fmt.Sprintf(`{
		"type":"elastic"%s,"config":{
			"elastic_url":%q,"tls_skip_verify":"true","api_key":%q%s}}`,
		topLevel, stub.URL, elasticInlineEncoded, extraConfig),
		"create the inline elastic source "+source)

	elasticMustWrite(t, "POST", "sys/cred/specs/"+spec, fmt.Sprintf(`{
		"type":"api_key","source":%q,"config":{
			"key_name":%q,"expiration":"24h","role_descriptors":%q}}`,
		source, elasticSpecKeyName, elasticSpecRoles),
		"create the inline elastic spec "+spec)

	if role != "" {
		elasticMustWrite(t, "POST", "auth/jwt/role/"+role, fmt.Sprintf(`{
			"token_policies":[%q],"cred_spec_name":%q,
			"user_claim":"sub","token_ttl":%d}`,
			elasticEnv.Policy(), spec, tokenTTL),
			"create the inline agent role "+role)
	}
}

// TestElasticSource_InlineMintCarriesTheSpecToTheCluster drives the inline path
// end to end: the source authenticates with its own key, the cluster issues a
// scoped one, and the gateway injects it.
//
// The assertion on the create body is the point. A spec's mint parameters are
// the part of this driver an operator actually configures, and key_name in
// particular could not be set at all until the adjunct check stopped treating it
// as a credential field the source could not carry — so this row cannot pass
// against the driver as it was.
func TestElasticSource_InlineMintCarriesTheSpecToTheCluster(t *testing.T) {
	ensureEnv(t)

	stub := startElasticClusterStub(t)
	setupElasticInlineSource(t, stub, elasticInlineSource, elasticInlineSpec, elasticInlineAgentRole, 3600, "", "")

	// Standing the spec up already cost the cluster a create and a delete: spec
	// validation test-mints and then releases the lease. Start counting here.
	stub.reset()
	upstream.Reset()

	status, body, _ := h.ChainRequest(t, leaderPort, elasticEnv, h.ChainOpts{
		AgentToken: h.GetDefaultJWT(t),
		Bearer:     h.FullChainUserJWT(t),
		Role:       elasticInlineAgentRole,
		Path:       h.ProbePath("elastic-inline-mint"),
	})
	if status != 200 {
		t.Fatalf("status %d, body %s", status, string(body))
	}

	// The stub derives what it issues from the key that authenticated the create,
	// so this header names the source's own key specifically.
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "ApiKey " + elasticMintedFor(elasticInlineEncoded)},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})

	creates := stub.createdKeys()
	if len(creates) != 1 {
		t.Fatalf("the cluster saw %d key creations, want exactly 1: %+v", len(creates), creates)
	}
	got := creates[0]

	if got.ClusterKey != elasticInlineEncoded {
		t.Errorf("the create authenticated with %q, want the source's own key", got.ClusterKey)
	}
	if name, _ := got.Body["name"].(string); name != elasticSpecKeyName {
		t.Errorf("created key name %q, want the spec's key_name %q", name, elasticSpecKeyName)
	}
	if exp, _ := got.Body["expiration"].(string); exp != "24h" {
		t.Errorf("created key expiration %q, want the spec's 24h", exp)
	}
	// Sent as a JSON object, not the string the spec holds — the driver parses it
	// before sending, and a cluster would reject the string form.
	rd, ok := got.Body["role_descriptors"].(map[string]interface{})
	if !ok {
		t.Fatalf("role_descriptors reached the cluster as %T, want a JSON object", got.Body["role_descriptors"])
	}
	if _, ok := rd["reader"]; !ok {
		t.Errorf("role_descriptors did not carry the spec's role: %+v", rd)
	}
}

// TestElasticSource_MintedKeyIsInvalidatedWhenTheSessionEnds is the row the
// revocable change needs.
//
// A minted key is registered for expiry against the SESSION's lifetime, not the
// key's own — so a role with a short token_ttl brings the revocation forward to
// where a test can watch it. The key here asks for 24h; what ends it is the
// agent's token running out five seconds later.
//
// Until api_key became revocable this lease reached nothing: the expiration
// manager is only told about a credential the type calls revocable, so every key
// minted for a caller outlived its session and sat at the cluster until its own
// expiration. Without that fix this row fails by timing out, having watched a
// cluster that was never asked to invalidate anything.
func TestElasticSource_MintedKeyIsInvalidatedWhenTheSessionEnds(t *testing.T) {
	ensureEnv(t)

	stub := startElasticClusterStub(t)
	setupElasticInlineSource(t, stub, elasticRevokeSource, elasticRevokeSpec, elasticRevokeAgentRole, 5, "", "")

	stub.reset()
	upstream.Reset()

	status, body, _ := h.ChainRequest(t, leaderPort, elasticEnv, h.ChainOpts{
		AgentToken: h.GetDefaultJWT(t),
		Bearer:     h.FullChainUserJWT(t),
		Role:       elasticRevokeAgentRole,
		Path:       h.ProbePath("elastic-inline-revoke"),
	})
	if status != 200 {
		t.Fatalf("status %d, body %s", status, string(body))
	}
	if creates := stub.createdKeys(); len(creates) != 1 {
		t.Fatalf("the cluster saw %d key creations, want exactly 1", len(creates))
	}

	// Nothing to synchronise on but the effect: the revocation runs on the
	// expiration manager's own timer once the session's five seconds are up.
	stub.awaitInvalidated(t, elasticMintedKeyID, 60*time.Second)

	for _, id := range stub.invalidatedKeys() {
		if id != elasticMintedKeyID {
			t.Errorf("the cluster was asked to invalidate %q, which this row never minted", id)
		}
	}
}

// TestElasticSource_RotationStagesSweepsAndCleansUp drives a full source
// rotation against a real cluster.
//
// Worth a row beyond the elastic specifics: the vault rotation row covers the
// FAST path, where prepare and activate collapse into one job because Vault
// reports a zero activation delay. Elastic reports a positive one, so this is
// the staged path — prepare, persist, wait, activate, clean up — end to end.
//
// It also drives the orphan sweep, by priming the cluster with a rotation key an
// earlier cycle would have abandoned. The sweep issues an authenticated bulk
// delete, so what it is allowed to match is the whole of its safety: the live
// key is primed as sweepable too, and the row asserts the sweep left it alone.
func TestElasticSource_RotationStagesSweepsAndCleansUp(t *testing.T) {
	ensureEnv(t)

	const abandoned = "fc-es-abandoned-1"

	stub := startElasticClusterStub(t)

	// Primed before the source exists, because the source is enrolled for
	// rotation the moment it is created and the first cycle is the one that
	// sweeps. Both keys are listed as sweepable; only the abandoned one may be
	// reclaimed, since the live key is excluded by id — which is what stops a
	// sweep from destroying the credential its own source authenticates with.
	stub.primeQueryable(abandoned, elasticInlineKeyID)

	// No role: this source is here to rotate, not to serve a request.
	setupElasticInlineSource(t, stub, elasticRotSource, elasticRotSpec, "", 0,
		`,"rotation_period":15`, `,"activation_delay":"1s"`)

	stub.reset()

	// last_rotation is absent until one completes, so this waits for the field to
	// appear rather than for a value to change.
	deadline := time.Now().Add(120 * time.Second)
	rotated := false
	for time.Now().Before(deadline) {
		readStatus, readBody := h.APIRequest(t, "GET", "sys/cred/sources/"+elasticRotSource, leaderPort, "")
		if readStatus == 200 {
			if last, _ := h.JSONPath(h.ParseJSON(t, readBody), "data.last_rotation").(string); last != "" {
				rotated = true
				break
			}
		}
		time.Sleep(2 * time.Second)
	}
	if !rotated {
		t.Fatalf("source %s never recorded a completed rotation within the deadline", elasticRotSource)
	}

	// The replacement key, stamped so an operator reading the cluster can tell
	// what it is and which key it replaced.
	var rotationCreate *elasticCreate
	for i := range stub.createdKeys() {
		c := stub.createdKeys()[i]
		metadata, _ := c.Body["metadata"].(map[string]interface{})
		if purpose, _ := metadata["purpose"].(string); purpose == "source_rotation" {
			rotationCreate = &c
			break
		}
	}
	if rotationCreate == nil {
		t.Fatalf("no key was created for the rotation; the cluster saw %+v", stub.createdKeys())
	}
	metadata, _ := rotationCreate.Body["metadata"].(map[string]interface{})
	if replacing, _ := metadata["replacing"].(string); replacing != elasticInlineKeyID {
		t.Errorf("the rotation key records replacing=%q, want the key it replaced (%q)", replacing, elasticInlineKeyID)
	}
	if rotationCreate.ClusterKey != elasticInlineEncoded {
		t.Errorf("the rotation create authenticated with %q, want the key being replaced", rotationCreate.ClusterKey)
	}

	batches := stub.invalidateBatches()
	if len(batches) == 0 {
		t.Fatalf("the cluster was never asked to invalidate anything; a rotation should sweep and then clean up")
	}

	// The sweep runs first, at the top of prepare. It must have taken the
	// abandoned key and left the one the source is still using.
	sweep := batches[0]
	if len(sweep) != 1 || sweep[0] != abandoned {
		t.Errorf("the sweep invalidated %v, want exactly the abandoned key %q", sweep, abandoned)
	}
	for _, id := range sweep {
		if id == elasticInlineKeyID {
			t.Errorf("the sweep invalidated the key its own source authenticates with (%q)", id)
		}
	}

	// And cleanup destroyed the key that was replaced — the point of rotating.
	if !stub.sawInvalidated(elasticInlineKeyID) {
		t.Errorf("the replaced key %q was never invalidated; it is still live at the cluster", elasticInlineKeyID)
	}
}
