//go:build e2e

package fullchain

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// mcp_aws signs rather than injects: instead of putting a credential into a
// header, it derives an AWS SigV4 signature over the whole request. Several
// providers sign — aws, alicloud, and the S3 legs of the dual-mode gateways —
// but they expect the *client* to have signed and then verify and re-sign
// (provider/aws/signature.go pairs VerifyIncomingSignature with ResignRequest).
// mcp_aws only signs outbound, from a credential it minted, for a caller who
// authenticated some other way.
//
// It is also the only one of the signing providers this suite can reach. aws
// derives its target from a compiled-in endpoint resolver keyed by the signature
// scope, alicloud from a host allowlist, and the dual-mode gateways cannot be
// configured onto a local listener at all: their config write resets fields it
// does not mention, they ignore auto_auth_path given at mount time, and they
// expose no way to trust a private CA. So the signing path has no other
// end-to-end coverage.
//
// Because the credential never appears verbatim, the assertions are about the
// signature's shape rather than a header's value.

// The credential type enforces part of AWS's format: the key id must begin AKIA
// or ASIA, and the secret must be exactly 40 characters. Nothing else is checked
// — no length or character set on the key id — which is the room these values
// exploit.
//
// A secret scanner recognises an AWS key id as the prefix followed by sixteen
// upper-case alphanumerics. Keeping the required prefix but continuing in
// lower-case and hyphens satisfies Warden while being unable to match that
// shape, so neither this file nor a repository scan has to carry an exception.
// Do not "correct" these to look like real keys.
const (
	mcpAWSAccessKey = "AKIA-fc-mcp-aws-not-a-real-key-id"
	mcpAWSSecretKey = "fc-mcp-aws-not-a-real-secret-0123456789x"
	mcpAWSRegion    = "us-east-1"
)

var mcpAWSEnv = h.ProviderEnv{
	Mount:    "fc-mcp-aws",
	Type:     "mcp_aws",
	URLKey:   "mcp_aws_url",
	CredType: "aws_access_keys",
	CredConfig: map[string]string{
		"access_key_id":     mcpAWSAccessKey,
		"secret_access_key": mcpAWSSecretKey,
	},
	ExtraConfig: map[string]any{"region": mcpAWSRegion},
}

// mcpAWSWrongCredEnv is the same provider bound to a credential it cannot sign
// with.
//
// A second mount is a limitation of this harness rather than of Warden: specs
// are not mount-scoped and a cert role could bind an api_key spec against the
// mount above, but ProviderEnv.Variants reuses the env's CredType, so varying
// the type needs a second env.
var mcpAWSWrongCredEnv = h.ProviderEnv{
	Mount:       "fc-mcp-aws-wrongcred",
	Type:        "mcp_aws",
	URLKey:      "mcp_aws_url",
	CredType:    "api_key",
	CredConfig:  map[string]string{"api_key": "fc-mcp-aws-wrong-type"},
	ExtraConfig: map[string]any{"region": mcpAWSRegion},
}

// TestMCPAWS_RequestIsSigned checks the upstream received a signature derived
// from this mount's credential and region.
//
// The evidence is necessarily indirect, and comes in two parts. The credential
// scope names the key and region, which ties the signature to this mount. The
// payload hash ties it to this request: a signature is computed over that hash,
// so one carrying the wrong body would be a signature of something the upstream
// did not receive.
func TestMCPAWS_RequestIsSigned(t *testing.T) {
	ensureEnv(t)

	reqBody := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	status, body, _ := h.ChainRequest(t, leaderPort, mcpAWSEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         mcpAWSEnv.CertRole(),
		Body:         reqBody,
		Headers:      h.InertDecoyHeaders(),
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})

	got := upstream.Last(t).Header
	auth := got.Get("Authorization")

	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256") {
		t.Fatalf("Authorization: got %q, want an AWS4-HMAC-SHA256 signature", auth)
	}
	// The credential scope names the key and the region the mount was configured
	// with, which is what ties the signature to this mount rather than to a
	// default or to another mount's credential.
	if !strings.Contains(auth, mcpAWSAccessKey) {
		t.Errorf("the signature does not name the mount's access key: %s", auth)
	}
	if !strings.Contains(auth, mcpAWSRegion) {
		t.Errorf("the signature does not name the configured region %q: %s", mcpAWSRegion, auth)
	}
	// A tripwire rather than evidence: a SigV4 signature never carries the secret
	// by construction, so this can only catch something pathological.
	if strings.Contains(auth, mcpAWSSecretKey) {
		t.Error("the secret access key appears in the Authorization header")
	}

	// What the signature was computed over. The payload hash is the only part of
	// a signed request that ties it to this body rather than to any body, so a
	// regression signing a stale or empty payload shows up here and nowhere else.
	wantHash := fmt.Sprintf("%x", sha256.Sum256([]byte(reqBody)))
	if h := got.Get("X-Amz-Content-Sha256"); h != wantHash {
		t.Errorf("X-Amz-Content-Sha256: got %q, want %q — the signature does not cover the "+
			"body the upstream received", h, wantHash)
	}
	// The signature is only over the headers it names, so a request whose date
	// was excluded could be replayed.
	if !strings.Contains(auth, "SignedHeaders=") || !strings.Contains(auth, "x-amz-date") {
		t.Errorf("the signature does not cover x-amz-date: %s", auth)
	}
	if got.Get("X-Amz-Date") == "" {
		t.Error("a signed request must carry X-Amz-Date")
	}
}

// TestMCPAWS_UnusableCredentialIs500NotUnauthorized pins a deliberate divergence.
//
// The caller authenticated, the policy allowed the request, and a credential was
// minted — it is simply of a type this provider cannot sign with. The httpproxy
// family answers 401 whenever its credential extractor fails; here it is a 500,
// because telling the caller to present different credentials would point them
// at something they cannot change. The fault is in how the mount was bound.
//
// Worth pinning precisely because it looks like an inconsistency: it is the row
// that would vanish if someone made the status codes uniform.
func TestMCPAWS_UnusableCredentialIs500NotUnauthorized(t *testing.T) {
	ensureEnv(t)

	status, body, _ := h.ChainRequest(t, leaderPort, mcpAWSWrongCredEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         mcpAWSWrongCredEnv.CertRole(),
		Body:         `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        500,
		UpstreamCalls: 0,
	})

	// The reason must not leak: which credential a mount holds is configuration,
	// not something a caller should learn from an error.
	if strings.Contains(string(body), "api_key") {
		t.Errorf("the response names the credential type: %s", body)
	}
}
