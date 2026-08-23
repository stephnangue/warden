package dualgateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/sigv4"
)

// Every channel that carried a credential for Warden has to be gone before the
// request leaves. The upstream is a third party: an operator token, an agent
// token or a user's bearer arriving there is a credential it could replay.
func TestStripInboundCredentials_RemovesEveryWardenChannel(t *testing.T) {
	h := http.Header{}
	for _, name := range []string{
		"Authorization",
		"X-Warden-Token", "X-Warden-Agent-Token", "X-Warden-Role", "X-Warden-Provider",
		"X-Warden-Subject-Token", "X-Warden-Actor-Token", "X-Warden-User-Token",
	} {
		h.Set(name, "sensitive")
	}
	h.Set("X-Trace-Id", "keep-me")

	stripInboundCredentials(h)

	for name := range h {
		if name == "X-Trace-Id" {
			continue
		}
		t.Errorf("%s survived the strip", name)
	}
	assert.Equal(t, "keep-me", h.Get("X-Trace-Id"), "unrelated headers must pass through")
}

// The S3 leg strips too, and the ordering is the part that can go wrong. An S3
// client may sign X-Warden-Token into its signature; removing it before the
// signature is checked would reject a correctly formed request, so the strip has
// to come after verification and before re-signing.
//
// The forward cannot succeed here — S3 mode resolves a vendor hostname over TLS
// — so the assertion is on the failure that would follow a premature strip: a
// 403 for a signature that no longer matches its own SignedHeaders.
func TestHandleS3Request_StripHappensAfterVerification(t *testing.T) {
	b := createBackend(t, headerAuthSpec)

	const accessKey = "warden-role-name"
	body := []byte(`{}`)

	httpReq := httptest.NewRequest("GET", "https://s3.fr-par.test.cloud/bucket/key", nil)
	httpReq.Header.Set("X-Warden-Token", "operator-token")

	// Sign with the access key in both slots, which is how the gateway
	// reconstructs client credentials to verify.
	signer := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
	require.NoError(t, sigv4.ResignRequest(context.Background(), signer, httpReq,
		awssdk.Credentials{AccessKeyID: accessKey, SecretAccessKey: accessKey},
		"s3", "fr-par", body))
	require.Contains(t, httpReq.Header.Get("Authorization"), "x-warden-token",
		"the header must be inside SignedHeaders for this test to mean anything")

	rec := httptest.NewRecorder()
	b.handleS3Request(context.Background(), &logical.Request{
		HTTPRequest:    httpReq,
		ResponseWriter: rec,
		Credential: &credential.Credential{
			Type: "test_keys",
			Data: map[string]string{"access_key": "AK", "secret_key": "SK"},
		},
	})

	// 502 is the forward failing against an unreachable vendor host, which is
	// only reached once extraction and verification have both succeeded. A
	// strip that ran too early gives 401 (Authorization gone, nothing to
	// extract from) or 403 (signature no longer matches its SignedHeaders), so
	// the exact code is the assertion.
	assert.Equal(t, http.StatusBadGateway, rec.Code,
		"want the forward to have been attempted; 401/403 mean the strip ran before verification")
}
