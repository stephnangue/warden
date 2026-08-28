//go:build e2e

package credential

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// A keyless Alicloud source holds no RAM access key. Every mint exchanges the
// caller's Warden-minted assertion at STS AssumeRoleWithOIDC for a session on the
// spec's role, so what this suite has to prove is that the assertion is real, that
// it reaches STS in the right shape, and that the credentials come back.
//
// The exchange is what a stub can stand in for: it is an ordinary HTTPS call to an
// endpoint the source names, so pointing sts_endpoint at a local listener puts the
// whole mint under test. That is the same move e2e/fullchain/ibmcloud_test.go
// makes for IBM's IAM grant.
//
// It lives here rather than in e2e/fullchain for two reasons that both come from
// the provider rather than the driver. The Alicloud gateway is agent-only by
// design — provider/alicloud/agent_only_test.go pins that it never yields a user
// principal — so it has no user_auth_path, while every fullchain mount is
// configured with one. And it has no URL override key at all: it resolves its
// target from the inbound Host, which must end in .aliyuncs.com, and then dials
// that real public host. So the mount is set up directly here, in the agent-only
// shape e2e/forwarding/sigv4_test.go already uses.
//
// The consequence is worth stating plainly: this covers the mint hop, not the
// gateway hop. Minting runs before routing, so the exchange happens and is fully
// observable even though the request afterwards cannot reach a local upstream.
// Nothing here proves the minted security_token is signed correctly onto an
// outbound request — the same gap e2e/fullchain/mcp_aws_test.go records for AWS.

const (
	alicloudSourceName = "e2e-alicloud-keyless"
	alicloudSpecName   = "e2e-alicloud-federated"
	alicloudPolicyName = "e2e-alicloud-gateway"
	alicloudJWTRole    = "e2e-alicloud-federated"
	alicloudMount      = "e2e-alicloud"

	// Deliberately not shaped like real Alibaba identifiers, so a secret scanner
	// has nothing to catch. Do not "correct" these to look real.
	alicloudRoleARN     = "acs:ram::100000000000001:role/e2e-not-a-real-role"
	alicloudProviderARN = "acs:ram::100000000000001:oidc-provider/e2e-not-a-real-provider"

	// The audience an operator registers as a client_id on the RAM OIDC provider.
	// There is no conventional default for Alibaba, which is why the source has to
	// carry one.
	alicloudAudience = "https://warden.e2e.example.com"

	// What e2e/setup.sh configures the issuer with. The assertion's iss is pinned
	// to exactly this.
	alicloudIssuerURL = "https://127.0.0.1:8000"
)

// alicloudSTSExchange is one recorded AssumeRoleWithOIDC call.
type alicloudSTSExchange struct {
	Query    url.Values
	Form     url.Values
	AuthHdr  string
	RawQuery string
}

// alicloudSTSStub stands in for Alibaba STS. It records what the driver sent and
// answers with canned session credentials.
type alicloudSTSStub struct {
	*httptest.Server

	mu        sync.Mutex
	exchanges []alicloudSTSExchange
}

func startAlicloudSTSStub(t *testing.T) *alicloudSTSStub {
	t.Helper()
	stub := &alicloudSTSStub{}
	stub.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ParseForm reads the body, so capture the raw query first.
		rawQuery := r.URL.RawQuery
		query := r.URL.Query()
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}

		stub.mu.Lock()
		stub.exchanges = append(stub.exchanges, alicloudSTSExchange{
			Query:    query,
			Form:     r.PostForm,
			AuthHdr:  r.Header.Get("Authorization"),
			RawQuery: rawQuery,
		})
		stub.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"RequestId": "e2e-sts-request",
			"Credentials": map[string]any{
				"AccessKeyId":     "STS.e2e-not-a-real-session-key",
				"AccessKeySecret": "e2e-not-a-real-session-secret",
				"SecurityToken":   "e2e-not-a-real-security-token",
				"Expiration":      time.Now().Add(time.Hour).UTC().Format("2006-01-02T15:04:05Z"),
			},
		})
	}))
	t.Cleanup(stub.Close)
	return stub
}

func (s *alicloudSTSStub) Exchanges() []alicloudSTSExchange {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]alicloudSTSExchange(nil), s.exchanges...)
}

// mustWrite performs one setup write, accepting 409 so a rerun against a cluster
// that still holds the previous run's objects is idempotent.
func mustWrite(t *testing.T, port int, path, body, what string) {
	t.Helper()
	status, resp := h.APIRequest(t, "POST", path, port, body)
	switch status {
	case 200, 201, 204, 409:
	default:
		t.Fatalf("%s: status %d: %s", what, status, string(resp))
	}
}

// setupAlicloudKeyless provisions the keyless source, an exchange spec, the policy
// and JWT role that bind it, and the agent-only mount.
//
// Cleanup is registered before anything is created, so a failure partway through
// does not leave objects behind for the next run to trip over.
func setupAlicloudKeyless(t *testing.T, port int, stsURL string) {
	t.Helper()

	t.Cleanup(func() {
		leader := h.GetLeaderPort(t)
		h.APIRequest(t, "DELETE", "sys/providers/"+alicloudMount, leader, "")
		h.APIRequest(t, "DELETE", "auth/jwt/role/"+alicloudJWTRole, leader, "")
		h.APIRequest(t, "DELETE", "sys/policies/cbp/"+alicloudPolicyName, leader, "")
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+alicloudSpecName, leader, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+alicloudSourceName, leader, "")
	})

	// The source carries no access_key_id and no access_key_secret — that is the
	// whole point. tls_skip_verify is what permits the stub's http:// endpoint.
	mustWrite(t, port, "sys/cred/sources/"+alicloudSourceName, mustJSON(t, map[string]any{
		"type": "alicloud",
		"config": map[string]string{
			"auth_method":       "oidc_federation",
			"oidc_provider_arn": alicloudProviderARN,
			"audience":          alicloudAudience,
			"sts_endpoint":      stsURL,
			"tls_skip_verify":   "true",
		},
	}), "create keyless alicloud source")

	// subject_token_source lives in the spec's config, alongside the mint
	// settings — that is what marks the spec as an exchange spec and skips the
	// create-time test-mint a keyless source could never satisfy.
	mustWrite(t, port, "sys/cred/specs/"+alicloudSpecName, mustJSON(t, map[string]any{
		"type":   "alicloud_keys",
		"source": alicloudSourceName,
		"config": map[string]string{
			"subject_token_source": "warden_identity",
			"mint_method":          "assume_role",
			"role_arn":             alicloudRoleARN,
			"duration_seconds":     "3600s",
		},
	}), "create federated alicloud spec")

	mustWrite(t, port, "sys/policies/cbp/"+alicloudPolicyName, mustJSON(t, map[string]any{
		"policy": fmt.Sprintf("path %q {\n  capabilities = [\"read\",\"create\",\"update\",\"delete\",\"list\"]\n}", alicloudMount+"/gateway*"),
	}), "create alicloud gateway policy")

	mustWrite(t, port, "auth/jwt/role/"+alicloudJWTRole, mustJSON(t, map[string]any{
		"token_policies": []string{alicloudPolicyName},
		"user_claim":     "sub",
		"cred_spec_name": alicloudSpecName,
		"token_ttl":      3600,
	}), "create alicloud JWT role")

	mustWrite(t, port, "sys/providers/"+alicloudMount, `{"type":"alicloud"}`, "mount alicloud provider")

	// Agent-only: the provider yields no user principal by design, so there is no
	// user leg to configure.
	status, body := h.APIRequest(t, "POST", alicloudMount+"/config", port, mustJSON(t, map[string]any{
		"auto_auth_path": "auth/jwt/",
		"default_role":   alicloudJWTRole,
	}))
	if status != 200 && status != 201 && status != 204 {
		t.Fatalf("configure alicloud provider: status %d: %s", status, string(body))
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// TestAlicloudKeyless_MintsFromAWardenAssertion drives one gateway request and
// checks what the exchange carried.
//
// The gateway request does not complete, and does not need to: minting runs before
// routing, so the exchange has already happened by the time the request is refused.
// It is refused for carrying no ACS3 or SigV4 signature — a signed request would
// only get as far as host resolution, which will not dial a local listener either.
// Either way the mint is what this observes.
func TestAlicloudKeyless_MintsFromAWardenAssertion(t *testing.T) {
	leader := h.GetLeaderPort(t)
	sts := startAlicloudSTSStub(t)
	setupAlicloudKeyless(t, leader, sts.URL)

	jwt := h.GetDefaultJWT(t)
	// The Alicloud gateway is agent-only and takes its caller identity the way an
	// ACS3 client would carry a session token: a JWT in x-acs-security-token is
	// transparent mode, and the role comes from the mount's default_role. A plain
	// Authorization: Bearer is not a credential this provider recognises — it
	// yields a 401 before anything mints.
	//
	// The Host is the one a real client would send, since the provider resolves its
	// upstream target from it. This request never gets that far: the gateway
	// dispatch refuses anything without an ACS3 or SigV4 signature before host
	// resolution runs. It is set anyway so the request is the shape a client sends
	// rather than one that only happens to work.
	status, body := h.DoRequest(t, "POST",
		h.NodeURL(leader)+"/v1/"+alicloudMount+"/gateway/?Action=DescribeRegions&Version=2014-05-26",
		map[string]string{
			"x-acs-security-token": jwt,
			"Host":                 "ecs.cn-hangzhou.aliyuncs.com",
		}, "")
	// Recorded rather than asserted: the outcome of the hop after the mint is not
	// what this test is about, and pinning it would make the test fail for reasons
	// that have nothing to do with federation. It is still the first thing to read
	// if the exchange below did not happen.
	t.Logf("gateway request returned %d: %s", status, string(body))

	exchanges := sts.Exchanges()
	if len(exchanges) != 1 {
		t.Fatalf("STS saw %d exchanges, want exactly 1", len(exchanges))
	}
	ex := exchanges[0]

	// The RPC common parameters identify the call and stay in the query.
	if got := ex.Query.Get("Action"); got != "AssumeRoleWithOIDC" {
		t.Errorf("Action = %q, want AssumeRoleWithOIDC", got)
	}
	if got := ex.Query.Get("Version"); got != "2015-04-01" {
		t.Errorf("Version = %q, want 2015-04-01", got)
	}
	if ex.Query.Get("Timestamp") == "" {
		t.Error("Timestamp is missing from the query")
	}

	// The exchange parameters travel in the form body.
	if got := ex.Form.Get("RoleArn"); got != alicloudRoleARN {
		t.Errorf("RoleArn = %q, want %q", got, alicloudRoleARN)
	}
	if got := ex.Form.Get("OIDCProviderArn"); got != alicloudProviderARN {
		t.Errorf("OIDCProviderArn = %q, want %q", got, alicloudProviderARN)
	}
	if got := ex.Form.Get("DurationSeconds"); got != "3600" {
		t.Errorf("DurationSeconds = %q, want 3600", got)
	}

	assertion := ex.Form.Get("OIDCToken")
	if assertion == "" {
		t.Fatal("OIDCToken is missing from the request body")
	}

	// The two properties the driver's design turns on. AssumeRoleWithOIDC is
	// anonymous, and the assertion must never reach the URL — a transport failure
	// prints the whole URL into logs, so a token in the query leaks on every
	// timeout.
	if ex.AuthHdr != "" {
		t.Errorf("AssumeRoleWithOIDC carried an Authorization header: %q", ex.AuthHdr)
	}
	if strings.Contains(ex.RawQuery, "OIDCToken") || strings.Contains(ex.RawQuery, assertion) {
		t.Errorf("the assertion appeared in the query string: %q", ex.RawQuery)
	}

	// The assertion is checked the way STS would: against the issuer's published
	// JWKS, signature first.
	claims := h.VerifyAssertion(t, leader, assertion)

	if got := claims["iss"]; got != alicloudIssuerURL {
		t.Errorf("iss = %v, want %q", got, alicloudIssuerURL)
	}
	if got := claims["aud"]; got != alicloudAudience {
		t.Errorf("aud = %v, want %q — it must match a client_id on the RAM OIDC provider", got, alicloudAudience)
	}
	sub, _ := claims["sub"].(string)
	if !strings.HasPrefix(sub, "wid:") {
		t.Errorf("sub = %q, want a wid: composite subject", sub)
	}
	if got := claims["warden_resource"]; got != "alicloud-ram:"+alicloudRoleARN {
		t.Errorf("warden_resource = %v, want the role the exchange targets", got)
	}
	exp, ok := claims["exp"].(float64)
	if !ok || time.Unix(int64(exp), 0).Before(time.Now()) {
		t.Errorf("exp = %v, want a time in the future", claims["exp"])
	}
}

// A keyless source mints only from a caller assertion, so a spec that does not ask
// for one has no way to mint. The spec-create test-mint is what catches it.
func TestAlicloudKeyless_NonExchangeSpecIsRefusedAtCreate(t *testing.T) {
	leader := h.GetLeaderPort(t)
	sts := startAlicloudSTSStub(t)
	setupAlicloudKeyless(t, leader, sts.URL)

	const name = "e2e-alicloud-non-exchange"
	t.Cleanup(func() { h.APIRequest(t, "DELETE", "sys/cred/specs/"+name, h.GetLeaderPort(t), "") })

	status, body := h.APIRequest(t, "POST", "sys/cred/specs/"+name, leader, mustJSON(t, map[string]any{
		"type":   "alicloud_keys",
		"source": alicloudSourceName,
		"config": map[string]string{
			"mint_method": "assume_role",
			"role_arn":    alicloudRoleARN,
		},
	}))

	if status == 200 || status == 201 {
		t.Fatalf("a non-exchange spec on a keyless source was accepted (status %d)", status)
	}
	if !strings.Contains(string(body), "subject_token_source") {
		t.Errorf("refusal should name subject_token_source, got: %s", string(body))
	}
}

// A federated source holds no secret of its own, so a rotation_period could never
// be honoured — the manager would retry, park the entry as failed, and come back
// hourly for the life of the source. Refusing at create is what keeps that entry
// from existing.
func TestAlicloudKeyless_RotationPeriodRefusedOnKeylessSource(t *testing.T) {
	leader := h.GetLeaderPort(t)
	sts := startAlicloudSTSStub(t)

	const name = "e2e-alicloud-rotating"
	t.Cleanup(func() { h.APIRequest(t, "DELETE", "sys/cred/sources/"+name, h.GetLeaderPort(t), "") })

	status, body := h.APIRequest(t, "POST", "sys/cred/sources/"+name, leader, mustJSON(t, map[string]any{
		"type":            "alicloud",
		"rotation_period": 86400,
		"config": map[string]string{
			"auth_method":       "oidc_federation",
			"oidc_provider_arn": alicloudProviderARN,
			"audience":          alicloudAudience,
			"sts_endpoint":      sts.URL,
			"tls_skip_verify":   "true",
		},
	}))

	if status == 200 || status == 201 {
		t.Fatalf("a keyless source was accepted with a rotation_period (status %d)", status)
	}
	if !strings.Contains(string(body), "rotation_period") {
		t.Errorf("refusal should name rotation_period, got: %s", string(body))
	}
}

// The static and keyless shapes are mutually exclusive: a source carrying both is
// half-converted, and which half wins would be silent.
func TestAlicloudKeyless_MixedConfigIsRefused(t *testing.T) {
	leader := h.GetLeaderPort(t)

	const name = "e2e-alicloud-mixed"
	t.Cleanup(func() { h.APIRequest(t, "DELETE", "sys/cred/sources/"+name, h.GetLeaderPort(t), "") })

	status, body := h.APIRequest(t, "POST", "sys/cred/sources/"+name, leader, mustJSON(t, map[string]any{
		"type": "alicloud",
		"config": map[string]string{
			"auth_method":       "oidc_federation",
			"oidc_provider_arn": alicloudProviderARN,
			"access_key_id":     "LTAI-e2e-not-a-real-key",
			"access_key_secret": "e2e-not-a-real-secret",
		},
	}))

	if status == 200 || status == 201 {
		t.Fatalf("a source carrying both a key pair and federation config was accepted (status %d)", status)
	}
	if !strings.Contains(string(body), "access_key_id") {
		t.Errorf("refusal should name the offending field, got: %s", string(body))
	}
}
