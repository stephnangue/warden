package drivers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/helper"
)

// fakeJWT builds an unsigned three-segment token carrying claims. The driver only
// reads claims from it, never verifies it, so no signature is needed.
func fakeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + enc(payload) + "." + enc([]byte("sig"))
}

// fakeEntra answers every token request with status and body, recording the form.
type fakeEntra struct {
	mu     sync.Mutex
	srv    *httptest.Server
	forms  []url.Values
	paths  []string
	status int
	body   string
}

func newFakeEntra(t *testing.T, status int, body string) *fakeEntra {
	t.Helper()
	f := &fakeEntra{status: status, body: body}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.forms = append(f.forms, r.PostForm)
		f.paths = append(f.paths, r.URL.Path)
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.status)
		_, _ = w.Write([]byte(f.body))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeEntra) lastForm(t *testing.T) url.Values {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	require.NotEmpty(t, f.forms, "no request reached the fake Entra")
	return f.forms[len(f.forms)-1]
}

// oboSuccessBody is a realistic Entra OBO answer, including the refresh_token and
// id_token Entra returns unasked; neither may surface anywhere.
const oboSuccessBody = `{"token_type":"Bearer","scope":"https://graph.microsoft.com/User.Read","expires_in":3600,` +
	`"access_token":"eyJ.graph.token","refresh_token":"RT-must-not-leak","id_token":"IDT-must-not-leak"}`

func keylessOBODriver(loginHost string) *AzureDriver {
	return &AzureDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeAzure,
			Config: credential.NewConfig(map[string]string{"auth_method": "oidc_federation"})},
		httpClient: &http.Client{Timeout: 10 * time.Second},
		loginHost:  loginHost,
	}
}

func staticOBODriver(loginHost string) *AzureDriver {
	d := newTestAzureDriver()
	d.loginHost = loginHost
	return d
}

func oboSpec(extra map[string]string) *credential.CredSpec {
	cfg := map[string]string{
		"mint_method":          "on_behalf_of",
		"tenant_id":            testAzureTenant,
		"client_id":            testAzureClient,
		"subject_token_source": "user_identity",
	}
	for k, v := range extra {
		cfg[k] = v
	}
	return &credential.CredSpec{Name: "m365", Config: credential.NewConfig(cfg)}
}

func TestAzureOBO_Keyless_HappyPath(t *testing.T) {
	entra := newFakeEntra(t, http.StatusOK, oboSuccessBody)
	drv := keylessOBODriver(entra.srv.URL)

	userTok := fakeJWT(t, map[string]any{"oid": "user-oid-1", "sub": "pairwise-sub", "aud": testAzureClient})
	actorTok := fakeJWT(t, map[string]any{"sub": "wid:root:auth_jwt_1:agent-1", "aud": "api://AzureADTokenExchange"})
	inputs := &credential.ExchangeInputs{SubjectToken: userTok, ActorToken: actorTok}

	rawData, meta, ttl, leaseID, err := drv.MintCredentialWithExchange(context.Background(), oboSpec(nil), inputs)
	require.NoError(t, err)

	form := entra.lastForm(t)
	assert.Equal(t, oboGrantType, form.Get("grant_type"))
	assert.Equal(t, testAzureClient, form.Get("client_id"))
	assert.Equal(t, userTok, form.Get("assertion"), "the user's token is the OBO assertion")
	assert.Equal(t, "on_behalf_of", form.Get("requested_token_use"))
	assert.Equal(t, "https://graph.microsoft.com/.default", form.Get("scope"), "Graph is the default resource for on_behalf_of")
	assert.Equal(t, clientAssertionType, form.Get("client_assertion_type"))
	assert.Equal(t, actorTok, form.Get("client_assertion"), "Warden's assertion authenticates the app")
	assert.False(t, form.Has("client_secret"), "a keyless OBO request carries no secret")
	assert.Equal(t, "/"+testAzureTenant+"/oauth2/v2.0/token", entra.paths[0])

	assert.Equal(t, "eyJ.graph.token", rawData["access_token"])
	assert.Len(t, rawData, 1, "only the access token is vended")
	assert.Equal(t, time.Hour-oboRefreshBuffer, ttl)
	assert.Empty(t, leaseID)

	assert.Equal(t, "user-oid-1", meta["subject"], "the user is identified by oid, not sub")
	assert.Equal(t, "wid:root:auth_jwt_1:agent-1", meta["actor"], "the actor is the federated assertion's subject")
	assert.Equal(t, testAzureClient, meta["client_id"])
	assert.Equal(t, "true", meta["delegated"])
	_, err = helper.ToStringMap(meta)
	require.NoError(t, err, "the credential layer accepts string metadata only")

	everything := fmt.Sprint(rawData, meta)
	assert.NotContains(t, everything, "RT-must-not-leak")
	assert.NotContains(t, everything, "IDT-must-not-leak")
}

func TestAzureOBO_Static_HappyPath(t *testing.T) {
	entra := newFakeEntra(t, http.StatusOK, oboSuccessBody)
	drv := staticOBODriver(entra.srv.URL)

	userTok := fakeJWT(t, map[string]any{"sub": "only-sub"})
	_, meta, _, _, err := drv.MintCredentialWithExchange(context.Background(),
		oboSpec(map[string]string{"resource_uri": "https://graph.microsoft.com"}),
		&credential.ExchangeInputs{SubjectToken: userTok})
	require.NoError(t, err)

	form := entra.lastForm(t)
	assert.Equal(t, "test-secret", form.Get("client_secret"), "the source's secret authenticates the app")
	assert.False(t, form.Has("client_assertion"))
	assert.Equal(t, userTok, form.Get("assertion"))
	assert.Equal(t, "https://graph.microsoft.com/.default", form.Get("scope"))
	assert.Equal(t, "only-sub", meta["subject"], "sub is the fallback when there is no oid")
	_, hasActor := meta["actor"]
	assert.False(t, hasActor)
}

func TestAzureOBO_MaxTTLCapsLease(t *testing.T) {
	entra := newFakeEntra(t, http.StatusOK, oboSuccessBody)
	spec := oboSpec(nil)
	spec.MaxTTL = 10 * time.Minute
	_, _, ttl, _, err := keylessOBODriver(entra.srv.URL).MintCredentialWithExchange(context.Background(), spec,
		&credential.ExchangeInputs{SubjectToken: "u.t.k", ActorToken: "a.t.k"})
	require.NoError(t, err)
	assert.Equal(t, 10*time.Minute, ttl)
}

func TestAzureOBO_Guards(t *testing.T) {
	ctx := context.Background()
	unreachable := unreachableAzureHost

	// No user token: ErrUserRequired, so the caller is told to present a user.
	_, _, _, _, err := keylessOBODriver(unreachable).MintCredentialWithExchange(ctx, oboSpec(nil), &credential.ExchangeInputs{})
	require.Error(t, err)
	assert.ErrorIs(t, err, credential.ErrUserRequired)
	_, _, _, _, err = keylessOBODriver(unreachable).MintCredentialWithExchange(ctx, oboSpec(nil), nil)
	assert.ErrorIs(t, err, credential.ErrUserRequired)

	// Keyless source without an actor assertion.
	_, _, _, _, err = keylessOBODriver(unreachable).MintCredentialWithExchange(ctx, oboSpec(nil),
		&credential.ExchangeInputs{SubjectToken: "u.t.k"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "actor_token_source=warden_identity")

	// The user's token can never double as the client credential.
	_, _, _, _, err = keylessOBODriver(unreachable).MintCredentialWithExchange(ctx, oboSpec(nil),
		&credential.ExchangeInputs{SubjectToken: "same.t.k", ActorToken: "same.t.k"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "identical")

	// Static source: no actor, and only the source's own app and tenant.
	_, _, _, _, err = staticOBODriver(unreachable).MintCredentialWithExchange(ctx, oboSpec(nil),
		&credential.ExchangeInputs{SubjectToken: "u.t.k", ActorToken: "a.t.k"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "remove actor_token_source")

	_, _, _, _, err = staticOBODriver(unreachable).MintCredentialWithExchange(ctx,
		oboSpec(map[string]string{"client_id": "33333333-3333-3333-3333-333333333333"}),
		&credential.ExchangeInputs{SubjectToken: "u.t.k"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "source's own app")

	_, _, _, _, err = staticOBODriver(unreachable).MintCredentialWithExchange(ctx,
		oboSpec(map[string]string{"tenant_id": "00000000-0000-0000-0000-000000000009"}),
		&credential.ExchangeInputs{SubjectToken: "u.t.k"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "source's tenant")

	// The plain mint path has no user to act for.
	_, _, _, _, err = staticOBODriver(unreachable).MintCredential(ctx, oboSpec(nil))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "subject_token_source=user_identity")
}

func TestAzureOBO_ErrorClassification(t *testing.T) {
	claims := `{"access_token":{"polids":{"essential":true,"values":["00aa00aa-bb11-cc22-dd33-44ee44ee44ee"]}}}`
	claimsJSON, _ := json.Marshal(claims)
	desc := `"error_description":"AADSTS50079: user jane@contoso.com must enroll\r\nTrace ID: x"`

	tests := []struct {
		name          string
		status        int
		body          string
		static        bool
		wantChallenge string // "" when not a user challenge
		wantClaims    bool
		wantMsg       string
		wantStatus    int
	}{
		{
			name:   "claims challenge",
			status: http.StatusBadRequest,
			body: `{"error":"interaction_required",` + desc + `,"error_codes":[50079],` +
				`"trace_id":"0000aaaa-11bb-cccc-dd22-eeeeee333333","claims":` + string(claimsJSON) + `}`,
			wantChallenge: credential.UserChallengeInsufficientClaims, wantClaims: true, wantStatus: 400,
		},
		{
			name:          "interaction required without claims",
			status:        http.StatusBadRequest,
			body:          `{"error":"interaction_required","error_codes":[50076]}`,
			wantChallenge: credential.UserChallengeInvalidToken, wantStatus: 400,
		},
		{
			// Observed in the Step 0 spike: a user token minted for Graph, not the app.
			name:          "user token for another audience",
			status:        http.StatusBadRequest,
			body:          `{"error":"invalid_grant","error_codes":[50013]}`,
			wantChallenge: credential.UserChallengeInvalidToken, wantStatus: 400,
		},
		{
			name:          "expired user token",
			status:        http.StatusBadRequest,
			body:          `{"error":"invalid_grant","error_codes":[500133]}`,
			wantChallenge: credential.UserChallengeInvalidToken, wantStatus: 400,
		},
		{
			// The same code under invalid_client is the client assertion's lifetime:
			// Warden's to fix, and re-authenticating the user would only loop.
			name:    "expired client assertion",
			status:  http.StatusUnauthorized,
			body:    `{"error":"invalid_client","error_codes":[500133]}`,
			wantMsg: "refused Warden's federated credential", wantStatus: 401,
		},
		{
			name:    "consent missing",
			status:  http.StatusBadRequest,
			body:    `{"error":"invalid_grant","suberror":"consent_required","error_codes":[65001]}`,
			wantMsg: "admin consent is missing", wantStatus: 400,
		},
		{
			// Observed in the Step 0 spike: a client assertion whose subject no FIC names.
			name:    "federated credential subject mismatch",
			status:  http.StatusUnauthorized,
			body:    `{"error":"invalid_client","error_codes":[700213]}`,
			wantMsg: "refused Warden's federated credential", wantStatus: 401,
		},
		{
			name:    "federated credential not yet propagated",
			status:  http.StatusBadRequest,
			body:    `{"error":"invalid_client","error_codes":[70021]}`,
			wantMsg: "refused Warden's federated credential", wantStatus: 400,
		},
		{
			name:    "bad client secret",
			status:  http.StatusUnauthorized,
			body:    `{"error":"invalid_client","error_codes":[7000215]}`,
			static:  true,
			wantMsg: "refused the client secret", wantStatus: 401,
		},
		{
			name:    "unparseable refusal",
			status:  http.StatusBadRequest,
			body:    `<html>proxy says no</html>`,
			wantMsg: "on-behalf-of token request refused", wantStatus: 400,
		},
		{
			name:    "throttled",
			status:  http.StatusTooManyRequests,
			body:    `{"error":"temporarily_unavailable"}`,
			wantMsg: "status 429", wantStatus: 429,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entra := newFakeEntra(t, tc.status, tc.body)
			var drv *AzureDriver
			inputs := &credential.ExchangeInputs{SubjectToken: "u.t.k"}
			if tc.static {
				drv = staticOBODriver(entra.srv.URL)
			} else {
				drv = keylessOBODriver(entra.srv.URL)
				inputs.ActorToken = "a.t.k"
			}
			_, _, _, _, err := drv.MintCredentialWithExchange(context.Background(), oboSpec(nil), inputs)
			require.Error(t, err)

			status, ok := credential.UpstreamStatus(err)
			require.True(t, ok, "the upstream status must stay reachable")
			assert.Equal(t, tc.wantStatus, status)

			var uce *credential.UserChallengeError
			if tc.wantChallenge != "" {
				require.True(t, errors.As(err, &uce), "want a user challenge, got %v", err)
				assert.ErrorIs(t, err, credential.ErrUserChallenge)
				assert.Equal(t, tc.wantChallenge, uce.Code)
				assert.Equal(t, testAzureTenant, uce.TenantID)
				if tc.wantClaims {
					assert.JSONEq(t, claims, uce.Claims)
				} else {
					assert.Empty(t, uce.Claims)
				}
			} else {
				assert.False(t, errors.As(err, &uce), "not a user challenge: %v", err)
				assert.Contains(t, err.Error(), tc.wantMsg)
			}

			// Nothing Entra wrote as free text, and no token bytes, reach the error.
			msg := err.Error()
			assert.NotContains(t, msg, "jane@contoso.com")
			assert.NotContains(t, msg, "\r")
			assert.NotContains(t, msg, "u.t.k")
			assert.NotContains(t, msg, "a.t.k")
			assert.NotContains(t, msg, "proxy says no")
		})
	}
}

// A refusal carrying an implausible number of codes is cut, so it cannot swell
// the error string that reaches logs, audit and the client.
func TestAzureOBO_ErrorCodesCapped(t *testing.T) {
	codes := make([]string, 5000)
	for i := range codes {
		codes[i] = "123456"
	}
	entra := newFakeEntra(t, http.StatusBadRequest, `{"error":"invalid_grant","error_codes":[`+strings.Join(codes, ",")+`]}`)
	_, _, _, _, err := keylessOBODriver(entra.srv.URL).MintCredentialWithExchange(context.Background(), oboSpec(nil),
		&credential.ExchangeInputs{SubjectToken: "u.t.k", ActorToken: "a.t.k"})
	require.Error(t, err)
	assert.Equal(t, maxEntraErrorCodes, strings.Count(err.Error(), "AADSTS"))
}

func TestAzureOBO_UnsafeErrorFieldsDropped(t *testing.T) {
	entra := newFakeEntra(t, http.StatusBadRequest,
		`{"error":"invalid grant\r\nX-Injected: 1","error_codes":[1],"trace_id":"abc\r\ndef","correlation_id":"ok-123","claims":"not json"}`)
	_, _, _, _, err := keylessOBODriver(entra.srv.URL).MintCredentialWithExchange(context.Background(), oboSpec(nil),
		&credential.ExchangeInputs{SubjectToken: "u.t.k", ActorToken: "a.t.k"})
	require.Error(t, err)
	msg := err.Error()
	assert.NotContains(t, msg, "X-Injected")
	assert.NotContains(t, msg, "\n")
	assert.Contains(t, msg, "correlation_id=ok-123")
	var uce *credential.UserChallengeError
	assert.False(t, errors.As(err, &uce), "invalid claims JSON is not a claims challenge")
}

func TestAzureOBO_InferAndResource(t *testing.T) {
	typ, err := (&AzureDriverFactory{}).InferCredentialType(credential.NewConfig(map[string]string{"mint_method": "on_behalf_of"}))
	require.NoError(t, err)
	assert.Equal(t, credential.TypeAzureBearerToken, typ)

	res, ok := azureAssertionResource(credential.NewConfig(map[string]string{"mint_method": "on_behalf_of"}))
	require.True(t, ok)
	assert.Equal(t, "azure:"+graphResource, res)

	res, ok = azureAssertionResource(credential.NewConfig(map[string]string{
		"mint_method": "on_behalf_of", "resource_uri": "https://contoso.sharepoint.com/",
	}))
	require.True(t, ok)
	assert.True(t, strings.HasSuffix(res, "contoso.sharepoint.com/"))
}
