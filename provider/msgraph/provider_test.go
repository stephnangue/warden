package msgraph

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

func TestCheckGraphURL(t *testing.T) {
	for _, ok := range []string{
		"https://graph.microsoft.com",
		"https://graph.microsoft.com/",
		"https://GRAPH.microsoft.com",
		"https://graph.microsoft.us",
		"https://dod-graph.microsoft.us",
		"https://microsoftgraph.chinacloudapi.cn",
	} {
		assert.NoError(t, checkGraphURL(ok, defaultGraphHosts), ok)
	}
	for _, bad := range []string{
		"http://graph.microsoft.com",
		"https://evil.example",
		"https://graph.microsoft.com.evil.example",
		"https://graph.microsoft.com/v1.0",
		"https://user:pw@graph.microsoft.com",
		"https://graph.microsoft.com?x=1",
		"https://graph.microsoft.com:8443",
		"https://graph.microsoft.com:443",
		"graph.microsoft.com",
		"",
	} {
		assert.Error(t, checkGraphURL(bad, defaultGraphHosts), bad)
	}
}

// graph_url can only name a Graph host, at mount time and on every config write:
// the mount sends every user's delegated token there.
func TestGraphURLAllowList_Config(t *testing.T) {
	require.NoError(t, Spec.ValidateExtraConfig(map[string]any{"graph_url": "https://graph.microsoft.us"}))
	require.NoError(t, Spec.ValidateExtraConfig(map[string]any{}))
	require.Error(t, Spec.ValidateExtraConfig(map[string]any{"graph_url": "https://evil.example"}))

	write := func(v string) error {
		_, err := Spec.OnConfigWrite(&framework.FieldData{
			Raw:    map[string]any{"graph_url": v},
			Schema: map[string]*framework.FieldSchema{"graph_url": {Type: framework.TypeString}},
		}, map[string]any{})
		return err
	}
	assert.NoError(t, write("https://graph.microsoft.com"))
	assert.Error(t, write("https://evil.example"))
	assert.Error(t, write("http://graph.microsoft.com"))

	_, err := Spec.OnConfigWrite(&framework.FieldData{Raw: map[string]any{}, Schema: map[string]*framework.FieldSchema{}}, map[string]any{})
	assert.NoError(t, err, "a write that leaves graph_url alone is not refused")
}

func refuse(t *testing.T, spec *httpproxy.ProviderSpec, method, path, providerURL string) (int, error) {
	t.Helper()
	return spec.RefuseRequest(httptest.NewRequest(method, path, nil), providerURL, nil)
}

func TestRefuseRequest(t *testing.T) {
	// $batch in any spelling, whatever policy allowed.
	for _, p := range []string{
		"/v1/msgraph/role/r/gateway/v1.0/$batch",
		"/v1/msgraph/gateway/beta/$batch",
		"/v1/msgraph/gateway/V1.0/$Batch/",
		"/v1/msgraph/gateway/v1.0/me/../$batch",
		"/v1/msgraph/gateway/v1.0/%24batch",
	} {
		status, err := refuse(t, Spec, http.MethodPost, p, DefaultGraphURL)
		assert.Equal(t, http.StatusBadRequest, status, p)
		assert.ErrorIs(t, err, errBatchNotSupported, p)
	}

	status, err := refuse(t, Spec, http.MethodGet, "/v1/msgraph/gateway/v1.0/me/messages", DefaultGraphURL)
	assert.NoError(t, err)
	assert.Zero(t, status)

	// An upstream that is not Graph is refused per request too, whatever put it there.
	status, err = refuse(t, Spec, http.MethodGet, "/v1/msgraph/gateway/v1.0/me", "https://evil.example")
	assert.Equal(t, http.StatusInternalServerError, status)
	assert.ErrorIs(t, err, errUpstreamNotTrusted)

	// A spec built for a test host accepts it, and only it.
	local := newSpec(append([]string{"127.0.0.1"}, defaultGraphHosts...))
	_, err = refuse(t, local, http.MethodGet, "/v1/msgraph/gateway/v1.0/me", "https://127.0.0.1:8443")
	assert.NoError(t, err)
	_, err = refuse(t, Spec, http.MethodGet, "/v1/msgraph/gateway/v1.0/me", "https://127.0.0.1:8443")
	assert.Error(t, err)

	// The last trusted upstream is remembered, but a different one is checked
	// afresh rather than waved through.
	_, err = refuse(t, local, http.MethodGet, "/v1/msgraph/gateway/v1.0/me", "https://127.0.0.1:8443")
	assert.NoError(t, err)
	status, err = refuse(t, local, http.MethodGet, "/v1/msgraph/gateway/v1.0/me", "https://evil.example")
	assert.Equal(t, http.StatusInternalServerError, status)
	assert.ErrorIs(t, err, errUpstreamNotTrusted)
}

func TestResolveUpstream_BinaryTransfers(t *testing.T) {
	cases := []struct {
		method, path string
		bypass       bool
	}{
		{http.MethodPut, "/v1/msgraph/gateway/v1.0/me/drive/root:/a.pdf:/content", true},
		{http.MethodGet, "/v1/msgraph/gateway/v1.0/me/drive/items/1/content", true},
		{http.MethodGet, "/v1/msgraph/gateway/v1.0/me/photo/$value", true},
		{http.MethodGet, "/v1/msgraph/gateway/v1.0/me/messages/1/$value/", true},
		{http.MethodGet, "/v1/msgraph/gateway/v1.0/me/messages", false},
		{http.MethodPost, "/v1/msgraph/gateway/v1.0/me/sendMail", false},
	}
	for _, tc := range cases {
		d, ok := resolveUpstream(httptest.NewRequest(tc.method, tc.path, nil), DefaultGraphURL, nil)
		assert.Equal(t, tc.bypass, ok, tc.path)
		if tc.bypass {
			assert.True(t, d.BypassBodyParsing, tc.path)
			assert.True(t, d.SkipDefaultAccept, tc.path)
		}
	}
}

func TestExtractGraphToken(t *testing.T) {
	got, err := extractGraphToken(&logical.Request{Credential: &credential.Credential{
		Type: credential.TypeAzureBearerToken, Data: map[string]string{"access_token": "eyJ.obo"},
	}})
	require.NoError(t, err)
	assert.Equal(t, "Bearer eyJ.obo", got["Authorization"])

	got, err = extractGraphToken(&logical.Request{Credential: &credential.Credential{
		Type: credential.TypeOAuthBearerToken, Data: map[string]string{"api_key": "eyJ.oauth"},
	}})
	require.NoError(t, err)
	assert.Equal(t, "Bearer eyJ.oauth", got["Authorization"])

	_, err = extractGraphToken(&logical.Request{Credential: &credential.Credential{
		Type: credential.TypeAPIKey, Data: map[string]string{"api_key": "sk-x"},
	}})
	assert.Error(t, err, "a credential type Graph cannot take is refused")

	_, err = extractGraphToken(&logical.Request{Credential: &credential.Credential{
		Type: credential.TypeAzureBearerToken, Data: map[string]string{},
	}})
	assert.Error(t, err)

	_, err = extractGraphToken(&logical.Request{})
	assert.Error(t, err)
}

func decodeGraphError(t *testing.T, resp *logical.Response) graphError {
	t.Helper()
	var body graphErrorBody
	require.NoError(t, json.Unmarshal(resp.Body, &body))
	return body.Error
}

func TestRenderGraphError(t *testing.T) {
	cases := []struct {
		name     string
		failure  *logical.GatewayFailure
		wantCode string
	}{
		{"refused batch", &logical.GatewayFailure{Class: logical.GatewayFailureBadRequest, Status: 400, Err: errBatchNotSupported}, graphCodeBatchRefused},
		{"user must re-authenticate", &logical.GatewayFailure{Class: logical.GatewayFailureMint, Status: 401,
			Err: &logical.CredentialIssueError{Spec: "m365", Err: fmt.Errorf("mint: %w",
				&credential.UserChallengeError{Code: credential.UserChallengeInvalidToken})}}, graphCodeInvalidToken},
		{"consent missing", &logical.GatewayFailure{Class: logical.GatewayFailureMint, Status: 403,
			Err: &logical.CredentialIssueError{Spec: "m365", Err: errors.New("azure: admin consent is missing")}}, graphCodeDenied},
		{"policy denied", &logical.GatewayFailure{Class: logical.GatewayFailureDenied, Status: 403, Err: errors.New("permission denied")}, graphCodeDenied},
		{"unavailable", &logical.GatewayFailure{Class: logical.GatewayFailureUnavailable, Status: 503, Err: errors.New("try later")}, graphCodeUnavailable},
		{"internal", &logical.GatewayFailure{Class: logical.GatewayFailureInternal, Status: 401, Err: errors.New("credential unusable")}, graphCodeGeneral},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.failure.RequestID = "req-1"
			resp := renderGraphError(nil, tc.failure)
			require.NotNil(t, resp)
			assert.Equal(t, tc.failure.Status, resp.StatusCode, "the status stays Warden's")
			assert.Equal(t, "application/json", resp.Headers.Get("Content-Type"))
			assert.Equal(t, "req-1", resp.Headers.Get("request-id"))
			assert.Empty(t, resp.Headers.Values("WWW-Authenticate"), "core's challenge is never overwritten")

			ge := decodeGraphError(t, resp)
			assert.Equal(t, tc.wantCode, ge.Code)
			assert.True(t, strings.HasPrefix(ge.Message, "Warden: "))
			assert.Equal(t, "req-1", ge.InnerError.RequestID)
			assert.NotEmpty(t, ge.InnerError.Date)
		})
	}
}

func TestSkill(t *testing.T) {
	md := Skill()
	assert.True(t, strings.HasPrefix(md, "---\nname: msgraph\n"), "the skill name is the provider type")
	assert.Contains(t, md, "\nprovider: msgraph\n")
	assert.Contains(t, md, "\ncategory: provider-guide\n")
}
