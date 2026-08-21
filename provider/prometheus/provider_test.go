package prometheus

import (
	"net/http"
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func apiKeyRequest(key string) *logical.Request {
	return &logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{"api_key": key},
		},
	}
}

func TestPrometheusExtractor_Bearer_Default(t *testing.T) {
	headers, err := prometheusExtractor(authTypeBearer)(apiKeyRequest("my-bearer-token"))
	require.NoError(t, err)
	assert.Equal(t, "Bearer my-bearer-token", headers["Authorization"])
}

// An unset scheme is bearer: stateAuthType defaults, and an extractor built with
// an empty string must not fall through to some third behaviour.
func TestPrometheusExtractor_UnsetSchemeIsBearer(t *testing.T) {
	headers, err := prometheusExtractor("")(apiKeyRequest("my-bearer-token"))
	require.NoError(t, err)
	assert.Equal(t, "Bearer my-bearer-token", headers["Authorization"])
}

func TestPrometheusExtractor_BasicAuth(t *testing.T) {
	// api_key is pre-encoded base64("admin:secret") = "YWRtaW46c2VjcmV0"
	headers, err := prometheusExtractor(authTypeBasic)(apiKeyRequest("YWRtaW46c2VjcmV0"))
	require.NoError(t, err)
	assert.Equal(t, "Basic YWRtaW46c2VjcmV0", headers["Authorization"])
}

func TestPrometheusExtractor_NoCredential(t *testing.T) {
	_, err := prometheusExtractor(authTypeBearer)(&logical.Request{})
	assert.ErrorContains(t, err, "no credential available")
}

func TestPrometheusExtractor_WrongType(t *testing.T) {
	_, err := prometheusExtractor(authTypeBearer)(&logical.Request{
		Credential: &credential.Credential{Type: "vault_token"},
	})
	assert.ErrorContains(t, err, "unsupported credential type")
}

func TestPrometheusExtractor_MissingAPIKey(t *testing.T) {
	_, err := prometheusExtractor(authTypeBasic)(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{},
		},
	})
	assert.ErrorContains(t, err, "missing api_key")
}

// TestPrometheusExtractor_IgnoresCredentialAuthType pins that the scheme comes
// from the mount and nowhere else. auth_type used to be read from credential
// data, where nothing could set it; a credential still carrying the field must
// not resurrect that path.
func TestPrometheusExtractor_IgnoresCredentialAuthType(t *testing.T) {
	req := &logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{"api_key": "k", "auth_type": "basic"},
		},
	}
	headers, err := prometheusExtractor(authTypeBearer)(req)
	require.NoError(t, err)
	assert.Equal(t, "Bearer k", headers["Authorization"], "credential data must not select the scheme")
}

// TestResolveUpstream_SelectsSchemeFromState covers the wiring between mount
// config and the extractor actually used for a request.
func TestResolveUpstream_SelectsSchemeFromState(t *testing.T) {
	require.NotNil(t, Spec.ResolveUpstream)

	cases := []struct {
		name  string
		state map[string]any
		want  string
	}{
		{"unset defaults to bearer", map[string]any{}, "Bearer k"},
		{"bearer", map[string]any{"auth_type": authTypeBearer}, "Bearer k"},
		{"basic", map[string]any{"auth_type": authTypeBasic}, "Basic k"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, ok := Spec.ResolveUpstream(&http.Request{}, "", tc.state)
			require.True(t, ok)
			require.NotNil(t, d.ExtractCredentials)

			headers, err := d.ExtractCredentials(apiKeyRequest("k"))
			require.NoError(t, err)
			assert.Equal(t, tc.want, headers["Authorization"])
		})
	}
}

// TestValidateAuthType_RejectsTypos is the reason the enum is enforced by hand:
// framework.FieldSchema.AllowedValues only reaches the OpenAPI document, so
// without this a misspelt scheme would be stored and read back as bearer — the
// mount would speak the wrong scheme and say it was configured correctly.
func TestValidateAuthType_RejectsTypos(t *testing.T) {
	assert.NoError(t, validateAuthType(""))
	assert.NoError(t, validateAuthType(authTypeBearer))
	assert.NoError(t, validateAuthType(authTypeBasic))

	for _, bad := range []string{"basci", "Basic", "none", "digest"} {
		assert.ErrorContains(t, validateAuthType(bad), "auth_type must be", "value %q", bad)
	}
}

// Both write paths must reject it: OnConfigWrite guards a config write on a live
// mount, ValidateExtraConfig guards the config supplied at enable time.
func TestConfigWritePaths_RejectInvalidAuthType(t *testing.T) {
	require.NotNil(t, Spec.OnConfigWrite)
	require.NotNil(t, Spec.ValidateExtraConfig)

	fd := &framework.FieldData{
		Raw:    map[string]interface{}{"auth_type": "basci"},
		Schema: Spec.ExtraConfigFields,
	}
	_, err := Spec.OnConfigWrite(fd, map[string]any{})
	assert.ErrorContains(t, err, "auth_type must be")

	assert.ErrorContains(t, Spec.ValidateExtraConfig(map[string]any{"auth_type": "basci"}), "auth_type must be")
	assert.NoError(t, Spec.ValidateExtraConfig(map[string]any{"auth_type": authTypeBasic}))
	assert.NoError(t, Spec.ValidateExtraConfig(map[string]any{}), "an unset auth_type is the bearer default")
}

// A config write that does not mention auth_type must leave the stored one
// alone, rather than resetting the mount to bearer.
func TestOnConfigWrite_LeavesUnmentionedSchemeAlone(t *testing.T) {
	state := map[string]any{"auth_type": authTypeBasic}
	fd := &framework.FieldData{Raw: map[string]interface{}{}, Schema: Spec.ExtraConfigFields}

	got, err := Spec.OnConfigWrite(fd, state)
	require.NoError(t, err)
	assert.Equal(t, authTypeBasic, stateAuthType(got))
}

// OnInitialize applies mount-time config; OnConfigRead reports what is in force.
func TestConfigRoundTrip(t *testing.T) {
	require.NotNil(t, Spec.OnInitialize)
	require.NotNil(t, Spec.OnConfigRead)

	state := Spec.OnInitialize(map[string]any{"auth_type": authTypeBasic}, map[string]any{})
	assert.Equal(t, authTypeBasic, Spec.OnConfigRead(state)["auth_type"])

	empty := Spec.OnInitialize(map[string]any{}, map[string]any{})
	assert.Equal(t, authTypeBearer, Spec.OnConfigRead(empty)["auth_type"],
		"a mount that never set auth_type reads back as bearer, not empty")
}

func TestSpec(t *testing.T) {
	assert.Equal(t, "prometheus", Spec.Name)
	assert.Equal(t, "prometheus_url", Spec.URLConfigKey)
	assert.NotNil(t, Spec.ExtractCredentials)
	assert.Contains(t, Spec.ExtraConfigFields, "auth_type")
	assert.NotNil(t, Factory)
}
