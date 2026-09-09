package drivers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// secretManagerStub answers the Secret Manager access call, recording the resource it
// was asked for and the bearer that asked, so a test can tell which identity did the
// read and which version it addressed.
type secretManagerStub struct {
	*httptest.Server

	lastPath   atomic.Value // string: the version resource, without the :access suffix
	lastBearer atomic.Value // string
	payload    []byte
	corruptCRC bool
}

func newSecretManagerStub(t *testing.T, payload string) *secretManagerStub {
	t.Helper()
	s := &secretManagerStub{payload: []byte(payload)}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v1/")
		path = strings.TrimSuffix(path, ":access")
		s.lastPath.Store(path)
		s.lastBearer.Store(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))

		sum := crc32.Checksum(s.payload, crc32.MakeTable(crc32.Castagnoli))
		if s.corruptCRC {
			sum++
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"name": path,
			"payload": map[string]string{
				"data":       base64.StdEncoding.EncodeToString(s.payload),
				"dataCrc32c": strconv.FormatInt(int64(sum), 10),
			},
		})
	}))
	t.Cleanup(s.Close)
	return s
}

func secretSpec(cfg map[string]string) *credential.CredSpec {
	full := map[string]string{"mint_method": "secret_read"}
	for k, v := range cfg {
		full[k] = v
	}
	return &credential.CredSpec{Name: "secret-spec", Config: credential.NewConfig(full)}
}

// A chaining source is minted as the calling principal, which forces the exchange
// path, so this is the shape the feature actually runs in.
func newSecretReadFederationDriver(t *testing.T, stsURL, smURL, iamCredURL string) *GCPDriver {
	t.Helper()
	d := newFederationDriver(testWIFProvider, stsURL, iamCredURL)
	d.secretManagerHost = smURL
	return d
}

func gcpSTSStub(t *testing.T, token string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": token, "expires_in": 3600, "token_type": "Bearer",
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestResolveSecretVersionPath(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  map[string]string
		want string
	}{
		{
			name: "bare id with project reads the current version",
			cfg:  map[string]string{"secret_name": "datadog-keys", "project": "acme-prod"},
			want: "projects/acme-prod/secrets/datadog-keys/versions/latest",
		},
		{
			name: "qualified resource carries its own project",
			cfg:  map[string]string{"secret_name": "projects/acme-prod/secrets/datadog-keys"},
			want: "projects/acme-prod/secrets/datadog-keys/versions/latest",
		},
		{
			name: "a pinned version is addressed by number",
			cfg:  map[string]string{"secret_name": "datadog-keys", "project": "acme-prod", "secret_version": "3"},
			want: "projects/acme-prod/secrets/datadog-keys/versions/3",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveSecretVersionPath(secretSpec(tc.cfg), nil, nil)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	t.Run("a bare id without a project cannot be addressed", func(t *testing.T) {
		_, err := resolveSecretVersionPath(secretSpec(map[string]string{"secret_name": "datadog-keys"}), nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "project")
	})

	t.Run("resolves the agent principal", func(t *testing.T) {
		got, err := resolveSecretVersionPath(
			secretSpec(map[string]string{"secret_name": "per-agent-{{agent.sub}}", "project": "acme-prod"}),
			nil, map[string]string{"sub": "e2e-agent"})
		require.NoError(t, err)
		assert.Equal(t, "projects/acme-prod/secrets/per-agent-e2e-agent/versions/latest", got)
	})

	// Without claims a template would otherwise be sent literally, and a store will
	// happily return a secret actually named "per-agent-{{agent.sub}}" to whoever can
	// create one.
	t.Run("fails closed when there are no claims to resolve from", func(t *testing.T) {
		_, err := resolveSecretVersionPath(
			secretSpec(map[string]string{"secret_name": "per-agent-{{agent.sub}}", "project": "acme-prod"}), nil, nil)
		require.Error(t, err)
	})
}

// Secret Manager stores arbitrary bytes, so there is no single right shape. A flat
// object of strings is the multi-field secret a chained consumer reads by name;
// anything else is vended whole, because the key_value type keeps only string fields
// and admitting a nested document would silently drop part of it.
func TestParseSecretPayload(t *testing.T) {
	t.Run("object of scalars is vended under its own keys", func(t *testing.T) {
		got, err := parseSecretPayload([]byte(`{"api_key":"k1","port":5432,"tls":true}`))
		require.NoError(t, err)
		assert.Equal(t, map[string]interface{}{
			"api_key": "k1",
			"port":    "5432",
			"tls":     "true",
		}, got, "numbers render without a decimal point, as stored")
	})

	for name, payload := range map[string]string{
		"a plain api key":    "not-json-at-all",
		"a JSON array":       `["a","b"]`,
		"a bare JSON string": `"just-a-string"`,
		"a JSON number":      `12345`,
	} {
		t.Run(name+" is one opaque secret", func(t *testing.T) {
			got, err := parseSecretPayload([]byte(payload))
			require.NoError(t, err)
			assert.Equal(t, map[string]interface{}{"value": payload}, got)
		})
	}

	// A consuming spec naming no secret_field takes the sole key when there is only
	// one, so blobbing a document under "value" would send every secret stored beside
	// the wanted one upstream as the credential. Dropping the nested field instead
	// would be quietly lossy. Neither is acceptable, so the shape is refused.
	t.Run("a nested document is refused, not blobbed", func(t *testing.T) {
		for _, payload := range []string{
			`{"api_key":"k","meta":{"env":"prod"}}`,
			`{"api_key":"k","hosts":["a","b"]}`,
		} {
			_, err := parseSecretPayload([]byte(payload))
			require.Errorf(t, err, "%s must be refused", payload)
			assert.Contains(t, err.Error(), "nested")
		}
	})

	t.Run("a null field is refused", func(t *testing.T) {
		_, err := parseSecretPayload([]byte(`{"api_key":null}`))
		require.Error(t, err)
	})

	t.Run("an empty object carries no secret", func(t *testing.T) {
		_, err := parseSecretPayload([]byte(`{}`))
		require.Error(t, err)
	})
}

func TestGCPDriver_SecretRead_Federated(t *testing.T) {
	const payload = `{"api_key":"dd-key","application_key":"dd-app"}`

	t.Run("reads with the federated token and vends the payload", func(t *testing.T) {
		sm := newSecretManagerStub(t, payload)
		sts := gcpSTSStub(t, "FED-TOKEN")
		d := newSecretReadFederationDriver(t, sts.URL, sm.URL, "")

		data, meta, ttl, leaseID, err := d.MintCredentialWithExchange(context.TODO(),
			secretSpec(map[string]string{"secret_name": "datadog-keys", "project": "acme-prod"}),
			&credential.ExchangeInputs{SubjectToken: "caller-assertion"})
		require.NoError(t, err)

		assert.Equal(t, map[string]interface{}{"api_key": "dd-key", "application_key": "dd-app"}, data)
		assert.Nil(t, meta)
		assert.Zero(t, ttl, "a stored secret does not expire")
		assert.Empty(t, leaseID, "a stored secret holds no lease")

		assert.Equal(t, "projects/acme-prod/secrets/datadog-keys/versions/latest", sm.lastPath.Load())
		assert.Equal(t, "FED-TOKEN", sm.lastBearer.Load(), "the read must use the caller's federated token")
	})

	t.Run("impersonates when the spec names a service account", func(t *testing.T) {
		sm := newSecretManagerStub(t, payload)
		sts := gcpSTSStub(t, "FED-TOKEN")

		var impersonationBearer atomic.Value
		iamCred := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			impersonationBearer.Store(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"accessToken": "IMPERSONATED"})
		}))
		defer iamCred.Close()

		d := newSecretReadFederationDriver(t, sts.URL, sm.URL, iamCred.URL)

		_, _, _, _, err := d.MintCredentialWithExchange(context.TODO(),
			secretSpec(map[string]string{
				"secret_name": "datadog-keys", "project": "acme-prod",
				"target_service_account": "reader@acme-prod.iam.gserviceaccount.com",
			}),
			&credential.ExchangeInputs{SubjectToken: "caller-assertion"})
		require.NoError(t, err)

		assert.Equal(t, "FED-TOKEN", impersonationBearer.Load(), "the federated token authorizes the impersonation")
		assert.Equal(t, "IMPERSONATED", sm.lastBearer.Load(), "the impersonated token performs the read")
	})

	t.Run("a templated name resolves from the caller's claims", func(t *testing.T) {
		sm := newSecretManagerStub(t, payload)
		sts := gcpSTSStub(t, "FED-TOKEN")
		d := newSecretReadFederationDriver(t, sts.URL, sm.URL, "")

		_, _, _, _, err := d.MintCredentialWithExchange(context.TODO(),
			secretSpec(map[string]string{"secret_name": "per-agent-{{agent.sub}}", "project": "acme-prod"}),
			&credential.ExchangeInputs{
				SubjectToken: "caller-assertion",
				AgentClaims:  map[string]string{"sub": "e2e-agent"},
			})
		require.NoError(t, err)
		assert.Equal(t, "projects/acme-prod/secrets/per-agent-e2e-agent/versions/latest", sm.lastPath.Load())
	})

	t.Run("json_key_map projects the payload", func(t *testing.T) {
		sm := newSecretManagerStub(t, payload)
		sts := gcpSTSStub(t, "FED-TOKEN")
		d := newSecretReadFederationDriver(t, sts.URL, sm.URL, "")

		data, _, _, _, err := d.MintCredentialWithExchange(context.TODO(),
			secretSpec(map[string]string{
				"secret_name": "datadog-keys", "project": "acme-prod",
				"json_key_map": "api_key=token",
			}),
			&credential.ExchangeInputs{SubjectToken: "caller-assertion"})
		require.NoError(t, err)
		assert.Equal(t, map[string]interface{}{"token": "dd-key"}, data,
			"a selection vends exactly the fields it names")
	})

	t.Run("a projection selecting nothing is an error, not an empty credential", func(t *testing.T) {
		sm := newSecretManagerStub(t, payload)
		sts := gcpSTSStub(t, "FED-TOKEN")
		d := newSecretReadFederationDriver(t, sts.URL, sm.URL, "")

		_, _, _, _, err := d.MintCredentialWithExchange(context.TODO(),
			secretSpec(map[string]string{
				"secret_name": "datadog-keys", "project": "acme-prod",
				"json_key_map": "absent=token",
			}),
			&credential.ExchangeInputs{SubjectToken: "caller-assertion"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "json_key_map")
	})

	t.Run("a payload failing its checksum is refused", func(t *testing.T) {
		sm := newSecretManagerStub(t, payload)
		sm.corruptCRC = true
		sts := gcpSTSStub(t, "FED-TOKEN")
		d := newSecretReadFederationDriver(t, sts.URL, sm.URL, "")

		_, _, _, _, err := d.MintCredentialWithExchange(context.TODO(),
			secretSpec(map[string]string{"secret_name": "datadog-keys", "project": "acme-prod"}),
			&credential.ExchangeInputs{SubjectToken: "caller-assertion"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "integrity")
	})

	t.Run("a plain secret is vended under value", func(t *testing.T) {
		sm := newSecretManagerStub(t, "sk-plain-api-key")
		sts := gcpSTSStub(t, "FED-TOKEN")
		d := newSecretReadFederationDriver(t, sts.URL, sm.URL, "")

		data, _, _, _, err := d.MintCredentialWithExchange(context.TODO(),
			secretSpec(map[string]string{"secret_name": "openai", "project": "acme-prod"}),
			&credential.ExchangeInputs{SubjectToken: "caller-assertion"})
		require.NoError(t, err)
		assert.Equal(t, map[string]interface{}{"value": "sk-plain-api-key"}, data)
	})
}

func TestGCPDriver_SecretRead_Static(t *testing.T) {
	const payload = `{"api_key":"dd-key"}`

	t.Run("reads as the source itself", func(t *testing.T) {
		sm := newSecretManagerStub(t, payload)
		grant := tokenGrantServer(t, 3600)

		d := newStaticGCPDriver(t, grant.URL, newTestGCPSAKey(t, grant.URL+"/token", "sa@test-project.iam.gserviceaccount.com"))
		d.secretManagerHost = sm.URL

		data, _, ttl, _, err := d.MintCredential(context.TODO(),
			secretSpec(map[string]string{"secret_name": "datadog-keys", "project": "acme-prod"}))
		require.NoError(t, err)
		assert.Equal(t, map[string]interface{}{"api_key": "dd-key"}, data)
		assert.Zero(t, ttl)
	})

	// Nothing on a static request was verified into claims, so a template has nothing
	// to resolve from and must not be sent literally.
	t.Run("a templated name fails closed", func(t *testing.T) {
		sm := newSecretManagerStub(t, payload)
		grant := tokenGrantServer(t, 3600)

		d := newStaticGCPDriver(t, grant.URL, newTestGCPSAKey(t, grant.URL+"/token", "sa@test-project.iam.gserviceaccount.com"))
		d.secretManagerHost = sm.URL

		_, _, _, _, err := d.MintCredential(context.TODO(),
			secretSpec(map[string]string{"secret_name": "per-agent-{{agent.sub}}", "project": "acme-prod"}))
		require.Error(t, err)
		assert.Nil(t, sm.lastPath.Load(), "no read may be attempted with an unresolved name")
	})

	// Impersonation is authorized by the caller's own assertion, which a static source
	// does not have. Reading as the source instead would vend the secret under an
	// authority the operator did not name.
	t.Run("target_service_account is refused", func(t *testing.T) {
		grant := tokenGrantServer(t, 3600)
		d := newStaticGCPDriver(t, grant.URL, newTestGCPSAKey(t, grant.URL+"/token", "sa@test-project.iam.gserviceaccount.com"))

		_, _, _, _, err := d.MintCredential(context.TODO(),
			secretSpec(map[string]string{
				"secret_name": "datadog-keys", "project": "acme-prod",
				"target_service_account": "reader@acme-prod.iam.gserviceaccount.com",
			}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "target_service_account")
	})
}

func TestGCPDriver_SecretRead_PayloadBounds(t *testing.T) {
	t.Run("an empty payload is refused", func(t *testing.T) {
		sm := newSecretManagerStub(t, "")
		sts := gcpSTSStub(t, "FED-TOKEN")
		d := newSecretReadFederationDriver(t, sts.URL, sm.URL, "")

		_, _, _, _, err := d.MintCredentialWithExchange(context.TODO(),
			secretSpec(map[string]string{"secret_name": "s", "project": "p"}),
			&credential.ExchangeInputs{SubjectToken: "a"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})

	// The 64KiB ceiling is on the decoded payload. Base64 inside the JSON envelope
	// makes the body half again as large, so bounding the body at 64KiB would have
	// truncated any secret past roughly 48KiB.
	t.Run("a secret at the documented ceiling still reads", func(t *testing.T) {
		sm := newSecretManagerStub(t, strings.Repeat("x", gcpMaxSecretPayloadSize))
		sts := gcpSTSStub(t, "FED-TOKEN")
		d := newSecretReadFederationDriver(t, sts.URL, sm.URL, "")

		data, _, _, _, err := d.MintCredentialWithExchange(context.TODO(),
			secretSpec(map[string]string{"secret_name": "s", "project": "p"}),
			&credential.ExchangeInputs{SubjectToken: "a"})
		require.NoError(t, err)
		assert.Len(t, data["value"], gcpMaxSecretPayloadSize)
	})
}

func TestGCPDriver_SecretRead_InferenceAndAssertionResource(t *testing.T) {
	f := &GCPDriverFactory{}

	got, err := f.InferCredentialType(credential.NewConfig(map[string]string{"mint_method": "secret_read"}))
	require.NoError(t, err)
	assert.Equal(t, credential.TypeKeyValue, got)

	res, ok := gcpAssertionResource(
		credential.NewConfig(map[string]string{
			"auth_method":                gcpAuthMethodOIDCFederation,
			"workload_identity_provider": testWIFProvider,
		}),
		credential.NewConfig(map[string]string{"mint_method": "secret_read", "secret_name": "datadog-keys"}),
	)
	require.True(t, ok)
	assert.Equal(t, "gcp-secretmanager:datadog-keys", res)

	// Carried unresolved, like every templated coordinate here: this runs before the
	// exchange that would produce the claims to resolve it from.
	res, ok = gcpAssertionResource(
		credential.NewConfig(map[string]string{
			"auth_method":                gcpAuthMethodOIDCFederation,
			"workload_identity_provider": testWIFProvider,
		}),
		credential.NewConfig(map[string]string{"mint_method": "secret_read", "secret_name": "per-agent-{{agent.sub}}"}),
	)
	require.True(t, ok)
	assert.Equal(t, "gcp-secretmanager:per-agent-{{agent.sub}}", res)
}

func TestVerifySecretCRC32C(t *testing.T) {
	payload := []byte("some-secret")
	sum := strconv.FormatInt(int64(crc32.Checksum(payload, crc32.MakeTable(crc32.Castagnoli))), 10)

	require.NoError(t, verifySecretCRC32C(payload, sum))
	require.Error(t, verifySecretCRC32C([]byte("tampered"), sum))

	// The checksum is optional, and refusing a secret because the service omitted it
	// would fail closed on something carrying no evidence of corruption.
	require.NoError(t, verifySecretCRC32C(payload, ""))

	// One that is present but unreadable is the opposite case: the envelope is
	// demonstrably not what the service sends, which is what this guards against.
	require.Error(t, verifySecretCRC32C(payload, "not-a-number"))
	require.Error(t, verifySecretCRC32C(payload, "-1"))
	require.Error(t, verifySecretCRC32C(payload, "4294967296"))
}

func TestGCPDriver_SecretRead_EndpointOverrideDefaults(t *testing.T) {
	sm := newSecretManagerStub(t, `{"k":"v"}`)

	f := &GCPDriverFactory{}
	require.NoError(t, f.ValidateConfig(credential.NewConfig(map[string]string{
		"auth_method":                gcpAuthMethodOIDCFederation,
		"workload_identity_provider": testWIFProvider,
		"secretmanager_endpoint":     sm.URL,
	})))

	// Rotation manages real keys, which no endpoint override redirects.
	err := f.ValidateRotationConfig(credential.NewConfig(map[string]string{"secretmanager_endpoint": sm.URL}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secretmanager_endpoint")
}

// A trailing slash on the override must not produce a doubled separator in the URL.
func TestGCPDriver_SecretManagerHostTrimsTrailingSlash(t *testing.T) {
	sm := newSecretManagerStub(t, `{"k":"v"}`)
	sts := gcpSTSStub(t, "FED-TOKEN")

	d := newSecretReadFederationDriver(t, sts.URL, strings.TrimRight(sm.URL, "/"), "")
	_, _, _, _, err := d.MintCredentialWithExchange(context.TODO(),
		secretSpec(map[string]string{"secret_name": "s", "project": "p"}),
		&credential.ExchangeInputs{SubjectToken: "a"})
	require.NoError(t, err)
	assert.Equal(t, "projects/p/secrets/s/versions/latest", sm.lastPath.Load())
}

// A locator becomes segments of the request path. Unescaped, a name carrying "#"
// truncates the request — reading a different version than the spec names, while
// defeating the write-time rule against addressing two — and one carrying "?" moves
// the version into a query string, turning the read into a different call. The
// write-time charset checks make these unwritable; escaping means a config that
// drifted past them still cannot reshape the request.
func TestResolveSecretVersionPath_EscapesEverySegment(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  map[string]string
	}{
		{"fragment truncation", map[string]string{"secret_name": "keys/versions/2:access#", "project": "p"}},
		{"query injection", map[string]string{"secret_name": "keys?alt=media", "project": "p"}},
		{"traversal", map[string]string{"secret_name": "../../other", "project": "p"}},
		{"project fragment", map[string]string{"secret_name": "keys", "project": "p#x"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveSecretVersionPath(secretSpec(tc.cfg), nil, nil)
			require.NoError(t, err)
			for _, unsafe := range []string{"#", "?"} {
				assert.NotContainsf(t, got, unsafe, "%q must not survive into the path: %s", unsafe, got)
			}
			assert.True(t, strings.HasSuffix(got, "/versions/latest"),
				"the version this spec addresses must not be reachable from the name: %s", got)
		})
	}
}

// A qualified name is split on its own separators, so the project it carries is the
// one used — and a malformed one is refused rather than silently reshaped.
func TestResolveSecretVersionPath_QualifiedName(t *testing.T) {
	got, err := resolveSecretVersionPath(
		secretSpec(map[string]string{"secret_name": "projects/acme/secrets/dd-keys"}), nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "projects/acme/secrets/dd-keys/versions/latest", got)

	for _, bad := range []string{"projects/acme/secrets/", "projects//secrets/x", "projects/acme/dd"} {
		_, err := resolveSecretVersionPath(secretSpec(map[string]string{"secret_name": bad}), nil, nil)
		require.Errorf(t, err, "%q must be refused", bad)
	}
}
