package drivers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Each staging driver turns the config a staged PrepareRotation returned into
// the cleanup config its CleanupRotation reads, naming the staged credential.
// A wrong key here makes a discard delete nothing, or the wrong credential.
func TestStagedCleanupConfig(t *testing.T) {
	gcpKey := `{"type":"service_account","project_id":"proj","private_key_id":"new-kid","private_key":"k","client_email":"sa@proj.iam.gserviceaccount.com"}`

	cases := []struct {
		name      string
		discarder credential.StagedRotationDiscarder
		newConfig map[string]string
		want      map[string]string
	}{
		{"aws", &AWSDriver{},
			map[string]string{"access_key_id": "AKIANEW", "secret_access_key": "s", "region": "us-east-1"},
			map[string]string{"access_key_id": "AKIANEW"}},
		{"alicloud", &AlicloudDriver{},
			map[string]string{"access_key_id": "LTAINEW", "access_key_secret": "s", "management_user_name": "warden"},
			map[string]string{"access_key_id": "LTAINEW", "management_user_name": "warden"}},
		{"elastic", &ElasticDriver{},
			map[string]string{"api_key": "enc", "api_key_id": "new-id"},
			map[string]string{"api_key_id": "new-id"}},
		{"scaleway", &ScalewayDriver{},
			map[string]string{"management_access_key": "SCWNEW", "management_secret_key": "s"},
			map[string]string{"access_key": "SCWNEW"}},
		{"azure", &AzureDriver{},
			map[string]string{"client_id": "app", "client_secret": "s", "secret_id": "new-sid"},
			map[string]string{"client_id": "app", "old_secret_id": "new-sid"}},
		{"gcp", &GCPDriver{},
			map[string]string{"service_account_key": gcpKey},
			map[string]string{
				"old_key_id":              "new-kid",
				"service_account_email":   "sa@proj.iam.gserviceaccount.com",
				"project_id":              "proj",
				"old_service_account_key": gcpKey,
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.discarder.StagedCleanupConfig(context.Background(), tc.newConfig)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)

			_, err = tc.discarder.StagedCleanupConfig(context.Background(), map[string]string{})
			assert.Error(t, err, "a staged config without the credential's id must be refused, not discard nothing")
		})
	}

	t.Run("azure spec", func(t *testing.T) {
		got, err := (&AzureDriver{}).StagedSpecCleanupConfig(context.Background(),
			map[string]string{"client_id": "workload", "secret_id": "new-sid", "tenant_id": "t"})
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"client_id": "workload", "old_secret_id": "new-sid"}, got)
	})
}

// The IBM staged config carries only the new key, so its id is looked up with a
// token from the key the driver still holds.
func TestIBMDriver_StagedCleanupConfig(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/identity/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "token-for-" + r.FormValue("apikey"),
			"token_type":   "Bearer",
			"expires_in":   3600,
			"expiration":   time.Now().Add(time.Hour).Unix(),
		})
	})
	mux.HandleFunc("/v1/apikeys/details", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer token-for-test-key", r.Header.Get("Authorization"),
			"the lookup must authenticate with the old key")
		var body map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, "new-rotated-api-key", body["apikey"], "the lookup must ask about the new key")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "ApiKey-new", "iam_id": "iam-x"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d := newTestIBMDriver(t, srv.URL)
	got, err := d.StagedCleanupConfig(context.Background(), map[string]string{"api_key": "new-rotated-api-key"})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"api_key_id": "ApiKey-new"}, got)
}
