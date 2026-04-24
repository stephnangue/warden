package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createAlicloudTestLogger() *logger.GatedLogger {
	config := &logger.Config{
		Level:   logger.TraceLevel,
		Format:  logger.DefaultFormat,
		Outputs: []io.Writer{io.Discard},
	}
	gl, _ := logger.NewGatedLogger(config, logger.GatedWriterConfig{
		Underlying:   io.Discard,
		InitialState: logger.GateOpen,
	})
	return gl
}

// --- Factory tests ---

func TestAlicloudDriverFactory_Type(t *testing.T) {
	f := &AlicloudDriverFactory{}
	assert.Equal(t, credential.SourceTypeAlicloud, f.Type())
}

func TestAlicloudDriverFactory_InferCredentialType(t *testing.T) {
	f := &AlicloudDriverFactory{}
	ct, err := f.InferCredentialType(map[string]string{})
	require.NoError(t, err)
	assert.Equal(t, credential.TypeAlicloudKeys, ct)
}

func TestAlicloudDriverFactory_SensitiveConfigFields(t *testing.T) {
	f := &AlicloudDriverFactory{}
	fields := f.SensitiveConfigFields()
	assert.Contains(t, fields, "access_key_secret")
	assert.Contains(t, fields, "ca_data")
}

func TestAlicloudDriverFactory_ValidateConfig(t *testing.T) {
	f := &AlicloudDriverFactory{}

	t.Run("empty config is valid (MVP allows it)", func(t *testing.T) {
		assert.NoError(t, f.ValidateConfig(map[string]string{}))
	})

	t.Run("valid config", func(t *testing.T) {
		assert.NoError(t, f.ValidateConfig(map[string]string{
			"access_key_id":     "LTAItest",
			"access_key_secret": "secret",
			"sts_endpoint":      "https://sts.aliyuncs.com",
			"ram_endpoint":      "https://ram.aliyuncs.com",
		}))
	})
}

func TestAlicloudDriverFactory_Create(t *testing.T) {
	f := &AlicloudDriverFactory{}
	log := createAlicloudTestLogger()

	d, err := f.Create(map[string]string{
		"access_key_id":     "LTAItest",
		"access_key_secret": "secret",
	}, log)
	require.NoError(t, err)
	assert.Equal(t, credential.SourceTypeAlicloud, d.Type())
}

// --- MintCredential: mint_method validation ---

// Static keys are deliberately not supported by the alicloud driver — they
// belong on a local source, which keeps the driver focused on management-key
// flows (assume_role, dynamic_keys).
func TestAlicloudDriver_StaticKeysRejected(t *testing.T) {
	f := &AlicloudDriverFactory{}
	d, _ := f.Create(map[string]string{}, createAlicloudTestLogger())
	_, _, _, err := d.MintCredential(context.Background(), &credential.CredSpec{
		Config: map[string]string{
			"mint_method":       "static_keys",
			"access_key_id":     "x",
			"access_key_secret": "y",
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "assume_role")
}

func TestAlicloudDriver_UnsupportedMintMethod(t *testing.T) {
	f := &AlicloudDriverFactory{}
	d, _ := f.Create(map[string]string{}, createAlicloudTestLogger())
	_, _, _, err := d.MintCredential(context.Background(), &credential.CredSpec{
		Config: map[string]string{"mint_method": "bogus"},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported or missing mint_method")
}

func TestAlicloudDriver_MissingMintMethod(t *testing.T) {
	f := &AlicloudDriverFactory{}
	d, _ := f.Create(map[string]string{}, createAlicloudTestLogger())
	_, _, _, err := d.MintCredential(context.Background(), &credential.CredSpec{
		Config: map[string]string{},
	})
	assert.Error(t, err)
}

// --- MintCredential: assume_role (STS) ---

func TestAlicloudDriver_MintAssumeRole(t *testing.T) {
	var receivedAction string
	var receivedAuth string
	var receivedRoleArn string

	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAction = r.URL.Query().Get("Action")
		receivedRoleArn = r.URL.Query().Get("RoleArn")
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Credentials": map[string]any{
				"AccessKeyId":     "STS.tempid",
				"AccessKeySecret": "tempsecret",
				"SecurityToken":   "tempstsToken",
				"Expiration":      "2099-01-01T00:00:00Z",
			},
		})
	}))
	defer sts.Close()

	f := &AlicloudDriverFactory{}
	d, err := f.Create(map[string]string{
		"access_key_id":     "LTAI-mgmt",
		"access_key_secret": "mgmt-secret",
		"sts_endpoint":      sts.URL,
	}, createAlicloudTestLogger())
	require.NoError(t, err)

	spec := &credential.CredSpec{
		Name: "ops",
		Config: map[string]string{
			"mint_method":      "assume_role",
			"role_arn":         "acs:ram::123:role/ops",
			"duration_seconds": "1800s",
		},
	}

	raw, ttl, leaseID, err := d.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "STS.tempid", raw["access_key_id"])
	assert.Equal(t, "tempsecret", raw["access_key_secret"])
	assert.Equal(t, "tempstsToken", raw["security_token"])
	assert.Equal(t, 1800, int(ttl.Seconds()), "ttl should match duration_seconds")
	assert.Equal(t, "", leaseID, "STS has no leaseID")

	// Verify the request was signed with ACS3 and had the right params
	assert.Equal(t, "AssumeRole", receivedAction)
	assert.Equal(t, "acs:ram::123:role/ops", receivedRoleArn)
	assert.True(t, strings.HasPrefix(receivedAuth, "ACS3-HMAC-SHA256"), "must be ACS3 signed: %q", receivedAuth)
	assert.Contains(t, receivedAuth, "Credential=LTAI-mgmt")
}

func TestAlicloudDriver_MintAssumeRole_MissingRoleArn(t *testing.T) {
	f := &AlicloudDriverFactory{}
	d, _ := f.Create(map[string]string{
		"access_key_id":     "LTAI-mgmt",
		"access_key_secret": "mgmt-secret",
	}, createAlicloudTestLogger())

	_, _, _, err := d.MintCredential(context.Background(), &credential.CredSpec{
		Config: map[string]string{"mint_method": "assume_role"},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "role_arn")
}

func TestAlicloudDriver_MintAssumeRole_MissingManagementKey(t *testing.T) {
	f := &AlicloudDriverFactory{}
	d, _ := f.Create(map[string]string{}, createAlicloudTestLogger())
	_, _, _, err := d.MintCredential(context.Background(), &credential.CredSpec{
		Config: map[string]string{
			"mint_method": "assume_role",
			"role_arn":    "acs:ram::123:role/x",
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "access_key_id")
}

// --- Revoke is a no-op (STS tokens are self-expiring) ---

func TestAlicloudDriver_RevokeIsNoop(t *testing.T) {
	f := &AlicloudDriverFactory{}
	d, _ := f.Create(map[string]string{}, createAlicloudTestLogger())
	assert.NoError(t, d.Revoke(context.Background(), ""))
	assert.NoError(t, d.Revoke(context.Background(), "any-lease-id"))
}

func TestAlicloudDriver_DynamicKeysRejected(t *testing.T) {
	f := &AlicloudDriverFactory{}
	d, _ := f.Create(map[string]string{
		"access_key_id":     "LTAI-mgmt",
		"access_key_secret": "mgmt-secret",
	}, createAlicloudTestLogger())
	_, _, _, err := d.MintCredential(context.Background(), &credential.CredSpec{
		Config: map[string]string{
			"mint_method":   "dynamic_keys",
			"ram_user_name": "warden-svc",
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "assume_role")
}

// --- VerifySpec ---

func TestAlicloudDriver_VerifySpec(t *testing.T) {
	f := &AlicloudDriverFactory{}

	t.Run("unsupported mint_method", func(t *testing.T) {
		d, _ := f.Create(map[string]string{}, createAlicloudTestLogger())
		err := d.(*AlicloudDriver).VerifySpec(context.Background(), &credential.CredSpec{
			Config: map[string]string{"mint_method": "bogus"},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported mint_method")
	})

	t.Run("assume_role requires role_arn", func(t *testing.T) {
		d, _ := f.Create(map[string]string{
			"access_key_id":     "LTAI-mgmt",
			"access_key_secret": "mgmt-secret",
		}, createAlicloudTestLogger())
		err := d.(*AlicloudDriver).VerifySpec(context.Background(), &credential.CredSpec{
			Config: map[string]string{"mint_method": "assume_role"},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "role_arn")
	})

	t.Run("assume_role requires management keys", func(t *testing.T) {
		d, _ := f.Create(map[string]string{}, createAlicloudTestLogger())
		err := d.(*AlicloudDriver).VerifySpec(context.Background(), &credential.CredSpec{
			Config: map[string]string{
				"mint_method": "assume_role",
				"role_arn":    "acs:ram::123:role/x",
			},
		})
		assert.Error(t, err)
	})

	t.Run("happy path: live AssumeRole dry-run succeeds", func(t *testing.T) {
		var receivedAction, receivedSession, receivedDuration string
		sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedAction = r.URL.Query().Get("Action")
			receivedSession = r.URL.Query().Get("RoleSessionName")
			receivedDuration = r.URL.Query().Get("DurationSeconds")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Credentials": map[string]any{
					"AccessKeyId":     "STS.verify",
					"AccessKeySecret": "verify-secret",
					"SecurityToken":   "verify-token",
					"Expiration":      "2099-01-01T00:00:00Z",
				},
			})
		}))
		defer sts.Close()

		d, _ := f.Create(map[string]string{
			"access_key_id":     "LTAI-mgmt",
			"access_key_secret": "mgmt-secret",
			"sts_endpoint":      sts.URL,
		}, createAlicloudTestLogger())

		err := d.(*AlicloudDriver).VerifySpec(context.Background(), &credential.CredSpec{
			Config: map[string]string{
				"mint_method": "assume_role",
				"role_arn":    "acs:ram::123:role/verify-ok",
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "AssumeRole", receivedAction)
		assert.Equal(t, "warden-verify", receivedSession)
		assert.Equal(t, "900", receivedDuration, "dry-run must use the minimum 900s duration")
	})

	t.Run("failure: STS rejects the role", func(t *testing.T) {
		sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Code":      "EntityNotExist.Role",
				"Message":   "The role does not exist.",
				"RequestId": "req",
			})
		}))
		defer sts.Close()

		d, _ := f.Create(map[string]string{
			"access_key_id":     "LTAI-mgmt",
			"access_key_secret": "mgmt-secret",
			"sts_endpoint":      sts.URL,
		}, createAlicloudTestLogger())

		err := d.(*AlicloudDriver).VerifySpec(context.Background(), &credential.CredSpec{
			Config: map[string]string{
				"mint_method": "assume_role",
				"role_arn":    "acs:ram::123:role/does-not-exist",
			},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "pre-flight AssumeRole")
	})
}

// --- callSignedJSON: envelope-aware retries ---
//
// These tests drive callSignedJSON through VerifySpec so they exercise the
// same code path operators hit at spec creation time. A handler function
// closes over a hit counter and can flip its response per-call to simulate
// transient failures followed by success.

// alicloudEnvelopeHandler returns an http.HandlerFunc that emits a successful
// AssumeRole response or an error envelope depending on which attempt this is.
// responses is walked in order; the last entry sticks once exhausted.
func alicloudEnvelopeHandler(hits *int, responses []struct {
	status int
	body   map[string]any
}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idx := *hits
		if idx >= len(responses) {
			idx = len(responses) - 1
		}
		*hits++
		resp := responses[idx]
		w.Header().Set("Content-Type", "application/json")
		if resp.status != 0 {
			w.WriteHeader(resp.status)
		}
		_ = json.NewEncoder(w).Encode(resp.body)
	}
}

func TestAlicloudDriver_CallSignedJSON_RetriesOnThrottling(t *testing.T) {
	hits := 0
	sts := httptest.NewServer(alicloudEnvelopeHandler(&hits, []struct {
		status int
		body   map[string]any
	}{
		{status: http.StatusBadRequest, body: map[string]any{
			"Code":      "Throttling.Api",
			"Message":   "Request was denied due to api throttling.",
			"RequestId": "req-throttle",
		}},
		{status: http.StatusOK, body: map[string]any{
			"Credentials": map[string]any{
				"AccessKeyId":     "STS.ok",
				"AccessKeySecret": "ok-secret",
				"SecurityToken":   "ok-token",
				"Expiration":      "2099-01-01T00:00:00Z",
			},
		}},
	}))
	defer sts.Close()

	f := &AlicloudDriverFactory{}
	d, _ := f.Create(map[string]string{
		"access_key_id":     "LTAI-mgmt",
		"access_key_secret": "mgmt-secret",
		"sts_endpoint":      sts.URL,
	}, createAlicloudTestLogger())

	err := d.(*AlicloudDriver).VerifySpec(context.Background(), &credential.CredSpec{
		Config: map[string]string{
			"mint_method": "assume_role",
			"role_arn":    "acs:ram::123:role/retry-ok",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, 2, hits, "first call throttled, second should succeed")
}

func TestAlicloudDriver_CallSignedJSON_RetriesOnInternalError(t *testing.T) {
	hits := 0
	sts := httptest.NewServer(alicloudEnvelopeHandler(&hits, []struct {
		status int
		body   map[string]any
	}{
		{status: http.StatusBadRequest, body: map[string]any{
			"Code":      "InternalError",
			"Message":   "The request processing has failed due to some unknown error.",
			"RequestId": "req-internal",
		}},
		{status: http.StatusOK, body: map[string]any{
			"Credentials": map[string]any{
				"AccessKeyId":     "STS.ok",
				"AccessKeySecret": "ok-secret",
				"SecurityToken":   "ok-token",
				"Expiration":      "2099-01-01T00:00:00Z",
			},
		}},
	}))
	defer sts.Close()

	f := &AlicloudDriverFactory{}
	d, _ := f.Create(map[string]string{
		"access_key_id":     "LTAI-mgmt",
		"access_key_secret": "mgmt-secret",
		"sts_endpoint":      sts.URL,
	}, createAlicloudTestLogger())

	err := d.(*AlicloudDriver).VerifySpec(context.Background(), &credential.CredSpec{
		Config: map[string]string{
			"mint_method": "assume_role",
			"role_arn":    "acs:ram::123:role/retry-internal",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, 2, hits)
}

func TestAlicloudDriver_CallSignedJSON_DoesNotRetrySignatureMismatch(t *testing.T) {
	hits := 0
	sts := httptest.NewServer(alicloudEnvelopeHandler(&hits, []struct {
		status int
		body   map[string]any
	}{
		{status: http.StatusBadRequest, body: map[string]any{
			"Code":      "SignatureDoesNotMatch",
			"Message":   "Specified signature is not matched with our calculation.",
			"RequestId": "req-sig",
		}},
	}))
	defer sts.Close()

	f := &AlicloudDriverFactory{}
	d, _ := f.Create(map[string]string{
		"access_key_id":     "LTAI-mgmt",
		"access_key_secret": "mgmt-secret",
		"sts_endpoint":      sts.URL,
	}, createAlicloudTestLogger())

	err := d.(*AlicloudDriver).VerifySpec(context.Background(), &credential.CredSpec{
		Config: map[string]string{
			"mint_method": "assume_role",
			"role_arn":    "acs:ram::123:role/sig",
		},
	})
	require.Error(t, err)
	assert.Equal(t, 1, hits, "signature mismatches must not be retried")
	assert.Contains(t, err.Error(), "SignatureDoesNotMatch")
	assert.Contains(t, err.Error(), "req-sig", "RequestId should be surfaced for operator triage")
}

func TestAlicloudDriver_CallSignedJSON_StopsAtMaxAttempts(t *testing.T) {
	hits := 0
	sts := httptest.NewServer(alicloudEnvelopeHandler(&hits, []struct {
		status int
		body   map[string]any
	}{
		{status: http.StatusBadRequest, body: map[string]any{
			"Code":      "Throttling",
			"Message":   "Please slow down.",
			"RequestId": "req-throttle-loop",
		}},
	}))
	defer sts.Close()

	f := &AlicloudDriverFactory{}
	d, _ := f.Create(map[string]string{
		"access_key_id":     "LTAI-mgmt",
		"access_key_secret": "mgmt-secret",
		"sts_endpoint":      sts.URL,
	}, createAlicloudTestLogger())

	err := d.(*AlicloudDriver).VerifySpec(context.Background(), &credential.CredSpec{
		Config: map[string]string{
			"mint_method": "assume_role",
			"role_arn":    "acs:ram::123:role/stuck",
		},
	})
	require.Error(t, err)
	assert.Equal(t, alicloudMaxRetryAttempts, hits, "retries must be capped at alicloudMaxRetryAttempts")
	assert.Contains(t, err.Error(), "exhausted")
	assert.Contains(t, err.Error(), "Throttling")
}

// --- Rotation ---

func TestAlicloudDriver_SupportsRotation(t *testing.T) {
	f := &AlicloudDriverFactory{}

	t.Run("requires management user name", func(t *testing.T) {
		d, _ := f.Create(map[string]string{
			"access_key_id":     "x",
			"access_key_secret": "y",
		}, createAlicloudTestLogger())
		assert.False(t, d.(*AlicloudDriver).SupportsRotation())
	})

	t.Run("requires management keys", func(t *testing.T) {
		d, _ := f.Create(map[string]string{
			"management_user_name": "u",
		}, createAlicloudTestLogger())
		assert.False(t, d.(*AlicloudDriver).SupportsRotation())
	})

	t.Run("all fields present", func(t *testing.T) {
		d, _ := f.Create(map[string]string{
			"access_key_id":        "x",
			"access_key_secret":    "y",
			"management_user_name": "u",
		}, createAlicloudTestLogger())
		assert.True(t, d.(*AlicloudDriver).SupportsRotation())
	})
}

// ramServer is a minimal in-memory mock of the Alicloud RAM API for rotation tests.
type ramServer struct {
	user          string
	keys          map[string]string // access_key_id -> status ("Active" or "Inactive")
	nextIDCounter int
	created       []string
	deactivated   []string
	deleted       []string
	actionSeq     []string // action names in the order received, for ordering assertions
}

func (s *ramServer) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	action := r.URL.Query().Get("Action")
	s.actionSeq = append(s.actionSeq, action)
	user := r.URL.Query().Get("UserName")
	if user != s.user {
		http.Error(w, "wrong user", http.StatusBadRequest)
		return
	}
	switch action {
	case "ListAccessKeys":
		type accessKey struct {
			AccessKeyID string `json:"AccessKeyId"`
			Status      string `json:"Status"`
		}
		type accessKeys struct {
			AccessKey []accessKey `json:"AccessKey"`
		}
		var list accessKeys
		for id, status := range s.keys {
			list.AccessKey = append(list.AccessKey, accessKey{AccessKeyID: id, Status: status})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"AccessKeys": list})
	case "CreateAccessKey":
		s.nextIDCounter++
		newID := fmt.Sprintf("LTAI-rotated-%d", s.nextIDCounter)
		s.keys[newID] = "Active"
		s.created = append(s.created, newID)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"AccessKey": map[string]any{
				"AccessKeyId":     newID,
				"AccessKeySecret": "secret-" + newID,
				"Status":          "Active",
			},
		})
	case "UpdateAccessKey":
		id := r.URL.Query().Get("UserAccessKeyId")
		status := r.URL.Query().Get("Status")
		if _, ok := s.keys[id]; !ok {
			http.Error(w, "no such key", http.StatusBadRequest)
			return
		}
		s.keys[id] = status
		if status == "Inactive" {
			s.deactivated = append(s.deactivated, id)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"RequestId": "req"})
	case "DeleteAccessKey":
		id := r.URL.Query().Get("UserAccessKeyId")
		delete(s.keys, id)
		s.deleted = append(s.deleted, id)
		_ = json.NewEncoder(w).Encode(map[string]any{"RequestId": "req"})
	default:
		http.Error(w, "unexpected action: "+action, http.StatusBadRequest)
	}
}

func TestAlicloudDriver_Rotation_HappyPath(t *testing.T) {
	ram := &ramServer{
		user: "warden-management",
		keys: map[string]string{"LTAI-old": "Active"},
	}
	srv := httptest.NewServer(http.HandlerFunc(ram.handle))
	defer srv.Close()

	f := &AlicloudDriverFactory{}
	d, err := f.Create(map[string]string{
		"access_key_id":        "LTAI-old",
		"access_key_secret":    "old-secret",
		"management_user_name": "warden-management",
		"ram_endpoint":         srv.URL,
	}, createAlicloudTestLogger())
	require.NoError(t, err)
	drv := d.(*AlicloudDriver)

	// Prepare: creates a new key, returns newConfig + cleanupConfig
	newConfig, cleanupConfig, activateAfter, err := drv.PrepareRotation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, DefaultAlicloudActivationDelay, activateAfter)
	assert.Equal(t, "LTAI-rotated-1", newConfig["access_key_id"])
	assert.Equal(t, "secret-LTAI-rotated-1", newConfig["access_key_secret"])
	assert.Equal(t, "LTAI-old", cleanupConfig["access_key_id"])
	assert.Equal(t, "warden-management", cleanupConfig["management_user_name"])
	// Both keys should exist right now
	assert.Equal(t, "Active", ram.keys["LTAI-old"])
	assert.Equal(t, "Active", ram.keys["LTAI-rotated-1"])
	assert.Empty(t, ram.deleted)

	// Commit: swap to the new config
	require.NoError(t, drv.CommitRotation(context.Background(), newConfig))
	mgmtID, _ := drv.mgmtAccessKey()
	assert.Equal(t, "LTAI-rotated-1", mgmtID)

	// Cleanup: two-step — UpdateAccessKey(Inactive) then DeleteAccessKey on the old key.
	require.NoError(t, drv.CleanupRotation(context.Background(), cleanupConfig))
	assert.Equal(t, []string{"LTAI-old"}, ram.deactivated, "old key must be marked Inactive before delete")
	assert.Equal(t, []string{"LTAI-old"}, ram.deleted)
	_, stillThere := ram.keys["LTAI-old"]
	assert.False(t, stillThere, "old key should be gone after cleanup")
	assert.Equal(t, "Active", ram.keys["LTAI-rotated-1"])

	// Ordering: Update(Inactive) must precede Delete.
	var updateIdx, deleteIdx = -1, -1
	for i, a := range ram.actionSeq {
		if a == "UpdateAccessKey" && updateIdx == -1 {
			updateIdx = i
		}
		if a == "DeleteAccessKey" && deleteIdx == -1 {
			// skip orphan-cleanup deletes from PrepareRotation (none here since we seeded only one key)
			deleteIdx = i
		}
	}
	require.NotEqual(t, -1, updateIdx, "UpdateAccessKey must have been called")
	require.NotEqual(t, -1, deleteIdx, "DeleteAccessKey must have been called")
	assert.Less(t, updateIdx, deleteIdx, "UpdateAccessKey(Inactive) must precede DeleteAccessKey")
}

func TestAlicloudDriver_Rotation_OrphanCleanup(t *testing.T) {
	// Simulate a previous failed rotation that left an orphan key behind.
	ram := &ramServer{
		user: "warden-management",
		keys: map[string]string{
			"LTAI-old":    "Active",
			"LTAI-orphan": "Active", // at the RAM two-key limit
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(ram.handle))
	defer srv.Close()

	f := &AlicloudDriverFactory{}
	d, _ := f.Create(map[string]string{
		"access_key_id":        "LTAI-old",
		"access_key_secret":    "old-secret",
		"management_user_name": "warden-management",
		"ram_endpoint":         srv.URL,
	}, createAlicloudTestLogger())
	drv := d.(*AlicloudDriver)

	newConfig, _, _, err := drv.PrepareRotation(context.Background())
	require.NoError(t, err)

	// Orphan should have been deleted before create
	assert.Contains(t, ram.deleted, "LTAI-orphan")
	// Current key must not be touched by orphan cleanup
	assert.NotContains(t, ram.deleted, "LTAI-old")
	// New key should have been created
	assert.Equal(t, "LTAI-rotated-1", newConfig["access_key_id"])
}

func TestAlicloudDriver_Rotation_MissingConfig(t *testing.T) {
	f := &AlicloudDriverFactory{}

	t.Run("missing management_user_name", func(t *testing.T) {
		d, _ := f.Create(map[string]string{
			"access_key_id":     "x",
			"access_key_secret": "y",
		}, createAlicloudTestLogger())
		_, _, _, err := d.(*AlicloudDriver).PrepareRotation(context.Background())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "management_user_name")
	})

	t.Run("missing management keys", func(t *testing.T) {
		d, _ := f.Create(map[string]string{
			"management_user_name": "u",
		}, createAlicloudTestLogger())
		_, _, _, err := d.(*AlicloudDriver).PrepareRotation(context.Background())
		assert.Error(t, err)
	})
}

func TestAlicloudDriver_Rotation_CleanupRefusesCurrentKey(t *testing.T) {
	// Guard: CleanupRotation must not delete the currently active key.
	f := &AlicloudDriverFactory{}
	d, _ := f.Create(map[string]string{
		"access_key_id":        "LTAI-current",
		"access_key_secret":    "secret",
		"management_user_name": "warden-management",
	}, createAlicloudTestLogger())
	err := d.(*AlicloudDriver).CleanupRotation(context.Background(), map[string]string{
		"access_key_id":        "LTAI-current",
		"management_user_name": "warden-management",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "currently active")
}

// --- ACS3 signing helper ---

func TestSignACS3_Helper(t *testing.T) {
	r, _ := http.NewRequest("POST", "https://sts.aliyuncs.com/?Action=AssumeRole&Version=2015-04-01", nil)
	r.Header.Set("x-acs-action", "AssumeRole")
	r.Header.Set("x-acs-version", "2015-04-01")

	err := signACS3(r, "LTAItest", "secret", "", nil)
	require.NoError(t, err)

	auth := r.Header.Get("Authorization")
	assert.True(t, strings.HasPrefix(auth, "ACS3-HMAC-SHA256"))
	assert.Contains(t, auth, "Credential=LTAItest")
	assert.NotEmpty(t, r.Header.Get("x-acs-date"))
	assert.NotEmpty(t, r.Header.Get("x-acs-signature-nonce"))
	assert.NotEmpty(t, r.Header.Get("x-acs-content-sha256"))
}

// TestSignACS3_KnownAnswer pins the full canonical-request + StringToSign +
// Signature calculation against a fixed input. Any silent drift in
// canonicalization (header ordering, query encoding, body hashing, signed
// headers list) will flip the signature and fail this test.
//
// Vector constructed from the ACS3 v3 spec:
//
//	POST https://sts.aliyuncs.com/?Action=AssumeRole&Version=2015-04-01
//	x-acs-date: 2026-04-23T10:00:00Z
//	x-acs-signature-nonce: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
//	access key: LTAItest / secret
func TestSignACS3_KnownAnswer(t *testing.T) {
	r, _ := http.NewRequest("POST", "https://sts.aliyuncs.com/?Action=AssumeRole&Version=2015-04-01", nil)
	r.Header.Set("x-acs-action", "AssumeRole")
	r.Header.Set("x-acs-version", "2015-04-01")
	// Pre-set the two non-deterministic headers so the signature is reproducible.
	r.Header.Set("x-acs-date", "2026-04-23T10:00:00Z")
	r.Header.Set("x-acs-signature-nonce", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	err := signACS3(r, "LTAItest", "secret", "", nil)
	require.NoError(t, err)

	expected := "ACS3-HMAC-SHA256 Credential=LTAItest,SignedHeaders=host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version,Signature=86a17bf44e598da32d55e6e23cf50d0874b0b709672a7d8cbb00b3beaeb79921"
	assert.Equal(t, expected, r.Header.Get("Authorization"))

	// The empty-body SHA-256 is a well-known constant; assert it too so a
	// regression in body hashing surfaces independently of the signature.
	assert.Equal(t,
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		r.Header.Get("x-acs-content-sha256"),
	)
}
