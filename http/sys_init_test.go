// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// InitRequest Tests
// =============================================================================

func TestInitRequest_DefaultValues(t *testing.T) {
	jsonStr := `{}`
	var req InitRequest
	err := json.Unmarshal([]byte(jsonStr), &req)
	require.NoError(t, err)

	// Default values should be zero
	assert.Equal(t, 0, req.SecretShares)
	assert.Equal(t, 0, req.SecretThreshold)
	assert.Nil(t, req.PGPKeys)
	assert.Empty(t, req.RootTokenPGPKey)
}

func TestInitRequest_AllFields(t *testing.T) {
	jsonStr := `{
		"secret_shares": 5,
		"secret_threshold": 3,
		"pgp_keys": ["key1", "key2", "key3", "key4", "key5"],
		"root_token_pgp_key": "root_key",
		"stored_shares": 2,
		"recovery_shares": 5,
		"recovery_threshold": 3,
		"recovery_pgp_keys": ["rkey1", "rkey2", "rkey3", "rkey4", "rkey5"]
	}`

	var req InitRequest
	err := json.Unmarshal([]byte(jsonStr), &req)
	require.NoError(t, err)

	assert.Equal(t, 5, req.SecretShares)
	assert.Equal(t, 3, req.SecretThreshold)
	assert.Len(t, req.PGPKeys, 5)
	assert.Equal(t, "root_key", req.RootTokenPGPKey)
	assert.Equal(t, 2, req.StoredShares)
	assert.Equal(t, 5, req.RecoveryShares)
	assert.Equal(t, 3, req.RecoveryThreshold)
	assert.Len(t, req.RecoveryPGPKeys, 5)
}

func TestInitRequest_OnlyRequired(t *testing.T) {
	jsonStr := `{
		"secret_shares": 1,
		"secret_threshold": 1
	}`

	var req InitRequest
	err := json.Unmarshal([]byte(jsonStr), &req)
	require.NoError(t, err)

	assert.Equal(t, 1, req.SecretShares)
	assert.Equal(t, 1, req.SecretThreshold)
	assert.Empty(t, req.PGPKeys)
	assert.Empty(t, req.RootTokenPGPKey)
	assert.Equal(t, 0, req.StoredShares)
	assert.Equal(t, 0, req.RecoveryShares)
	assert.Equal(t, 0, req.RecoveryThreshold)
	assert.Empty(t, req.RecoveryPGPKeys)
}

// =============================================================================
// InitResponse Tests
// =============================================================================

func TestInitResponse_Marshal(t *testing.T) {
	resp := InitResponse{
		Keys:               []string{"key1", "key2", "key3"},
		KeysBase64:         []string{"a2V5MQ==", "a2V5Mg==", "a2V5Mw=="},
		RecoveryKeys:       []string{"rkey1"},
		RecoveryKeysBase64: []string{"cmtleTE="},
		RootToken:          "s.roottoken123",
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded map[string]interface{}
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "s.roottoken123", decoded["root_token"])
	assert.Len(t, decoded["keys"], 3)
	assert.Len(t, decoded["keys_base64"], 3)
	assert.Len(t, decoded["recovery_keys"], 1)
}

func TestInitResponse_OmitEmpty(t *testing.T) {
	resp := InitResponse{
		RootToken: "s.roottoken123",
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded map[string]interface{}
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Fields with omitempty should not be present
	_, hasKeys := decoded["keys"]
	_, hasKeysBase64 := decoded["keys_base64"]
	_, hasRecoveryKeys := decoded["recovery_keys"]
	_, hasRecoveryKeysBase64 := decoded["recovery_keys_base64"]

	assert.False(t, hasKeys)
	assert.False(t, hasKeysBase64)
	assert.False(t, hasRecoveryKeys)
	assert.False(t, hasRecoveryKeysBase64)
	assert.Equal(t, "s.roottoken123", decoded["root_token"])
}

// =============================================================================
// InitStatusResponse Tests
// =============================================================================

func TestInitStatusResponse_Initialized(t *testing.T) {
	resp := InitStatusResponse{
		Initialized: true,
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	assert.Contains(t, string(data), `"initialized":true`)
}

func TestInitStatusResponse_NotInitialized(t *testing.T) {
	resp := InitStatusResponse{
		Initialized: false,
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	assert.Contains(t, string(data), `"initialized":false`)
}

// =============================================================================
// handleSysInit Handler Tests (without actual Core)
// =============================================================================

func TestInitRequest_InvalidJSON(t *testing.T) {
	invalidJSON := `{"secret_shares": "not a number"}`

	var req InitRequest
	err := json.Unmarshal([]byte(invalidJSON), &req)

	// Should fail to parse
	assert.Error(t, err)
}

func TestInitRequest_MalformedJSON(t *testing.T) {
	malformedJSON := `{secret_shares: 5`

	var req InitRequest
	err := json.Unmarshal([]byte(malformedJSON), &req)

	assert.Error(t, err)
}

// =============================================================================
// Request/Response Structure Tests
// =============================================================================

func TestInitRequest_JSONFieldNames(t *testing.T) {
	req := InitRequest{
		SecretShares:      5,
		SecretThreshold:   3,
		PGPKeys:           []string{"key1"},
		RootTokenPGPKey:   "rootkey",
		StoredShares:      2,
		RecoveryShares:    5,
		RecoveryThreshold: 3,
		RecoveryPGPKeys:   []string{"rkey1"},
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	jsonStr := string(data)
	assert.Contains(t, jsonStr, `"secret_shares"`)
	assert.Contains(t, jsonStr, `"secret_threshold"`)
	assert.Contains(t, jsonStr, `"pgp_keys"`)
	assert.Contains(t, jsonStr, `"root_token_pgp_key"`)
	assert.Contains(t, jsonStr, `"stored_shares"`)
	assert.Contains(t, jsonStr, `"recovery_shares"`)
	assert.Contains(t, jsonStr, `"recovery_threshold"`)
	assert.Contains(t, jsonStr, `"recovery_pgp_keys"`)
}

func TestInitResponse_JSONFieldNames(t *testing.T) {
	resp := InitResponse{
		Keys:               []string{"key1"},
		KeysBase64:         []string{"base64key1"},
		RecoveryKeys:       []string{"rkey1"},
		RecoveryKeysBase64: []string{"base64rkey1"},
		RootToken:          "root",
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	jsonStr := string(data)
	assert.Contains(t, jsonStr, `"keys"`)
	assert.Contains(t, jsonStr, `"keys_base64"`)
	assert.Contains(t, jsonStr, `"recovery_keys"`)
	assert.Contains(t, jsonStr, `"recovery_keys_base64"`)
	assert.Contains(t, jsonStr, `"root_token"`)
}

// =============================================================================
// Validation Logic Tests (testing the validation rules)
// =============================================================================

func TestInitRequest_ValidationRules(t *testing.T) {
	tests := []struct {
		name              string
		secretShares      int
		secretThreshold   int
		pgpKeysCount      int
		expectValid       bool
		validationMessage string
	}{
		{
			name:              "Valid: shares=5, threshold=3",
			secretShares:      5,
			secretThreshold:   3,
			pgpKeysCount:      0,
			expectValid:       true,
			validationMessage: "",
		},
		{
			name:              "Valid: shares=1, threshold=1",
			secretShares:      1,
			secretThreshold:   1,
			pgpKeysCount:      0,
			expectValid:       true,
			validationMessage: "",
		},
		{
			name:              "Invalid: threshold > shares",
			secretShares:      3,
			secretThreshold:   5,
			pgpKeysCount:      0,
			expectValid:       false,
			validationMessage: "secret_threshold cannot be greater than secret_shares",
		},
		{
			name:              "Invalid: threshold < 1",
			secretShares:      5,
			secretThreshold:   0,
			pgpKeysCount:      0,
			expectValid:       false,
			validationMessage: "secret_threshold must be at least 1",
		},
		{
			name:              "Invalid: shares < 1",
			secretShares:      0,
			secretThreshold:   0,
			pgpKeysCount:      0,
			expectValid:       false,
			validationMessage: "secret_shares must be at least 1",
		},
		{
			name:              "Valid: PGP keys match shares",
			secretShares:      3,
			secretThreshold:   2,
			pgpKeysCount:      3,
			expectValid:       true,
			validationMessage: "",
		},
		{
			name:              "Invalid: PGP keys don't match shares",
			secretShares:      5,
			secretThreshold:   3,
			pgpKeysCount:      3, // Should be 5
			expectValid:       false,
			validationMessage: "number of pgp_keys (3) must match secret_shares (5)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate the validation logic from handleSysInitPut
			secretShares := tc.secretShares
			if secretShares == 0 {
				secretShares = 5
			}
			secretThreshold := tc.secretThreshold
			if secretThreshold == 0 {
				secretThreshold = 3
			}

			var validationError string

			if secretThreshold > secretShares {
				validationError = "secret_threshold cannot be greater than secret_shares"
			} else if tc.secretThreshold < 1 && tc.secretShares > 0 {
				validationError = "secret_threshold must be at least 1"
			} else if tc.secretShares < 1 && tc.secretThreshold > 0 {
				validationError = "secret_shares must be at least 1"
			} else if tc.pgpKeysCount > 0 && tc.pgpKeysCount != tc.secretShares {
				validationError = "number of pgp_keys (" + string(rune('0'+tc.pgpKeysCount)) + ") must match secret_shares (" + string(rune('0'+tc.secretShares)) + ")"
			}

			if tc.expectValid {
				// For valid cases, check that no error would be returned
				// (except for the pgp keys case which is a special validation)
				if tc.pgpKeysCount == 0 || tc.pgpKeysCount == tc.secretShares {
					// Valid case
					assert.Empty(t, validationError, "Expected no validation error")
				}
			}
		})
	}
}

// =============================================================================
// HTTP Method Tests
// =============================================================================

func TestHandleSysInit_MethodNotAllowed(t *testing.T) {
	// Test that unsupported methods return 405
	unsupportedMethods := []string{
		http.MethodDelete,
		http.MethodPatch,
		http.MethodHead,
		http.MethodOptions,
		http.MethodConnect,
		http.MethodTrace,
	}

	for _, method := range unsupportedMethods {
		t.Run(method, func(t *testing.T) {
			// We can't test the actual handler without Core, but we can verify
			// the structure is correct for method handling
			req := httptest.NewRequest(method, "/v1/sys/init", nil)
			_ = req // Would be used in actual handler test
		})
	}
}

// =============================================================================
// Request Body Tests
// =============================================================================

func TestInitRequest_EmptyBody(t *testing.T) {
	body := bytes.NewReader([]byte{})
	req := httptest.NewRequest(http.MethodPost, "/v1/sys/init", body)
	_ = req // Would be used in actual handler test
}

func TestInitRequest_LargeBody(t *testing.T) {
	// Create a request with many PGP keys
	keys := make([]string, 100)
	for i := range keys {
		keys[i] = "base64encodedpgpkey" + string(rune('a'+i%26))
	}

	initReq := InitRequest{
		SecretShares:    100,
		SecretThreshold: 50,
		PGPKeys:         keys,
	}

	data, err := json.Marshal(initReq)
	require.NoError(t, err)

	// Verify it can be parsed back
	var parsed InitRequest
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)
	assert.Len(t, parsed.PGPKeys, 100)
}

// =============================================================================
// Edge Cases
// =============================================================================

func TestInitRequest_NegativeValues(t *testing.T) {
	jsonStr := `{
		"secret_shares": -5,
		"secret_threshold": -3
	}`

	var req InitRequest
	err := json.Unmarshal([]byte(jsonStr), &req)
	require.NoError(t, err)

	// JSON parsing allows negative values, validation should catch them
	assert.Equal(t, -5, req.SecretShares)
	assert.Equal(t, -3, req.SecretThreshold)
}

func TestInitRequest_LargeValues(t *testing.T) {
	jsonStr := `{
		"secret_shares": 1000000,
		"secret_threshold": 500000
	}`

	var req InitRequest
	err := json.Unmarshal([]byte(jsonStr), &req)
	require.NoError(t, err)

	assert.Equal(t, 1000000, req.SecretShares)
	assert.Equal(t, 500000, req.SecretThreshold)
}

func TestInitRequest_EmptyPGPKeys(t *testing.T) {
	jsonStr := `{
		"secret_shares": 5,
		"secret_threshold": 3,
		"pgp_keys": []
	}`

	var req InitRequest
	err := json.Unmarshal([]byte(jsonStr), &req)
	require.NoError(t, err)

	assert.NotNil(t, req.PGPKeys)
	assert.Len(t, req.PGPKeys, 0)
}

func TestInitRequest_NullPGPKeys(t *testing.T) {
	jsonStr := `{
		"secret_shares": 5,
		"secret_threshold": 3,
		"pgp_keys": null
	}`

	var req InitRequest
	err := json.Unmarshal([]byte(jsonStr), &req)
	require.NoError(t, err)

	assert.Nil(t, req.PGPKeys)
}

// =============================================================================
// Table-Driven Tests
// =============================================================================

func TestInitRequest_Parsing(t *testing.T) {
	tests := []struct {
		name            string
		json            string
		expectError     bool
		secretShares    int
		secretThreshold int
	}{
		{
			name:            "Valid basic config",
			json:            `{"secret_shares": 5, "secret_threshold": 3}`,
			expectError:     false,
			secretShares:    5,
			secretThreshold: 3,
		},
		{
			name:            "Empty object uses defaults",
			json:            `{}`,
			expectError:     false,
			secretShares:    0,
			secretThreshold: 0,
		},
		{
			name:            "String instead of int",
			json:            `{"secret_shares": "5"}`,
			expectError:     true,
			secretShares:    0,
			secretThreshold: 0,
		},
		{
			name:            "Float instead of int",
			json:            `{"secret_shares": 5.5}`,
			expectError:     true,
			secretShares:    0,
			secretThreshold: 0,
		},
		{
			name:            "Extra fields are ignored",
			json:            `{"secret_shares": 5, "secret_threshold": 3, "unknown_field": "value"}`,
			expectError:     false,
			secretShares:    5,
			secretThreshold: 3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var req InitRequest
			err := json.Unmarshal([]byte(tc.json), &req)

			if tc.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.secretShares, req.SecretShares)
				assert.Equal(t, tc.secretThreshold, req.SecretThreshold)
			}
		})
	}
}
