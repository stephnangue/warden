//go:build e2e

package credential

import (
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// keyedApproleSource is an hvault AppRole source body: it stores a secret_id.
const keyedApproleSource = `{"type":"hvault","rotation_period":300,"config":{
	"vault_address":"http://127.0.0.1:8200","auth_method":"approle",
	"role_id":"e2e-approle-role-id-1234","secret_id":"e2e-approle-secret-id-5678",
	"approle_mount":"e2e_approle","role_name":"warden-e2e-role"}}`

// TestKeylessEnforcementLevel drives keyless_enforcement_level=enforce against
// the HA cluster: keyed writes are refused on the leader and through a standby,
// keyless writes are accepted, and a keyed source created before the switch —
// setup.sh's vault-e2e — keeps minting.
func TestKeylessEnforcementLevel(t *testing.T) {
	const (
		refusedSource = "keyless-e2e-keyed"
		keylessSpec   = "keyless-e2e-kv"
	)
	cleanup := func() {
		port := h.GetLeaderPort(t)
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+keylessSpec, port, "")
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+refusedSource, port, "")
	}

	h.SetKeylessEnforcementLevel(t, "enforce")
	t.Cleanup(func() {
		cleanup()
		h.RestoreKeylessEnforcementLevel(t)
	})

	t.Run("KeyedSourceRefusedOnLeader", func(t *testing.T) {
		port := h.GetLeaderPort(t)
		status, body := h.APIRequest(t, "POST", "sys/cred/sources/"+refusedSource, port, keyedApproleSource)
		requireKeylessRefusal(t, status, body)

		status, _ = h.APIRequest(t, "GET", "sys/cred/sources/"+refusedSource, port, "")
		if status != 404 {
			t.Fatalf("a refused source must not be stored: read returned %d", status)
		}
	})

	t.Run("KeyedSourceRefusedThroughStandby", func(t *testing.T) {
		port := h.GetStandbyPort(t)
		status, body := h.APIRequest(t, "POST", "sys/cred/sources/"+refusedSource, port, keyedApproleSource)
		requireKeylessRefusal(t, status, body)
	})

	t.Run("KeylessSpecAccepted", func(t *testing.T) {
		port := h.GetLeaderPort(t)
		// vault-fed-e2e federates, and a key_value spec holds only locators.
		status, body := h.APIRequest(t, "POST", "sys/cred/specs/"+keylessSpec, port, `{
			"type":"key_value","source":"vault-fed-e2e","config":{
				"mint_method":"kv2_read","kv2_mount":"secret","secret_path":"e2e/app-config",
				"subject_token_source":"agent_identity"}}`)
		if status != 200 && status != 201 {
			t.Fatalf("keyless spec create: expected 2xx, got %d: %s", status, body)
		}
		if strings.Contains(string(body), "keyless_enforcement_level") {
			t.Fatalf("a keyless spec must carry no keyless warning: %s", body)
		}
	})

	t.Run("LegacyKeyedSourceStillMints", func(t *testing.T) {
		port := h.GetLeaderPort(t)
		status, body := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", port, h.GetDefaultJWT(t))
		if status != 200 {
			t.Fatalf("a source created before enforce must keep serving: got %d: %s", status, body)
		}

		status, body = h.APIRequest(t, "GET", "sys/cred/sources/vault-e2e", port, "")
		if status != 200 {
			t.Fatalf("read vault-e2e: got %d: %s", status, body)
		}
		secrets, _ := h.JSONPath(h.ParseJSON(t, body), "data.stored_secrets").([]interface{})
		if len(secrets) != 1 || secrets[0] != "secret_id" {
			t.Fatalf("vault-e2e stored_secrets: want [secret_id], got %v", secrets)
		}
	})
}

func requireKeylessRefusal(t *testing.T, status int, body []byte) {
	t.Helper()
	if status != 400 {
		t.Fatalf("expected 400, got %d: %s", status, body)
	}
	if !strings.Contains(string(body), "keyless_enforcement_level=enforce refuses") {
		t.Fatalf("refusal does not name the setting: %s", body)
	}
}
