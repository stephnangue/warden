//go:build e2e

package provider

import (
	"fmt"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestVaultTransparentStandby verifies transparent vault gateway through standby (T17).
func TestVaultTransparentStandby(t *testing.T) {
	standby := h.GetStandbyPort(t)
	jwt := h.GetDefaultJWT(t)

	status, _ := h.VaultTransparentRequest(t, "GET", "secret/data/e2e/app-config", "e2e-reader", standby, jwt)
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}
}

// TestExpiredJWT verifies expired JWT is rejected with 401/403 (T18).
func TestExpiredJWT(t *testing.T) {
	jwt := h.GetJWT(t, "e2e-ephemeral", "ephemeral-secret")
	time.Sleep(3 * time.Second)

	leader := h.GetLeaderPort(t)
	u := fmt.Sprintf("%s/v1/vault/role/e2e-reader/gateway/v1/secret/data/e2e/app-config", h.NodeURL(leader))
	status, _ := h.DoRequest(t, "GET", u, map[string]string{"Authorization": "Bearer " + jwt}, "")
	if status != 401 && status != 403 {
		t.Fatalf("expected 401 or 403, got %d", status)
	}
}

// TestInvalidJWT verifies garbage JWT is rejected with 401/403 (T19).
func TestInvalidJWT(t *testing.T) {
	leader := h.GetLeaderPort(t)
	fakeJWT := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmYWtlIn0.invalid-signature"

	u := fmt.Sprintf("%s/v1/vault/role/e2e-reader/gateway/v1/secret/data/e2e/app-config", h.NodeURL(leader))
	status, _ := h.DoRequest(t, "GET", u, map[string]string{"Authorization": "Bearer " + fakeJWT}, "")
	if status != 401 && status != 403 {
		t.Fatalf("expected 401 or 403, got %d", status)
	}
}
