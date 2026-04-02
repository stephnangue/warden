package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSys_Init(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/sys/init" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"root_token":"s.root123","keys":["key1","key2"],"keys_base64":["a2V5MQ==","a2V5Mg=="],"recovery_keys":["rk1"],"recovery_keys_base64":["cmsx"]}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	resp, err := client.Sys().Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if resp.RootToken != "s.root123" {
		t.Errorf("expected root token s.root123, got %s", resp.RootToken)
	}
	if len(resp.Keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(resp.Keys))
	}
	if len(resp.KeysBase64) != 2 {
		t.Errorf("expected 2 keys_base64, got %d", len(resp.KeysBase64))
	}
	if len(resp.RecoveryKeys) != 1 {
		t.Errorf("expected 1 recovery key, got %d", len(resp.RecoveryKeys))
	}
	if len(resp.RecoveryKeysBase64) != 1 {
		t.Errorf("expected 1 recovery_keys_base64, got %d", len(resp.RecoveryKeysBase64))
	}
}

func TestSys_InitWithRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"root_token":"s.custom","keys":["k1"]}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	resp, err := client.Sys().InitWithRequest(&InitRequest{
		SecretShares:    5,
		SecretThreshold: 3,
	})
	if err != nil {
		t.Fatalf("InitWithRequest failed: %v", err)
	}
	if resp.RootToken != "s.custom" {
		t.Errorf("expected s.custom, got %s", resp.RootToken)
	}
}

func TestSys_RevokeRootToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/sys/revoke-root-token" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	err := client.Sys().RevokeRootToken()
	if err != nil {
		t.Fatalf("RevokeRootToken failed: %v", err)
	}
}
