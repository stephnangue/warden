package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSys_PutPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/sys/policies/cbp/my-policy" {
			t.Errorf("expected path /v1/sys/policies/cbp/my-policy, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, err := NewClient(config)
	if err != nil {
		t.Fatal(err)
	}

	err = client.Sys().PutPolicy("my-policy", `path "secret/*" { capabilities = ["read"] }`)
	if err != nil {
		t.Fatalf("PutPolicy failed: %v", err)
	}
}

func TestSys_GetPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/v1/sys/policies/cbp/my-policy" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"name":"my-policy","policy":"path \"secret/*\" { capabilities = [\"read\"] }"}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	out, err := client.Sys().GetPolicy("my-policy")
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	if out.Name != "my-policy" {
		t.Errorf("expected name my-policy, got %s", out.Name)
	}
	if out.Policy == "" {
		t.Error("expected non-empty policy")
	}
}

func TestSys_GetPolicy_EmptyData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	_, err := client.Sys().GetPolicy("missing")
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestSys_ListPolicies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Query().Get("warden-list") != "true" {
			t.Error("expected warden-list=true query param")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"keys":["default","my-policy"]}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	keys, err := client.Sys().ListPolicies()
	if err != nil {
		t.Fatalf("ListPolicies failed: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	if keys[0] != "default" || keys[1] != "my-policy" {
		t.Errorf("unexpected keys: %v", keys)
	}
}

func TestSys_ListPolicies_NoKeys(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	keys, err := client.Sys().ListPolicies()
	if err != nil {
		t.Fatalf("ListPolicies failed: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected empty keys, got %v", keys)
	}
}

func TestSys_DeletePolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		if r.URL.Path != "/v1/sys/policies/cbp/my-policy" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	err := client.Sys().DeletePolicy("my-policy")
	if err != nil {
		t.Fatalf("DeletePolicy failed: %v", err)
	}
}
