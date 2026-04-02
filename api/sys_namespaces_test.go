package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSys_CreateNamespace(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/sys/namespaces/ns1" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"id":"ns-123","path":"ns1/","message":"namespace created","custom_metadata":{"env":"prod"}}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	out, err := client.Sys().CreateNamespace("ns1", &CreateNamespaceInput{
		CustomMetadata: map[string]string{"env": "prod"},
	})
	if err != nil {
		t.Fatalf("CreateNamespace failed: %v", err)
	}
	if out.ID != "ns-123" {
		t.Errorf("expected id ns-123, got %s", out.ID)
	}
	if out.Path != "ns1/" {
		t.Errorf("expected path ns1/, got %s", out.Path)
	}
	if out.Message != "namespace created" {
		t.Errorf("unexpected message: %s", out.Message)
	}
	if out.CustomMetadata["env"] != "prod" {
		t.Errorf("expected custom_metadata env=prod, got %v", out.CustomMetadata)
	}
}

func TestSys_CreateNamespace_NilInput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"id":"ns-456","path":"ns2/"}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	out, err := client.Sys().CreateNamespace("ns2", nil)
	if err != nil {
		t.Fatalf("CreateNamespace with nil input failed: %v", err)
	}
	if out.ID != "ns-456" {
		t.Errorf("expected id ns-456, got %s", out.ID)
	}
}

func TestSys_GetNamespace(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"id":"ns-123","path":"ns1/","locked":false,"tainted":true,"uuid":"abc-def","custom_metadata":{"team":"infra"}}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	out, err := client.Sys().GetNamespace("ns1")
	if err != nil {
		t.Fatalf("GetNamespace failed: %v", err)
	}
	if out.ID != "ns-123" {
		t.Errorf("expected id ns-123, got %s", out.ID)
	}
	if !out.Tainted {
		t.Error("expected tainted=true")
	}
	if out.Locked {
		t.Error("expected locked=false")
	}
	if out.Uuid != "abc-def" {
		t.Errorf("expected uuid abc-def, got %s", out.Uuid)
	}
	if out.CustomMetadata["team"] != "infra" {
		t.Errorf("unexpected custom_metadata: %v", out.CustomMetadata)
	}
}

func TestSys_ListNamespaces(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("warden-list") != "true" {
			t.Error("expected warden-list=true")
		}
		if r.URL.Query().Get("recursive") != "true" {
			t.Error("expected recursive=true")
		}
		if r.URL.Query().Get("include_parent") != "true" {
			t.Error("expected include_parent=true")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"namespaces":[{"id":"ns-1","path":"ns1/"},{"id":"ns-2","path":"ns2/","custom_metadata":{"k":"v"}}]}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	nss, err := client.Sys().ListNamespaces(true, true)
	if err != nil {
		t.Fatalf("ListNamespaces failed: %v", err)
	}
	if len(nss) != 2 {
		t.Fatalf("expected 2 namespaces, got %d", len(nss))
	}
	if nss[0].ID != "ns-1" {
		t.Errorf("expected ns-1, got %s", nss[0].ID)
	}
	if nss[1].CustomMetadata["k"] != "v" {
		t.Errorf("expected custom_metadata k=v, got %v", nss[1].CustomMetadata)
	}
}

func TestSys_ListNamespaces_Empty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	nss, err := client.Sys().ListNamespaces(false, false)
	if err != nil {
		t.Fatalf("ListNamespaces failed: %v", err)
	}
	if len(nss) != 0 {
		t.Errorf("expected empty, got %d", len(nss))
	}
}

func TestSys_UpdateNamespace(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"id":"ns-123","path":"ns1/","message":"namespace updated","custom_metadata":{"env":"staging"}}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	out, err := client.Sys().UpdateNamespace("ns1", &UpdateNamespaceInput{
		CustomMetadata: map[string]string{"env": "staging"},
	})
	if err != nil {
		t.Fatalf("UpdateNamespace failed: %v", err)
	}
	if out.Message != "namespace updated" {
		t.Errorf("unexpected message: %s", out.Message)
	}
	if out.CustomMetadata["env"] != "staging" {
		t.Errorf("unexpected custom_metadata: %v", out.CustomMetadata)
	}
}

func TestSys_UpdateNamespace_NilInput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"id":"ns-123","path":"ns1/","message":"ok"}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	_, err := client.Sys().UpdateNamespace("ns1", nil)
	if err != nil {
		t.Fatalf("UpdateNamespace with nil input failed: %v", err)
	}
}

func TestSys_DeleteNamespace(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		if r.URL.Path != "/v1/sys/namespaces/ns1" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	err := client.Sys().DeleteNamespace("ns1")
	if err != nil {
		t.Fatalf("DeleteNamespace failed: %v", err)
	}
}
