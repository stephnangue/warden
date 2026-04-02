package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOperator_Read(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/v1/secret/data/foo" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"key":"value"}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	resource, err := client.Operator().Read("secret/data/foo")
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if resource == nil {
		t.Fatal("expected resource, got nil")
	}
	if resource.Data["key"] != "value" {
		t.Errorf("expected key=value, got %v", resource.Data["key"])
	}
}

func TestOperator_ReadWithData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("version") != "2" {
			t.Error("expected version=2 query param")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"key":"v2"}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	resource, err := client.Operator().ReadWithData("secret/data/foo", map[string][]string{"version": {"2"}})
	if err != nil {
		t.Fatalf("ReadWithData failed: %v", err)
	}
	if resource.Data["key"] != "v2" {
		t.Errorf("unexpected data: %v", resource.Data)
	}
}

func TestOperator_Read_404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	resource, err := client.Operator().Read("secret/data/missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resource != nil {
		t.Errorf("expected nil resource for 404, got %v", resource)
	}
}

func TestOperator_Write(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		if r.URL.Path != "/v1/secret/data/foo" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"created":true}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	resource, err := client.Operator().Write("secret/data/foo", map[string]interface{}{"key": "value"})
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if resource == nil {
		t.Fatal("expected resource")
	}
}

func TestOperator_Delete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"deleted":true}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	resource, err := client.Operator().Delete("secret/data/foo")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if resource == nil {
		t.Fatal("expected resource")
	}
}

func TestOperator_DeleteWithData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		if r.URL.Query().Get("force") != "true" {
			t.Error("expected force=true query param")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"deleted":true}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	resource, err := client.Operator().DeleteWithData("secret/data/foo", map[string][]string{"force": {"true"}})
	if err != nil {
		t.Fatalf("DeleteWithData failed: %v", err)
	}
	if resource == nil {
		t.Fatal("expected resource")
	}
}

func TestOperator_Delete_404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	_, err := client.Operator().Delete("secret/data/missing")
	if err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestOperator_List(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Query().Get("warden-list") != "true" {
			t.Error("expected warden-list=true")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"keys":["a","b","c"]}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	resource, err := client.Operator().List("secret/metadata")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if resource == nil {
		t.Fatal("expected resource")
	}
}

func TestOperator_ReadRaw(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"raw":"content"}}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	resp, err := client.Operator().ReadRaw("secret/data/foo")
	if err != nil {
		t.Fatalf("ReadRaw failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestOperator_ReadRawWithData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != "val" {
			t.Error("expected key=val")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`ok`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	resp, err := client.Operator().ReadRawWithData("path", map[string][]string{"key": {"val"}})
	if err != nil {
		t.Fatalf("ReadRawWithData failed: %v", err)
	}
	resp.Body.Close()
}

func TestOperator_Write_404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Address = server.URL
	client, _ := NewClient(config)

	_, err := client.Operator().Write("secret/data/foo", map[string]interface{}{"k": "v"})
	if err == nil {
		t.Fatal("expected error for 404")
	}
}
