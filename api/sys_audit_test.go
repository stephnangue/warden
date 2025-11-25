package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSys_ListAudit(t *testing.T) {
	t.Run("successfully lists audit backends", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/sys/audit" {
				t.Errorf("expected path /v1/sys/audit, got %s", r.URL.Path)
			}
			if r.Method != http.MethodGet {
				t.Errorf("expected GET method, got %s", r.Method)
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": {
					"file/": {
						"type": "file",
						"description": "File audit backend",
						"accessor": "file_accessor_123",
						"config": {
							"file_path": "/var/log/audit.log"
						}
					},
					"syslog/": {
						"type": "syslog",
						"description": "Syslog audit backend",
						"accessor": "syslog_accessor_456",
						"config": {
							"facility": "local0"
						}
					}
				}
			}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		audits, err := client.Sys().ListAudit()
		if err != nil {
			t.Fatalf("ListAudit failed: %v", err)
		}

		if audits == nil {
			t.Fatal("expected audits map, got nil")
		}

		if len(audits) != 2 {
			t.Errorf("expected 2 audit backends, got %d", len(audits))
		}

		fileAudit, ok := audits["file/"]
		if !ok {
			t.Fatal("expected file/ audit backend")
		}

		if fileAudit.Type != "file" {
			t.Errorf("expected type file, got %s", fileAudit.Type)
		}

		if fileAudit.Description != "File audit backend" {
			t.Errorf("expected description 'File audit backend', got %s", fileAudit.Description)
		}

		if fileAudit.Accessor != "file_accessor_123" {
			t.Errorf("expected accessor file_accessor_123, got %s", fileAudit.Accessor)
		}

		syslogAudit, ok := audits["syslog/"]
		if !ok {
			t.Fatal("expected syslog/ audit backend")
		}

		if syslogAudit.Type != "syslog" {
			t.Errorf("expected type syslog, got %s", syslogAudit.Type)
		}
	})

	t.Run("returns error for server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"errors": ["internal server error"]}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL
		config.MaxRetries = 0

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		_, err = client.Sys().ListAudit()
		if err == nil {
			t.Error("expected error for 500 status")
		}
	})

	t.Run("returns error for empty response data", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		_, err = client.Sys().ListAudit()
		if err == nil {
			t.Error("expected error for empty data")
		}
		if err.Error() != "data from server response is empty" {
			t.Errorf("expected 'data from server response is empty' error, got: %v", err)
		}
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`invalid json`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		_, err = client.Sys().ListAudit()
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})

	t.Run("handles empty audit backends list", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data": {}}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		audits, err := client.Sys().ListAudit()
		if err != nil {
			t.Fatalf("ListAudit failed: %v", err)
		}

		if len(audits) != 0 {
			t.Errorf("expected empty audit backends map, got %d entries", len(audits))
		}
	})
}

func TestSys_ListAuditWithContext(t *testing.T) {
	t.Run("successfully lists audit backends with context", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": {
					"file/": {
						"type": "file",
						"description": "File audit backend",
						"accessor": "file_accessor_123"
					}
				}
			}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx := context.Background()
		audits, err := client.Sys().ListAuditWithContext(ctx)
		if err != nil {
			t.Fatalf("ListAuditWithContext failed: %v", err)
		}

		if len(audits) != 1 {
			t.Errorf("expected 1 audit backend, got %d", len(audits))
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(time.Second * 2)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data": {}}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
		defer cancel()

		_, err = client.Sys().ListAuditWithContext(ctx)
		if err == nil {
			t.Error("expected error due to context timeout")
		}
	})

	t.Run("respects context deadline", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(time.Millisecond * 500)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data": {}}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Millisecond*50))
		defer cancel()

		_, err = client.Sys().ListAuditWithContext(ctx)
		if err == nil {
			t.Error("expected error due to context deadline")
		}
	})
}

func TestSys_EnableAudit(t *testing.T) {
	t.Run("successfully enables audit backend", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/sys/audit/file" {
				t.Errorf("expected path /v1/sys/audit/file, got %s", r.URL.Path)
			}
			if r.Method != http.MethodPut {
				t.Errorf("expected PUT method, got %s", r.Method)
			}

			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		auditInput := &AuditInput{
			Type:        "file",
			Description: "Test file audit backend",
			Config: map[string]any{
				"file_path": "/var/log/audit.log",
			},
		}

		err = client.Sys().EnableAudit("file", auditInput)
		if err != nil {
			t.Fatalf("EnableAudit failed: %v", err)
		}
	})

	t.Run("returns error for server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"errors": ["invalid audit type"]}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL
		config.MaxRetries = 0

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		auditInput := &AuditInput{
			Type: "invalid",
		}

		err = client.Sys().EnableAudit("test", auditInput)
		if err == nil {
			t.Error("expected error for invalid audit type")
		}
	})

	t.Run("handles path with special characters", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/sys/audit/my-audit-backend" {
				t.Errorf("expected path /v1/sys/audit/my-audit-backend, got %s", r.URL.Path)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		auditInput := &AuditInput{
			Type: "file",
		}

		err = client.Sys().EnableAudit("my-audit-backend", auditInput)
		if err != nil {
			t.Fatalf("EnableAudit failed: %v", err)
		}
	})

	t.Run("handles audit backend with complex config", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		auditInput := &AuditInput{
			Type:        "socket",
			Description: "Socket audit backend",
			Config: map[string]any{
				"address":     "127.0.0.1:9090",
				"socket_type": "tcp",
				"format":      "json",
			},
		}

		err = client.Sys().EnableAudit("socket", auditInput)
		if err != nil {
			t.Fatalf("EnableAudit failed: %v", err)
		}
	})
}

func TestSys_EnableAuditWithContext(t *testing.T) {
	t.Run("successfully enables audit backend with context", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx := context.Background()
		auditInput := &AuditInput{
			Type: "file",
		}

		err = client.Sys().EnableAuditWithContext(ctx, "file", auditInput)
		if err != nil {
			t.Fatalf("EnableAuditWithContext failed: %v", err)
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(time.Second * 2)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
		defer cancel()

		auditInput := &AuditInput{
			Type: "file",
		}

		err = client.Sys().EnableAuditWithContext(ctx, "file", auditInput)
		if err == nil {
			t.Error("expected error due to context timeout")
		}
	})

	t.Run("handles nil audit input", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx := context.Background()
		err = client.Sys().EnableAuditWithContext(ctx, "file", nil)
		if err != nil {
			t.Fatalf("EnableAuditWithContext with nil input failed: %v", err)
		}
	})
}

func TestSys_DisableAudit(t *testing.T) {
	t.Run("successfully disables audit backend", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/sys/audit/file" {
				t.Errorf("expected path /v1/sys/audit/file, got %s", r.URL.Path)
			}
			if r.Method != http.MethodDelete {
				t.Errorf("expected DELETE method, got %s", r.Method)
			}

			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		err = client.Sys().DisableAudit("file")
		if err != nil {
			t.Fatalf("DisableAudit failed: %v", err)
		}
	})

	t.Run("returns error for non-existent audit backend", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"errors": ["audit backend not found"]}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL
		config.MaxRetries = 0

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		err = client.Sys().DisableAudit("nonexistent")
		if err == nil {
			t.Error("expected error for non-existent audit backend")
		}
	})

	t.Run("handles path with special characters", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/sys/audit/my-audit-backend" {
				t.Errorf("expected path /v1/sys/audit/my-audit-backend, got %s", r.URL.Path)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		err = client.Sys().DisableAudit("my-audit-backend")
		if err != nil {
			t.Fatalf("DisableAudit failed: %v", err)
		}
	})

	t.Run("returns error for server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"errors": ["internal server error"]}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL
		config.MaxRetries = 0

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		err = client.Sys().DisableAudit("file")
		if err == nil {
			t.Error("expected error for 500 status")
		}
	})
}

func TestSys_DisableAuditWithContext(t *testing.T) {
	t.Run("successfully disables audit backend with context", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx := context.Background()
		err = client.Sys().DisableAuditWithContext(ctx, "file")
		if err != nil {
			t.Fatalf("DisableAuditWithContext failed: %v", err)
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(time.Second * 2)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
		defer cancel()

		err = client.Sys().DisableAuditWithContext(ctx, "file")
		if err == nil {
			t.Error("expected error due to context timeout")
		}
	})

	t.Run("respects context deadline", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(time.Millisecond * 500)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Millisecond*50))
		defer cancel()

		err = client.Sys().DisableAuditWithContext(ctx, "file")
		if err == nil {
			t.Error("expected error due to context deadline")
		}
	})
}

func TestSys_AuditE2E(t *testing.T) {
	t.Run("complete audit lifecycle", func(t *testing.T) {
		// Track state across multiple requests
		auditEnabled := false

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				// List audits
				if auditEnabled {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{
						"data": {
							"file/": {
								"type": "file",
								"description": "File audit backend",
								"accessor": "file_accessor_123"
							}
						}
					}`))
				} else {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"data": {}}`))
				}
			case http.MethodPut:
				// Enable audit
				auditEnabled = true
				w.WriteHeader(http.StatusNoContent)
			case http.MethodDelete:
				// Disable audit
				auditEnabled = false
				w.WriteHeader(http.StatusNoContent)
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		// Initially, no audits should be enabled
		audits, err := client.Sys().ListAudit()
		if err != nil {
			t.Fatalf("ListAudit failed: %v", err)
		}
		if len(audits) != 0 {
			t.Errorf("expected 0 audits initially, got %d", len(audits))
		}

		// Enable an audit backend
		auditInput := &AuditInput{
			Type:        "file",
			Description: "File audit backend",
		}
		err = client.Sys().EnableAudit("file/", auditInput)
		if err != nil {
			t.Fatalf("EnableAudit failed: %v", err)
		}

		// Verify audit is enabled
		audits, err = client.Sys().ListAudit()
		if err != nil {
			t.Fatalf("ListAudit failed: %v", err)
		}
		if len(audits) != 1 {
			t.Errorf("expected 1 audit backend, got %d", len(audits))
		}

		// Disable the audit backend
		err = client.Sys().DisableAudit("file/")
		if err != nil {
			t.Fatalf("DisableAudit failed: %v", err)
		}

		// Verify audit is disabled
		audits, err = client.Sys().ListAudit()
		if err != nil {
			t.Fatalf("ListAudit failed: %v", err)
		}
		if len(audits) != 0 {
			t.Errorf("expected 0 audits after disable, got %d", len(audits))
		}
	})
}

func TestAuditTypeAliases(t *testing.T) {
	t.Run("AuditInput is alias of MountInput", func(t *testing.T) {
		var auditInput AuditInput
		var mountInput MountInput

		// Should have the same fields
		auditInput = AuditInput{
			Type:        "file",
			Description: "Test",
			Config:      map[string]any{"key": "value"},
		}

		mountInput = MountInput{
			Type:        "file",
			Description: "Test",
			Config:      map[string]any{"key": "value"},
		}

		// Since they're aliases, they should be assignable
		auditInput = AuditInput(mountInput)
		if auditInput.Type != "file" {
			t.Error("type alias assignment failed")
		}
	})

	t.Run("Audit is alias of MountOutput", func(t *testing.T) {
		var audit Audit
		var mountOutput MountOutput

		audit = Audit{
			Type:        "file",
			Description: "Test",
			Accessor:    "accessor_123",
			Config:      map[string]any{"key": "value"},
		}

		mountOutput = MountOutput{
			Type:        "file",
			Description: "Test",
			Accessor:    "accessor_123",
			Config:      map[string]any{"key": "value"},
		}

		// Since they're aliases, they should be assignable
		audit = Audit(mountOutput)
		if audit.Type != "file" {
			t.Error("type alias assignment failed")
		}
	})
}
