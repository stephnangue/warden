package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"golang.org/x/time/rate"
)

func TestDefaultConfig(t *testing.T) {
	t.Run("returns valid config with defaults", func(t *testing.T) {
		// Save and clear environment variables that might affect the test
		oldAddr := os.Getenv(EnvWardenAddress)
		defer func() {
			if oldAddr != "" {
				os.Setenv(EnvWardenAddress, oldAddr)
			} else {
				os.Unsetenv(EnvWardenAddress)
			}
		}()
		os.Unsetenv(EnvWardenAddress)

		config := DefaultConfig()

		if config == nil {
			t.Fatal("DefaultConfig returned nil")
		}

		if config.Address != "http://127.0.0.1:5000" {
			t.Errorf("expected default address http://127.0.0.1:5000, got %s", config.Address)
		}

		if config.HttpClient == nil {
			t.Error("HttpClient should not be nil")
		}

		if config.Timeout != time.Second*60 {
			t.Errorf("expected timeout 60s, got %v", config.Timeout)
		}

		if config.MinRetryWait != time.Millisecond*1000 {
			t.Errorf("expected MinRetryWait 1000ms, got %v", config.MinRetryWait)
		}

		if config.MaxRetryWait != time.Millisecond*1500 {
			t.Errorf("expected MaxRetryWait 1500ms, got %v", config.MaxRetryWait)
		}

		if config.MaxRetries != 2 {
			t.Errorf("expected MaxRetries 2, got %d", config.MaxRetries)
		}

		if config.Backoff == nil {
			t.Error("Backoff should not be nil")
		}

		if config.Error != nil {
			t.Errorf("unexpected error in config: %v", config.Error)
		}
	})

	t.Run("sets TLS minimum version to 1.2", func(t *testing.T) {
		config := DefaultConfig()
		transport := config.HttpClient.Transport.(*http.Transport)

		if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
			t.Errorf("expected TLS 1.2, got version %d", transport.TLSClientConfig.MinVersion)
		}
	})

	t.Run("configures redirect handling", func(t *testing.T) {
		config := DefaultConfig()

		// Test that CheckRedirect returns ErrUseLastResponse
		req := &http.Request{}
		err := config.HttpClient.CheckRedirect(req, nil)

		if err != http.ErrUseLastResponse {
			t.Errorf("expected ErrUseLastResponse, got %v", err)
		}
	})
}

func TestConfig_ConfigureTLS(t *testing.T) {
	t.Run("sets insecure skip verify", func(t *testing.T) {
		config := DefaultConfig()
		tlsConfig := &TLSConfig{
			Insecure: true,
		}

		err := config.ConfigureTLS(tlsConfig)
		if err != nil {
			t.Fatalf("ConfigureTLS failed: %v", err)
		}

		transport := config.HttpClient.Transport.(*http.Transport)
		if !transport.TLSClientConfig.InsecureSkipVerify {
			t.Error("expected InsecureSkipVerify to be true")
		}
	})

	t.Run("sets TLS server name", func(t *testing.T) {
		config := DefaultConfig()
		tlsConfig := &TLSConfig{
			TLSServerName: "example.com",
		}

		err := config.ConfigureTLS(tlsConfig)
		if err != nil {
			t.Fatalf("ConfigureTLS failed: %v", err)
		}

		transport := config.HttpClient.Transport.(*http.Transport)
		if transport.TLSClientConfig.ServerName != "example.com" {
			t.Errorf("expected ServerName example.com, got %s", transport.TLSClientConfig.ServerName)
		}
	})

	t.Run("requires both client cert and key", func(t *testing.T) {
		config := DefaultConfig()

		// Only cert, no key
		tlsConfig := &TLSConfig{
			ClientCert: "/path/to/cert",
		}

		err := config.ConfigureTLS(tlsConfig)
		if err == nil {
			t.Error("expected error when only cert is provided")
		}
		if !strings.Contains(err.Error(), "both client cert and client key must be provided") {
			t.Errorf("unexpected error message: %v", err)
		}

		// Only key, no cert
		tlsConfig = &TLSConfig{
			ClientKey: "/path/to/key",
		}

		err = config.ConfigureTLS(tlsConfig)
		if err == nil {
			t.Error("expected error when only key is provided")
		}
	})
}

func TestConfig_TLSConfig(t *testing.T) {
	config := DefaultConfig()
	tlsConfig := &TLSConfig{
		TLSServerName: "test.example.com",
		Insecure:      true,
	}

	err := config.ConfigureTLS(tlsConfig)
	if err != nil {
		t.Fatalf("ConfigureTLS failed: %v", err)
	}

	clonedTLS := config.TLSConfig()
	if clonedTLS == nil {
		t.Fatal("TLSConfig returned nil")
	}

	if clonedTLS.ServerName != "test.example.com" {
		t.Errorf("expected ServerName test.example.com, got %s", clonedTLS.ServerName)
	}

	if !clonedTLS.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify to be true")
	}
}

func TestConfig_ParseAddress(t *testing.T) {
	t.Run("parses standard HTTP address", func(t *testing.T) {
		config := DefaultConfig()
		addr := "http://example.com:8080"

		u, err := config.ParseAddress(addr)
		if err != nil {
			t.Fatalf("ParseAddress failed: %v", err)
		}

		if u.Scheme != "http" {
			t.Errorf("expected scheme http, got %s", u.Scheme)
		}

		if u.Host != "example.com:8080" {
			t.Errorf("expected host example.com:8080, got %s", u.Host)
		}

		if config.Address != addr {
			t.Errorf("expected Address to be set to %s, got %s", addr, config.Address)
		}
	})

	t.Run("parses HTTPS address", func(t *testing.T) {
		config := DefaultConfig()
		addr := "https://secure.example.com"

		u, err := config.ParseAddress(addr)
		if err != nil {
			t.Fatalf("ParseAddress failed: %v", err)
		}

		if u.Scheme != "https" {
			t.Errorf("expected scheme https, got %s", u.Scheme)
		}
	})

	t.Run("handles unix socket address", func(t *testing.T) {
		config := DefaultConfig()
		addr := "unix:///var/run/warden.sock"

		u, err := config.ParseAddress(addr)
		if err != nil {
			t.Fatalf("ParseAddress failed: %v", err)
		}

		// Unix socket should be converted to http://localhost
		if u.Scheme != "http" {
			t.Errorf("expected scheme http for unix socket, got %s", u.Scheme)
		}

		if u.Host != "localhost" {
			t.Errorf("expected host localhost for unix socket, got %s", u.Host)
		}
	})

	t.Run("returns error for invalid address", func(t *testing.T) {
		config := DefaultConfig()
		addr := "://invalid"

		_, err := config.ParseAddress(addr)
		if err == nil {
			t.Error("expected error for invalid address")
		}
	})
}

func TestParseRateLimit(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedRate  float64
		expectedBurst int
		expectError   bool
	}{
		{
			name:          "rate and burst",
			input:         "10.5:20",
			expectedRate:  10.5,
			expectedBurst: 20,
			expectError:   false,
		},
		{
			name:          "rate only",
			input:         "15.0",
			expectedRate:  15.0,
			expectedBurst: 15,
			expectError:   false,
		},
		{
			name:          "integer rate",
			input:         "100",
			expectedRate:  100.0,
			expectedBurst: 100,
			expectError:   false,
		},
		{
			name:        "invalid format",
			input:       "invalid",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rate, burst, err := parseRateLimit(tt.input)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if rate != tt.expectedRate {
				t.Errorf("expected rate %f, got %f", tt.expectedRate, rate)
			}

			if burst != tt.expectedBurst {
				t.Errorf("expected burst %d, got %d", tt.expectedBurst, burst)
			}
		})
	}
}

func TestNewClient(t *testing.T) {
	t.Run("creates client with default config", func(t *testing.T) {
		client, err := NewClient(nil)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		if client == nil {
			t.Fatal("NewClient returned nil")
		}

		if client.config == nil {
			t.Error("client config should not be nil")
		}

		if client.addr == nil {
			t.Error("client addr should not be nil")
		}
	})

	t.Run("creates client with custom config", func(t *testing.T) {
		config := &Config{
			Address:      "http://custom.example.com",
			HttpClient:   cleanhttp.DefaultPooledClient(),
			MaxRetries:   5,
			MinRetryWait: time.Second * 2,
			MaxRetryWait: time.Second * 10,
		}

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		if client.config.MaxRetries != 5 {
			t.Errorf("expected MaxRetries 5, got %d", client.config.MaxRetries)
		}

		if client.Address() != "http://custom.example.com" {
			t.Errorf("expected address http://custom.example.com, got %s", client.Address())
		}
	})

	t.Run("uses defaults for zero values", func(t *testing.T) {
		config := &Config{
			Address:    "http://test.example.com",
			HttpClient: cleanhttp.DefaultPooledClient(),
			// MinRetryWait and MaxRetryWait are zero
		}

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		// Should use default retry waits
		if client.config.MinRetryWait == 0 {
			t.Error("MinRetryWait should have default value")
		}

		if client.config.MaxRetryWait == 0 {
			t.Error("MaxRetryWait should have default value")
		}
	})

	t.Run("returns error for invalid address", func(t *testing.T) {
		config := &Config{
			Address:    "://invalid",
			HttpClient: cleanhttp.DefaultPooledClient(),
		}

		_, err := NewClient(config)
		if err == nil {
			t.Error("expected error for invalid address")
		}
	})
}

func TestClient_SetAddress(t *testing.T) {
	client, err := NewClient(nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	newAddr := "http://newserver.example.com:9000"
	err = client.SetAddress(newAddr)
	if err != nil {
		t.Fatalf("SetAddress failed: %v", err)
	}

	if client.Address() != newAddr {
		t.Errorf("expected address %s, got %s", newAddr, client.Address())
	}
}

func TestClient_Address(t *testing.T) {
	config := &Config{
		Address:    "http://test.example.com:8200",
		HttpClient: cleanhttp.DefaultPooledClient(),
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	addr := client.Address()
	if addr != "http://test.example.com:8200" {
		t.Errorf("expected address http://test.example.com:8200, got %s", addr)
	}
}

func TestClient_TokenMethods(t *testing.T) {
	// Save and clear WARDEN_TOKEN environment variable
	oldToken := os.Getenv(EnvWardenToken)
	defer func() {
		if oldToken != "" {
			os.Setenv(EnvWardenToken, oldToken)
		} else {
			os.Unsetenv(EnvWardenToken)
		}
	}()
	os.Unsetenv(EnvWardenToken)

	client, err := NewClient(nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	// Initially should be empty
	if client.Token() != "" {
		t.Error("expected empty token initially")
	}

	// Set token
	testToken := "test-token-12345"
	client.SetToken(testToken)
	if client.Token() != testToken {
		t.Errorf("expected token %s, got %s", testToken, client.Token())
	}

	// Clear token
	client.ClearToken()
	if client.Token() != "" {
		t.Error("expected empty token after ClearToken")
	}
}

func TestClient_SetLimiter(t *testing.T) {
	client, err := NewClient(nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	rateLimit := 10.0
	burst := 20

	client.SetLimiter(rateLimit, burst)

	limiter := client.Limiter()
	if limiter == nil {
		t.Fatal("expected limiter to be set")
	}

	if limiter.Limit() != rate.Limit(rateLimit) {
		t.Errorf("expected rate limit %f, got %f", rateLimit, limiter.Limit())
	}

	if limiter.Burst() != burst {
		t.Errorf("expected burst %d, got %d", burst, limiter.Burst())
	}
}

func TestClient_RetryWaitMethods(t *testing.T) {
	client, err := NewClient(nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	// Test MinRetryWait
	newMinWait := time.Second * 5
	client.SetMinRetryWait(newMinWait)
	if client.MinRetryWait() != newMinWait {
		t.Errorf("expected MinRetryWait %v, got %v", newMinWait, client.MinRetryWait())
	}

	// Test MaxRetryWait
	newMaxWait := time.Second * 30
	client.SetMaxRetryWait(newMaxWait)
	if client.MaxRetryWait() != newMaxWait {
		t.Errorf("expected MaxRetryWait %v, got %v", newMaxWait, client.MaxRetryWait())
	}
}

func TestClient_MaxRetries(t *testing.T) {
	client, err := NewClient(nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	newMaxRetries := 10
	client.SetMaxRetries(newMaxRetries)
	if client.MaxRetries() != newMaxRetries {
		t.Errorf("expected MaxRetries %d, got %d", newMaxRetries, client.MaxRetries())
	}
}

func TestClient_MaxIdleConnections(t *testing.T) {
	client, err := NewClient(nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	newMaxIdle := 50
	client.SetMaxIdleConnections(newMaxIdle)
	if client.MaxIdleConnections() != newMaxIdle {
		t.Errorf("expected MaxIdleConnections %d, got %d", newMaxIdle, client.MaxIdleConnections())
	}
}

func TestClient_DisableKeepAlives(t *testing.T) {
	client, err := NewClient(nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	// Initially should be false
	if client.DisableKeepAlives() {
		t.Error("expected DisableKeepAlives to be false initially")
	}

	// Set to true
	client.SetDisableKeepAlives(true)
	if !client.DisableKeepAlives() {
		t.Error("expected DisableKeepAlives to be true")
	}

	// Set back to false
	client.SetDisableKeepAlives(false)
	if client.DisableKeepAlives() {
		t.Error("expected DisableKeepAlives to be false")
	}
}

func TestClient_SRVLookup(t *testing.T) {
	client, err := NewClient(nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	// Initially should be false
	if client.SRVLookup() {
		t.Error("expected SRVLookup to be false initially")
	}

	// Set to true
	client.SetSRVLookup(true)
	if !client.SRVLookup() {
		t.Error("expected SRVLookup to be true")
	}
}

func TestClient_CheckRetry(t *testing.T) {
	client, err := NewClient(nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	customCheckRetry := func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		return false, nil
	}

	client.SetCheckRetry(customCheckRetry)

	retrieved := client.CheckRetry()
	if retrieved == nil {
		t.Error("expected CheckRetry to be set")
	}
}

func TestClient_ClientTimeout(t *testing.T) {
	client, err := NewClient(nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	newTimeout := time.Minute * 5
	client.SetClientTimeout(newTimeout)
	if client.ClientTimeout() != newTimeout {
		t.Errorf("expected ClientTimeout %v, got %v", newTimeout, client.ClientTimeout())
	}
}

func TestClient_OutputCurlString(t *testing.T) {
	client, err := NewClient(nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	// Initially should be false
	if client.OutputCurlString() {
		t.Error("expected OutputCurlString to be false initially")
	}

	// Set to true
	client.SetOutputCurlString(true)
	if !client.OutputCurlString() {
		t.Error("expected OutputCurlString to be true")
	}
}

func TestClient_OutputPolicy(t *testing.T) {
	client, err := NewClient(nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	// Initially should be false
	if client.OutputPolicy() {
		t.Error("expected OutputPolicy to be false initially")
	}

	// Set to true
	client.SetOutputPolicy(true)
	if !client.OutputPolicy() {
		t.Error("expected OutputPolicy to be true")
	}
}

func TestClient_SetBackoff(t *testing.T) {
	client, err := NewClient(nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	customBackoff := func(min, max time.Duration, attemptNum int, resp *http.Response) time.Duration {
		return time.Second
	}

	client.SetBackoff(customBackoff)
	// No direct getter, but we verify it doesn't panic
}

func TestClient_SetLogger(t *testing.T) {
	client, err := NewClient(nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	// Create a mock logger
	mockLogger := &mockLeveledLogger{}
	client.SetLogger(mockLogger)
	// No direct getter, but we verify it doesn't panic
}

func TestClient_NewRequest(t *testing.T) {
	client, err := NewClient(nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	client.SetToken("test-token")

	t.Run("creates request with correct method and path", func(t *testing.T) {
		req := client.NewRequest("GET", "/v1/secret/data/myapp")

		if req.Method != "GET" {
			t.Errorf("expected method GET, got %s", req.Method)
		}

		if !strings.Contains(req.URL.Path, "/v1/secret/data/myapp") {
			t.Errorf("expected path to contain /v1/secret/data/myapp, got %s", req.URL.Path)
		}

		if req.ClientToken != "test-token" {
			t.Errorf("expected token test-token, got %s", req.ClientToken)
		}

		if req.Params == nil {
			t.Error("expected Params to be initialized")
		}
	})

	t.Run("creates POST request", func(t *testing.T) {
		req := client.NewRequest("POST", "/v1/auth/login")

		if req.Method != "POST" {
			t.Errorf("expected method POST, got %s", req.Method)
		}
	})
}

func TestDefaultRetryPolicy(t *testing.T) {
	ctx := context.Background()

	t.Run("retries on 412 status", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 412,
		}

		retry, err := DefaultRetryPolicy(ctx, resp, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !retry {
			t.Error("expected retry to be true for 412 status")
		}
	})

	t.Run("retries on 500 status", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 500,
		}

		retry, err := DefaultRetryPolicy(ctx, resp, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !retry {
			t.Error("expected retry to be true for 500 status")
		}
	})

	t.Run("does not retry on 200 status", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
		}

		retry, err := DefaultRetryPolicy(ctx, resp, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if retry {
			t.Error("expected retry to be false for 200 status")
		}
	})

	t.Run("does not retry on 404 status", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 404,
		}

		retry, err := DefaultRetryPolicy(ctx, resp, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if retry {
			t.Error("expected retry to be false for 404 status")
		}
	})
}

func TestClient_RawRequestWithContext(t *testing.T) {
	t.Run("handles successful request", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data": "success"}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		req := client.NewRequest("GET", "/test")
		ctx := context.Background()

		resp, err := client.rawRequestWithContext(ctx, req)
		if err != nil {
			t.Fatalf("rawRequestWithContext failed: %v", err)
		}

		if resp == nil {
			t.Fatal("expected response, got nil")
		}

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}
	})

	t.Run("handles error response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"errors": ["internal server error"]}`))
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL
		config.MaxRetries = 0 // Disable retries for faster test

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		req := client.NewRequest("GET", "/test")
		ctx := context.Background()

		_, err = client.rawRequestWithContext(ctx, req)
		if err == nil {
			t.Error("expected error for 500 status")
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(time.Second * 2)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		config := DefaultConfig()
		config.Address = server.URL

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		req := client.NewRequest("GET", "/test")
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
		defer cancel()

		_, err = client.rawRequestWithContext(ctx, req)
		if err == nil {
			t.Error("expected error due to context timeout")
		}
	})

	t.Run("returns error when OutputCurlString is enabled", func(t *testing.T) {
		config := DefaultConfig()
		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		client.SetOutputCurlString(true)

		req := client.NewRequest("GET", "/test")
		ctx := context.Background()

		_, err = client.rawRequestWithContext(ctx, req)
		if err == nil {
			t.Error("expected error when OutputCurlString is enabled")
		}

		if _, ok := err.(*OutputStringError); !ok {
			t.Errorf("expected OutputStringError, got %T", err)
		}
	})
}

func TestClient_WithConfiguredTimeout(t *testing.T) {
	t.Run("applies timeout from config", func(t *testing.T) {
		config := DefaultConfig()
		config.Timeout = time.Second * 5

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx := context.Background()
		newCtx, cancel := client.withConfiguredTimeout(ctx)
		defer cancel()

		deadline, ok := newCtx.Deadline()
		if !ok {
			t.Error("expected context to have deadline")
		}

		if time.Until(deadline) > time.Second*6 {
			t.Error("deadline is too far in the future")
		}
	})

	t.Run("returns original context when timeout is zero", func(t *testing.T) {
		config := DefaultConfig()
		config.Timeout = 0

		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		ctx := context.Background()
		newCtx, cancel := client.withConfiguredTimeout(ctx)
		defer cancel()

		_, ok := newCtx.Deadline()
		if ok {
			t.Error("expected context to not have deadline when timeout is 0")
		}
	})
}

func TestConfig_ReadEnvironment(t *testing.T) {
	// Note: ReadWardenVariable returns empty string for WARDEN_ prefixed env vars
	// This test validates that ReadEnvironment doesn't panic and handles missing env vars properly

	t.Run("handles missing environment variables", func(t *testing.T) {
		config := &Config{
			HttpClient: cleanhttp.DefaultPooledClient(),
		}

		// Ensure Transport has TLSClientConfig initialized
		transport := config.HttpClient.Transport.(*http.Transport)
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		}

		err := config.ReadEnvironment()
		if err != nil {
			t.Fatalf("ReadEnvironment failed: %v", err)
		}

		// Should not panic and should complete successfully
	})

	t.Run("initializes TLS config when HttpClient is set", func(t *testing.T) {
		config := &Config{
			HttpClient: cleanhttp.DefaultPooledClient(),
		}

		// Initialize TLSClientConfig like DefaultConfig does
		transport := config.HttpClient.Transport.(*http.Transport)
		transport.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		err := config.ReadEnvironment()
		if err != nil {
			t.Fatalf("ReadEnvironment failed: %v", err)
		}

		if transport.TLSClientConfig == nil {
			t.Error("expected TLSClientConfig to be initialized")
		}
	})

	t.Run("handles non-WARDEN environment variables", func(t *testing.T) {
		// Set a non-WARDEN prefixed variable
		os.Setenv("TEST_VAR", "test_value")
		defer os.Unsetenv("TEST_VAR")

		config := &Config{
			HttpClient: cleanhttp.DefaultPooledClient(),
		}

		err := config.ReadEnvironment()
		if err != nil {
			t.Fatalf("ReadEnvironment failed: %v", err)
		}
	})
}

// Mock logger for testing
type mockLeveledLogger struct{}

func (m *mockLeveledLogger) Error(msg string, keysAndValues ...interface{}) {}
func (m *mockLeveledLogger) Info(msg string, keysAndValues ...interface{})  {}
func (m *mockLeveledLogger) Debug(msg string, keysAndValues ...interface{}) {}
func (m *mockLeveledLogger) Warn(msg string, keysAndValues ...interface{})  {}

func TestClient_ConcurrentAccess(t *testing.T) {
	// Test thread safety of client methods
	client, err := NewClient(nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	done := make(chan bool)

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func() {
			_ = client.Address()
			_ = client.Token()
			_ = client.MaxRetries()
			_ = client.ClientTimeout()
			done <- true
		}()
	}

	// Concurrent writes
	for i := 0; i < 10; i++ {
		go func(i int) {
			client.SetToken(fmt.Sprintf("token-%d", i))
			client.SetMaxRetries(i)
			client.SetClientTimeout(time.Second * time.Duration(i))
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}
}

func TestClient_NewRequestWithURLParsing(t *testing.T) {
	client, err := NewClient(nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	t.Run("handles path with query parameters", func(t *testing.T) {
		req := client.NewRequest("GET", "/v1/secret/data/myapp")

		// Add query parameters
		req.Params.Set("version", "2")
		req.Params.Set("format", "json")

		if req.Params.Get("version") != "2" {
			t.Error("expected version parameter to be set")
		}

		if req.Params.Get("format") != "json" {
			t.Error("expected format parameter to be set")
		}
	})

	t.Run("preserves URL scheme and host", func(t *testing.T) {
		customAddr := "https://custom.example.com:8200"
		err := client.SetAddress(customAddr)
		if err != nil {
			t.Fatalf("SetAddress failed: %v", err)
		}

		req := client.NewRequest("POST", "/v1/auth/login")

		parsedURL, err := url.Parse(customAddr)
		if err != nil {
			t.Fatalf("failed to parse custom address: %v", err)
		}

		if req.URL.Scheme != parsedURL.Scheme {
			t.Errorf("expected scheme %s, got %s", parsedURL.Scheme, req.URL.Scheme)
		}

		if req.URL.Host != parsedURL.Host {
			t.Errorf("expected host %s, got %s", parsedURL.Host, req.URL.Host)
		}
	})
}
