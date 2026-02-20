package gcp

import (
	"net/http"
	"testing"
	"time"

	"github.com/stephnangue/warden/framework"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGatewayPath(t *testing.T) {
	b := &gcpBackend{}

	tests := []struct {
		name      string
		path      string
		wantHost  string
		wantPath  string
		wantErr   bool
		errSubstr string
	}{
		{
			name:     "standard path",
			path:     "/gcp/gateway/storage.googleapis.com/storage/v1/b/my-bucket",
			wantHost: "storage.googleapis.com",
			wantPath: "/storage/v1/b/my-bucket",
		},
		{
			name:     "host only",
			path:     "/gcp/gateway/storage.googleapis.com",
			wantHost: "storage.googleapis.com",
			wantPath: "/",
		},
		{
			name:     "compute host with path",
			path:     "/gcp/gateway/compute.googleapis.com/compute/v1/projects/my-project/zones",
			wantHost: "compute.googleapis.com",
			wantPath: "/compute/v1/projects/my-project/zones",
		},
		{
			name:     "bigquery host",
			path:     "/gcp/gateway/bigquery.googleapis.com/bigquery/v2/projects/my-project/datasets",
			wantHost: "bigquery.googleapis.com",
			wantPath: "/bigquery/v2/projects/my-project/datasets",
		},
		{
			name:     "secret manager",
			path:     "/gcp/gateway/secretmanager.googleapis.com/v1/projects/my-project/secrets/my-secret",
			wantHost: "secretmanager.googleapis.com",
			wantPath: "/v1/projects/my-project/secrets/my-secret",
		},
		{
			name:     "transparent mode path",
			path:     "/gcp/role/myrole/gateway/storage.googleapis.com/storage/v1/b",
			wantHost: "storage.googleapis.com",
			wantPath: "/storage/v1/b",
		},
		{
			name:      "bare gateway",
			path:      "/gcp/gateway",
			wantErr:   true,
			errSubstr: "no GCP host specified",
		},
		{
			name:      "no gateway marker",
			path:      "/gcp/config",
			wantErr:   true,
			errSubstr: "invalid gateway path",
		},
		{
			name:      "empty after gateway",
			path:      "/gcp/gateway/",
			wantErr:   true,
			errSubstr: "no GCP host specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, gcpPath, err := b.parseGatewayPath(tt.path)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantHost, host)
				assert.Equal(t, tt.wantPath, gcpPath)
			}
		})
	}
}

func TestBuildTargetURL(t *testing.T) {
	b := &gcpBackend{}

	tests := []struct {
		name     string
		host     string
		path     string
		rawQuery string
		want     string
	}{
		{
			name: "simple path",
			host: "storage.googleapis.com",
			path: "/storage/v1/b/my-bucket",
			want: "https://storage.googleapis.com/storage/v1/b/my-bucket",
		},
		{
			name:     "path with query",
			host:     "compute.googleapis.com",
			path:     "/compute/v1/projects/my-project/zones",
			rawQuery: "maxResults=10&pageToken=abc",
			want:     "https://compute.googleapis.com/compute/v1/projects/my-project/zones?maxResults=10&pageToken=abc",
		},
		{
			name: "root path",
			host: "storage.googleapis.com",
			path: "/",
			want: "https://storage.googleapis.com/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := b.buildTargetURL(tt.host, tt.path, tt.rawQuery)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestPrepareHeaders(t *testing.T) {
	b := &gcpBackend{}

	t.Run("removes security headers and injects bearer", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com", nil)
		req.Header.Set("Authorization", "Bearer old-token")
		req.Header.Set("X-Warden-Token", "warden-token")
		req.Header.Set("X-Custom", "keep-me")

		b.prepareHeaders(req, "new-gcp-token")

		assert.Equal(t, "Bearer new-gcp-token", req.Header.Get("Authorization"))
		assert.Empty(t, req.Header.Get("X-Warden-Token"))
		assert.Equal(t, "keep-me", req.Header.Get("X-Custom"))
	})

	t.Run("no bearer token injection when empty", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com", nil)
		req.Header.Set("Authorization", "Bearer old-token")

		b.prepareHeaders(req, "")

		assert.Empty(t, req.Header.Get("Authorization"))
	})

	t.Run("removes hop-by-hop headers", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com", nil)
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Keep-Alive", "timeout=5")
		req.Header.Set("Transfer-Encoding", "chunked")

		b.prepareHeaders(req, "token")

		assert.Empty(t, req.Header.Get("Connection"))
		assert.Empty(t, req.Header.Get("Keep-Alive"))
		assert.Empty(t, req.Header.Get("Transfer-Encoding"))
	})

	t.Run("removes connection-listed headers", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com", nil)
		req.Header.Set("Connection", "X-Custom-Hop")
		req.Header.Set("X-Custom-Hop", "value")

		b.prepareHeaders(req, "token")

		assert.Empty(t, req.Header.Get("X-Custom-Hop"))
	})
}

func TestParseConfig(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		config := parseConfig(map[string]any{})
		assert.Equal(t, framework.DefaultMaxBodySize, config.MaxBodySize)
		assert.Equal(t, framework.DefaultTimeout, config.Timeout)
		assert.False(t, config.TransparentMode)
	})

	t.Run("custom values", func(t *testing.T) {
		config := parseConfig(map[string]any{
			"max_body_size":    float64(5242880),
			"timeout":          "60s",
			"transparent_mode": true,
			"auto_auth_path":   "auth/jwt/",
			"default_role":     "my-role",
		})
		assert.Equal(t, int64(5242880), config.MaxBodySize)
		assert.Equal(t, 60*time.Second, config.Timeout)
		assert.True(t, config.TransparentMode)
		assert.Equal(t, "auth/jwt/", config.AutoAuthPath)
		assert.Equal(t, "my-role", config.DefaultRole)
	})

	t.Run("timeout as integer seconds", func(t *testing.T) {
		config := parseConfig(map[string]any{
			"timeout": 45,
		})
		assert.Equal(t, 45*time.Second, config.Timeout)
	})
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]any
		wantErr bool
		errMsg  string
	}{
		{
			name:    "empty config is valid",
			config:  map[string]any{},
			wantErr: false,
		},
		{
			name:    "unknown key",
			config:  map[string]any{"unknown_key": "value"},
			wantErr: true,
			errMsg:  "unknown configuration key",
		},
		{
			name:    "negative max_body_size",
			config:  map[string]any{"max_body_size": -1},
			wantErr: true,
			errMsg:  "max_body_size must be greater than 0",
		},
		{
			name:    "max_body_size too large",
			config:  map[string]any{"max_body_size": 200000000},
			wantErr: true,
			errMsg:  "must not exceed",
		},
		{
			name:    "invalid timeout format",
			config:  map[string]any{"timeout": "not-a-duration"},
			wantErr: true,
			errMsg:  "invalid timeout format",
		},
		{
			name:    "transparent_mode wrong type",
			config:  map[string]any{"transparent_mode": "yes"},
			wantErr: true,
			errMsg:  "transparent_mode must be a boolean",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.config)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestExtractToken(t *testing.T) {
	t.Run("X-Warden-Token header", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com", nil)
		req.Header.Set("X-Warden-Token", "warden-token-123")
		assert.Equal(t, "warden-token-123", extractToken(req))
	})

	t.Run("Authorization Bearer header", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com", nil)
		req.Header.Set("Authorization", "Bearer bearer-token-456")
		assert.Equal(t, "bearer-token-456", extractToken(req))
	})

	t.Run("X-Warden-Token takes priority", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com", nil)
		req.Header.Set("X-Warden-Token", "warden-token")
		req.Header.Set("Authorization", "Bearer bearer-token")
		assert.Equal(t, "warden-token", extractToken(req))
	})

	t.Run("no token", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com", nil)
		assert.Empty(t, extractToken(req))
	})

	t.Run("non-bearer auth header", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com", nil)
		req.Header.Set("Authorization", "Basic abc123")
		assert.Empty(t, extractToken(req))
	})
}
