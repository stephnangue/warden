package s3

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/aws/processor"
)

func createControlTestContext(service, region, host, path string) *processor.ProcessorContext {
	req := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
	req.Host = host

	return &processor.ProcessorContext{
		LogicalRequest: &logical.Request{
			HTTPRequest: req,
			Path:        path,
		},
		Service: service,
		Region:  region,
	}
}

func TestNewS3ControlProcessor(t *testing.T) {
	proxyDomains := []string{"example.com", "test.com"}
	proc := NewS3ControlProcessor(proxyDomains, nil)

	if proc == nil {
		t.Fatal("NewS3ControlProcessor returned nil")
	}
	if proc.Name() != "s3-control" {
		t.Errorf("Expected name 's3-control', got '%s'", proc.Name())
	}
	if proc.Priority() != 150 {
		t.Errorf("Expected priority 150, got %d", proc.Priority())
	}
	if len(proc.ProxyDomains) != 2 {
		t.Errorf("Expected 2 proxy domains, got %d", len(proc.ProxyDomains))
	}
}

func TestS3ControlProcessor_CanProcess(t *testing.T) {
	proxyDomains := []string{"example.com"}
	proc := NewS3ControlProcessor(proxyDomains, nil)

	tests := []struct {
		name     string
		service  string
		host     string
		expected bool
	}{
		{
			name:     "explicit s3-control service",
			service:  "s3-control",
			host:     "123456789012.example.com",
			expected: true,
		},
		{
			name:     "s3-control service with any host",
			service:  "s3-control",
			host:     "any.host.com",
			expected: true,
		},
		{
			name:     "non-s3-control service",
			service:  "ec2",
			host:     "ec2.example.com",
			expected: false,
		},
		{
			name:     "s3 service (not s3-control)",
			service:  "s3",
			host:     "mybucket.s3.example.com",
			expected: false,
		},
		{
			name:     "aws domain with s3-control service",
			service:  "s3-control",
			host:     "123456789012.s3-control.us-east-1.amazonaws.com",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createControlTestContext(tt.service, "us-east-1", tt.host, "/v20180820/configuration/publicAccessBlock")
			got := proc.CanProcess(ctx)
			if got != tt.expected {
				t.Errorf("CanProcess() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestS3ControlProcessor_CanProcess_WithAccountIDHeader(t *testing.T) {
	// Test that S3 Control requests are detected via x-amz-account-id header
	// This is important because AWS SDKs sign S3 Control requests with "s3" as the service
	proxyDomains := []string{"example.com"}
	proc := NewS3ControlProcessor(proxyDomains, nil)

	tests := []struct {
		name            string
		service         string
		host            string
		accountIDHeader string
		expected        bool
	}{
		{
			name:            "s3 service with x-amz-account-id header",
			service:         "s3",
			host:            "s3.example.com",
			accountIDHeader: "123456789012",
			expected:        true,
		},
		{
			name:            "s3 service without x-amz-account-id header",
			service:         "s3",
			host:            "mybucket.s3.example.com",
			accountIDHeader: "",
			expected:        false,
		},
		{
			name:            "ec2 service with x-amz-account-id header (should not match)",
			service:         "ec2",
			host:            "ec2.example.com",
			accountIDHeader: "123456789012",
			expected:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createControlTestContext(tt.service, "us-east-1", tt.host, "/v20180820/tags/s3:mybucket")
			if tt.accountIDHeader != "" {
				ctx.LogicalRequest.HTTPRequest.Header.Set("x-amz-account-id", tt.accountIDHeader)
			}
			got := proc.CanProcess(ctx)
			if got != tt.expected {
				t.Errorf("CanProcess() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestS3ControlProcessor_CanProcess_WithHostPattern(t *testing.T) {
	// The host-based detection requires a specific format: accountId.proxyDomain
	// where proxyDomain is a single-segment domain (like "localhost")
	proxyDomains := []string{"localhost"}
	proc := NewS3ControlProcessor(proxyDomains, nil)

	tests := []struct {
		name     string
		service  string
		host     string
		expected bool
	}{
		{
			name:     "12-digit account ID with single-segment proxy domain",
			service:  "s3", // Not s3-control, relies on host parsing
			host:     "123456789012.localhost",
			expected: true,
		},
		{
			name:     "non-12-digit prefix",
			service:  "s3",
			host:     "mybucket.localhost",
			expected: false,
		},
		{
			name:     "11-digit prefix (invalid)",
			service:  "s3",
			host:     "12345678901.localhost",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createControlTestContext(tt.service, "us-east-1", tt.host, "/v20180820/jobs")
			got := proc.CanProcess(ctx)
			if got != tt.expected {
				t.Errorf("CanProcess() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestS3ControlProcessor_Process(t *testing.T) {
	// The parseHost expects accountId.proxyDomain (exactly 2 parts)
	proxyDomains := []string{"localhost"}
	proc := NewS3ControlProcessor(proxyDomains, nil)

	tests := []struct {
		name              string
		host              string
		path              string
		expectedTargetURL string
		expectedHost      string
		expectedPath      string
	}{
		{
			name:              "standard control request",
			host:              "123456789012.localhost",
			path:              "gateway/v20180820/configuration/publicAccessBlock",
			expectedTargetURL: "https://123456789012.s3-control.us-east-1.amazonaws.com",
			expectedHost:      "123456789012.s3-control.us-east-1.amazonaws.com",
			expectedPath:      "/v20180820/configuration/publicAccessBlock",
		},
		{
			name:              "root path",
			host:              "123456789012.localhost",
			path:              "gateway",
			expectedTargetURL: "https://123456789012.s3-control.us-east-1.amazonaws.com",
			expectedHost:      "123456789012.s3-control.us-east-1.amazonaws.com",
			expectedPath:      "/",
		},
		{
			name:              "jobs endpoint",
			host:              "123456789012.localhost",
			path:              "gateway/v20180820/jobs",
			expectedTargetURL: "https://123456789012.s3-control.us-east-1.amazonaws.com",
			expectedHost:      "123456789012.s3-control.us-east-1.amazonaws.com",
			expectedPath:      "/v20180820/jobs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createControlTestContext("s3-control", "us-east-1", tt.host, tt.path)
			result, err := proc.Process(ctx)

			if err != nil {
				t.Fatalf("Process() error = %v", err)
			}
			if result.TargetURL != tt.expectedTargetURL {
				t.Errorf("TargetURL = %s, want %s", result.TargetURL, tt.expectedTargetURL)
			}
			if result.TargetHost != tt.expectedHost {
				t.Errorf("TargetHost = %s, want %s", result.TargetHost, tt.expectedHost)
			}
			if result.TransformedPath != tt.expectedPath {
				t.Errorf("TransformedPath = %s, want %s", result.TransformedPath, tt.expectedPath)
			}
			if result.Metadata["account_id"] != "123456789012" {
				t.Errorf("account_id = %v, want 123456789012", result.Metadata["account_id"])
			}
			if result.Metadata["api_type"] != "control" {
				t.Errorf("api_type = %v, want control", result.Metadata["api_type"])
			}
		})
	}
}

func TestS3ControlProcessor_Process_Error(t *testing.T) {
	proxyDomains := []string{"localhost"}
	proc := NewS3ControlProcessor(proxyDomains, nil)

	tests := []struct {
		name string
		host string
	}{
		{
			name: "no account ID extractable",
			host: "invalid.example.com",
		},
		{
			name: "short host",
			host: "x",
		},
		{
			name: "non-matching proxy domain",
			host: "123456789012.otherdomain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createControlTestContext("s3-control", "us-east-1", tt.host, "/key")
			_, err := proc.Process(ctx)

			if err == nil {
				t.Error("Expected error, got nil")
			}
		})
	}
}

func TestS3ControlProcessor_Process_InvalidAccountID(t *testing.T) {
	proxyDomains := []string{"localhost"}
	proc := NewS3ControlProcessor(proxyDomains, nil)

	tests := []struct {
		name string
		host string
	}{
		{
			name: "account ID too short",
			host: "12345678901.localhost",
		},
		{
			name: "account ID too long",
			host: "1234567890123.localhost",
		},
		{
			name: "account ID with letters",
			host: "12345678901a.localhost",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createControlTestContext("s3-control", "us-east-1", tt.host, "/key")
			_, err := proc.Process(ctx)

			if err == nil {
				t.Error("Expected error for invalid account ID, got nil")
			}
		})
	}
}

func TestS3ControlProcessor_Process_DifferentRegions(t *testing.T) {
	proxyDomains := []string{"localhost"}
	proc := NewS3ControlProcessor(proxyDomains, nil)

	regions := []string{"us-east-1", "us-west-2", "eu-west-1", "ap-northeast-1"}

	for _, region := range regions {
		t.Run(region, func(t *testing.T) {
			ctx := createControlTestContext("s3-control", region, "123456789012.localhost", "gateway/v20180820/configuration")
			result, err := proc.Process(ctx)

			if err != nil {
				t.Fatalf("Process() error = %v", err)
			}

			expectedURL := "https://123456789012.s3-control." + region + ".amazonaws.com"
			if result.TargetURL != expectedURL {
				t.Errorf("TargetURL = %s, want %s", result.TargetURL, expectedURL)
			}
		})
	}
}

func TestS3ControlProcessor_Process_WithAccountIDHeader(t *testing.T) {
	// Test that account ID can be extracted from x-amz-account-id header
	// This is important for S3 Control API requests like ListTagsForResource
	proxyDomains := []string{"example.com"}
	proc := NewS3ControlProcessor(proxyDomains, nil)

	tests := []struct {
		name              string
		host              string
		accountIDHeader   string
		expectedTargetURL string
		expectedHost      string
		expectError       bool
	}{
		{
			name:              "account ID from header only",
			host:              "s3-control.example.com",
			accountIDHeader:   "123456789012",
			expectedTargetURL: "https://123456789012.s3-control.us-east-1.amazonaws.com",
			expectedHost:      "123456789012.s3-control.us-east-1.amazonaws.com",
			expectError:       false,
		},
		{
			name:              "account ID from header overrides host",
			host:              "987654321098.example.com", // This won't match because it's not 2 parts
			accountIDHeader:   "123456789012",
			expectedTargetURL: "https://123456789012.s3-control.us-east-1.amazonaws.com",
			expectedHost:      "123456789012.s3-control.us-east-1.amazonaws.com",
			expectError:       false,
		},
		{
			name:            "invalid account ID in header",
			host:            "s3-control.example.com",
			accountIDHeader: "invalid",
			expectError:     true,
		},
		{
			name:            "account ID too short in header",
			host:            "s3-control.example.com",
			accountIDHeader: "12345678901",
			expectError:     true,
		},
		{
			name:            "account ID with letters in header",
			host:            "s3-control.example.com",
			accountIDHeader: "12345678901a",
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createControlTestContext("s3-control", "us-east-1", tt.host, "gateway/v20180820/accesspoint/my-ap/policy")

			// Set the x-amz-account-id header
			ctx.LogicalRequest.HTTPRequest.Header.Set("x-amz-account-id", tt.accountIDHeader)

			result, err := proc.Process(ctx)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Process() error = %v", err)
			}
			if result.TargetURL != tt.expectedTargetURL {
				t.Errorf("TargetURL = %s, want %s", result.TargetURL, tt.expectedTargetURL)
			}
			if result.TargetHost != tt.expectedHost {
				t.Errorf("TargetHost = %s, want %s", result.TargetHost, tt.expectedHost)
			}
			if result.Metadata["account_id"] != tt.accountIDHeader {
				t.Errorf("account_id = %v, want %s", result.Metadata["account_id"], tt.accountIDHeader)
			}
		})
	}
}

func TestS3ControlProcessor_Metadata(t *testing.T) {
	proc := NewS3ControlProcessor([]string{}, nil)
	metadata := proc.Metadata()

	if metadata == nil {
		t.Fatal("Metadata() returned nil")
	}
	if len(metadata.ServiceNames) != 2 {
		t.Errorf("Expected 2 service names, got %d", len(metadata.ServiceNames))
	}
	// Check both s3 and s3-control are in service names
	hasS3 := false
	hasS3Control := false
	for _, name := range metadata.ServiceNames {
		if name == "s3" {
			hasS3 = true
		}
		if name == "s3-control" {
			hasS3Control = true
		}
	}
	if !hasS3 || !hasS3Control {
		t.Errorf("Expected ServiceNames to contain 's3' and 's3-control', got %v", metadata.ServiceNames)
	}
	if metadata.Priority != 150 {
		t.Errorf("Expected Priority 150, got %d", metadata.Priority)
	}
}

func BenchmarkS3ControlProcessor_Process(b *testing.B) {
	proc := NewS3ControlProcessor([]string{"localhost"}, nil)
	ctx := createControlTestContext("s3-control", "us-east-1", "123456789012.localhost", "gateway/v20180820/configuration")

	b.ResetTimer()
	for b.Loop() {
		proc.Process(ctx)
	}
}

func BenchmarkS3ControlProcessor_CanProcess(b *testing.B) {
	proc := NewS3ControlProcessor([]string{"localhost"}, nil)
	ctx := createControlTestContext("s3-control", "us-east-1", "123456789012.localhost", "gateway/v20180820/configuration")

	b.ResetTimer()
	for b.Loop() {
		proc.CanProcess(ctx)
	}
}
