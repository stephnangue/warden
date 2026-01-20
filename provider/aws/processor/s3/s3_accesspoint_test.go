package s3

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/aws/processor"
)

func createAccessPointTestContext(service, region, host, path string) *processor.ProcessorContext {
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

func TestNewS3AccessPointProcessor(t *testing.T) {
	proxyDomains := []string{"example.com", "test.com"}
	proc := NewS3AccessPointProcessor(proxyDomains, nil)

	if proc == nil {
		t.Fatal("NewS3AccessPointProcessor returned nil")
	}
	if proc.Name() != "s3-accesspoint" {
		t.Errorf("Expected name 's3-accesspoint', got '%s'", proc.Name())
	}
	if proc.Priority() != 180 {
		t.Errorf("Expected priority 180, got %d", proc.Priority())
	}
	if len(proc.ProxyDomains) != 2 {
		t.Errorf("Expected 2 proxy domains, got %d", len(proc.ProxyDomains))
	}
}

func TestS3AccessPointProcessor_CanProcess(t *testing.T) {
	proxyDomains := []string{"example.com"}
	proc := NewS3AccessPointProcessor(proxyDomains, nil)

	tests := []struct {
		name     string
		service  string
		host     string
		expected bool
	}{
		{
			name:     "s3-accesspoint host pattern",
			service:  "s3",
			host:     "myap.s3-accesspoint.example.com",
			expected: true,
		},
		{
			name:     "accesspoint host pattern (multi-region)",
			service:  "s3",
			host:     "mrap-alias.accesspoint.example.com",
			expected: true,
		},
		{
			name:     "accesspoint keyword in name",
			service:  "s3",
			host:     "myaccesspoint.example.com",
			expected: true,
		},
		{
			name:     "bucket name ending with 12-digit account ID should NOT match",
			service:  "s3",
			host:     "bucket-tutorial-us-east-1-905418489750.example.com",
			expected: false, // Regular bucket, not access point
		},
		{
			name:     "bucket name with 12-digit suffix should NOT match",
			service:  "s3",
			host:     "my-bucket-123456789012.example.com",
			expected: false, // Regular bucket, not access point
		},
		{
			name:     "non-s3 service",
			service:  "ec2",
			host:     "myap.s3-accesspoint.example.com",
			expected: false,
		},
		{
			name:     "regular s3 bucket",
			service:  "s3",
			host:     "mybucket.s3.example.com",
			expected: false,
		},
		{
			name:     "aws domain (no rewrite)",
			service:  "s3",
			host:     "myap.s3-accesspoint.us-east-1.amazonaws.com",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createAccessPointTestContext(tt.service, "us-east-1", tt.host, "/key")
			got := proc.CanProcess(ctx)
			if got != tt.expected {
				t.Errorf("CanProcess() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestS3AccessPointProcessor_CanProcess_S3ControlRequests(t *testing.T) {
	proxyDomains := []string{"localhost"}
	proc := NewS3AccessPointProcessor(proxyDomains, nil)

	tests := []struct {
		name      string
		service   string
		host      string
		path      string
		accountID string // x-amz-account-id header
		expected  bool
	}{
		{
			name:      "S3 Control request with accesspoint ARN in path should be skipped",
			service:   "s3",
			host:      "905418489750.localhost",
			path:      "/v1/aws/gateway/v20180820/tags/arn:aws:s3:us-east-1:905418489750:accesspoint/my-accesspoint",
			accountID: "905418489750",
			expected:  false, // Should NOT be processed by S3AccessPointProcessor
		},
		{
			name:      "S3 Access Point data request without account-id header should be processed",
			service:   "s3",
			host:      "localhost",
			path:      "/v1/aws/gateway/arn:aws:s3:us-east-1:905418489750:accesspoint/my-accesspoint/mykey",
			accountID: "", // No account-id header
			expected:  true,
		},
		{
			name:      "S3 Control request with bucket ARN in path should be skipped",
			service:   "s3",
			host:      "905418489750.localhost",
			path:      "/v1/aws/gateway/v20180820/tags/arn:aws:s3:::my-bucket",
			accountID: "905418489750",
			expected:  false, // Should NOT be processed (even though path doesn't have accesspoint)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://"+tt.host+tt.path, nil)
			req.Host = tt.host
			if tt.accountID != "" {
				req.Header.Set("x-amz-account-id", tt.accountID)
			}

			ctx := &processor.ProcessorContext{
				LogicalRequest: &logical.Request{
					HTTPRequest: req,
					Path:        tt.path,
				},
				Service: tt.service,
				Region:  "us-east-1",
			}

			got := proc.CanProcess(ctx)
			if got != tt.expected {
				t.Errorf("CanProcess() = %v, want %v for %s", got, tt.expected, tt.name)
			}
		})
	}
}

func TestS3AccessPointProcessor_Process(t *testing.T) {
	proxyDomains := []string{"example.com"}
	proc := NewS3AccessPointProcessor(proxyDomains, nil)

	tests := []struct {
		name              string
		host              string
		path              string
		expectedTargetURL string
		expectedHost      string
		expectedPath      string
		expectedType      string
	}{
		{
			name:              "single region access point",
			host:              "myap.s3-accesspoint.example.com",
			path:              "gateway/mykey",
			expectedTargetURL: "https://myap.s3-accesspoint.us-east-1.amazonaws.com",
			expectedHost:      "myap.s3-accesspoint.us-east-1.amazonaws.com",
			expectedPath:      "/mykey",
			expectedType:      "single-region",
		},
		{
			name:              "access point with account ID",
			host:              "myap-123456789012.s3-accesspoint.example.com",
			path:              "gateway/object",
			expectedTargetURL: "https://myap-123456789012.s3-accesspoint.us-east-1.amazonaws.com",
			expectedHost:      "myap-123456789012.s3-accesspoint.us-east-1.amazonaws.com",
			expectedPath:      "/object",
			expectedType:      "single-region",
		},
		{
			name:              "multi-region access point",
			host:              "mrap-alias.accesspoint.example.com",
			path:              "gateway/mykey",
			expectedTargetURL: "https://mrap-alias.accesspoint.s3-global.amazonaws.com",
			expectedHost:      "mrap-alias.accesspoint.s3-global.amazonaws.com",
			expectedPath:      "/mykey",
			expectedType:      "multi-region",
		},
		{
			name:              "root path",
			host:              "myap.s3-accesspoint.example.com",
			path:              "gateway",
			expectedTargetURL: "https://myap.s3-accesspoint.us-east-1.amazonaws.com",
			expectedHost:      "myap.s3-accesspoint.us-east-1.amazonaws.com",
			expectedPath:      "/",
			expectedType:      "single-region",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createAccessPointTestContext("s3", "us-east-1", tt.host, tt.path)
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
			if result.Metadata["type"] != tt.expectedType {
				t.Errorf("type = %v, want %s", result.Metadata["type"], tt.expectedType)
			}
		})
	}
}

func TestS3AccessPointProcessor_Process_Error(t *testing.T) {
	proxyDomains := []string{"example.com"}
	proc := NewS3AccessPointProcessor(proxyDomains, nil)

	// Host that won't parse to access point info
	ctx := createAccessPointTestContext("s3", "us-east-1", "invalid", "/key")
	_, err := proc.Process(ctx)

	if err == nil {
		t.Error("Expected error for invalid host, got nil")
	}
}

func TestS3AccessPointProcessor_Process_DifferentRegions(t *testing.T) {
	proxyDomains := []string{"example.com"}
	proc := NewS3AccessPointProcessor(proxyDomains, nil)

	regions := []string{"us-east-1", "us-west-2", "eu-west-1", "ap-northeast-1"}

	for _, region := range regions {
		t.Run(region, func(t *testing.T) {
			ctx := createAccessPointTestContext("s3", region, "myap.s3-accesspoint.example.com", "gateway/key")
			result, err := proc.Process(ctx)

			if err != nil {
				t.Fatalf("Process() error = %v", err)
			}

			expectedURL := "https://myap.s3-accesspoint." + region + ".amazonaws.com"
			if result.TargetURL != expectedURL {
				t.Errorf("TargetURL = %s, want %s", result.TargetURL, expectedURL)
			}
		})
	}
}

func TestS3AccessPointProcessor_Metadata(t *testing.T) {
	proc := NewS3AccessPointProcessor([]string{}, nil)
	metadata := proc.Metadata()

	if metadata == nil {
		t.Fatal("Metadata() returned nil")
	}
	if len(metadata.ServiceNames) != 1 || metadata.ServiceNames[0] != "s3" {
		t.Errorf("Expected ServiceNames to contain 's3', got %v", metadata.ServiceNames)
	}
	if len(metadata.HostPatterns) != 3 {
		t.Errorf("Expected 3 host patterns, got %d", len(metadata.HostPatterns))
	}
	if metadata.Priority != 180 {
		t.Errorf("Expected Priority 180, got %d", metadata.Priority)
	}
}

func TestParseAccessPointName(t *testing.T) {
	proc := NewS3AccessPointProcessor([]string{}, nil)

	tests := []struct {
		name            string
		prefix          string
		expectedName    string
		expectedAccount string
		expectedMRAP    bool
	}{
		{
			name:            "simple access point",
			prefix:          "myaccesspoint",
			expectedName:    "myaccesspoint",
			expectedAccount: "",
			expectedMRAP:    false,
		},
		{
			name:            "access point with account ID",
			prefix:          "myap-123456789012",
			expectedName:    "myap",
			expectedAccount: "123456789012",
			expectedMRAP:    false,
		},
		{
			name:            "multi-region access point",
			prefix:          "mrap-alias",
			expectedName:    "mrap-alias",
			expectedAccount: "",
			expectedMRAP:    true,
		},
		{
			name:            "access point with dashes",
			prefix:          "my-ap-name-123456789012",
			expectedName:    "my-ap-name",
			expectedAccount: "123456789012",
			expectedMRAP:    false,
		},
		{
			name:            "access point with non-account suffix",
			prefix:          "my-ap-name-abc",
			expectedName:    "my-ap-name-abc",
			expectedAccount: "",
			expectedMRAP:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := proc.parseAccessPointName(tt.prefix)

			if info.Name != tt.expectedName {
				t.Errorf("Name = %s, want %s", info.Name, tt.expectedName)
			}
			if info.AccountID != tt.expectedAccount {
				t.Errorf("AccountID = %s, want %s", info.AccountID, tt.expectedAccount)
			}
			if info.IsMultiRegion != tt.expectedMRAP {
				t.Errorf("IsMultiRegion = %v, want %v", info.IsMultiRegion, tt.expectedMRAP)
			}
		})
	}
}

func TestIsAllDigits(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"123456789012", true},
		{"000000000000", true},
		{"1", true},
		{"", true}, // empty string has no non-digits
		{"12345678901a", false},
		{"abcdefghijkl", false},
		{"123-456-7890", false},
		{"12345 67890", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isAllDigits(tt.input)
			if got != tt.expected {
				t.Errorf("isAllDigits(%s) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func BenchmarkS3AccessPointProcessor_Process(b *testing.B) {
	proc := NewS3AccessPointProcessor([]string{"example.com"}, nil)
	ctx := createAccessPointTestContext("s3", "us-east-1", "myap.s3-accesspoint.example.com", "gateway/key")

	b.ResetTimer()
	for b.Loop() {
		proc.Process(ctx)
	}
}

func BenchmarkS3AccessPointProcessor_CanProcess(b *testing.B) {
	proc := NewS3AccessPointProcessor([]string{"example.com"}, nil)
	ctx := createAccessPointTestContext("s3", "us-east-1", "myap.s3-accesspoint.example.com", "gateway/key")

	b.ResetTimer()
	for b.Loop() {
		proc.CanProcess(ctx)
	}
}
