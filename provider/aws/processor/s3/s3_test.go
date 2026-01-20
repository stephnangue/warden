package s3

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/aws/processor"
)

func createS3TestContext(service, region, host, path string) *processor.ProcessorContext {
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

func TestNewS3Processor(t *testing.T) {
	proxyDomains := []string{"example.com", "test.com"}
	proc := NewS3Processor(proxyDomains, nil)

	if proc == nil {
		t.Fatal("NewS3Processor returned nil")
	}
	if proc.Name() != "s3" {
		t.Errorf("Expected name 's3', got '%s'", proc.Name())
	}
	if proc.Priority() != 100 {
		t.Errorf("Expected priority 100, got %d", proc.Priority())
	}
	if len(proc.ProxyDomains) != 2 {
		t.Errorf("Expected 2 proxy domains, got %d", len(proc.ProxyDomains))
	}
}

func TestS3Processor_CanProcess(t *testing.T) {
	proxyDomains := []string{"example.com"}
	proc := NewS3Processor(proxyDomains, nil)

	tests := []struct {
		name     string
		service  string
		host     string
		expected bool
	}{
		{
			name:     "standard s3 request",
			service:  "s3",
			host:     "mybucket.s3.example.com",
			expected: true,
		},
		{
			name:     "non-s3 service",
			service:  "ec2",
			host:     "ec2.example.com",
			expected: false,
		},
		{
			name:     "s3 with aws domain (no rewrite needed)",
			service:  "s3",
			host:     "mybucket.s3.us-east-1.amazonaws.com",
			expected: true,
		},
		{
			name:     "directory bucket should not be processed",
			service:  "s3",
			host:     "mybucket--usw2-az1--x-s3.s3.example.com",
			expected: false,
		},
		{
			name:     "access point host should not be processed by S3 processor",
			service:  "s3",
			host:     "myaccesspoint.s3-accesspoint.example.com",
			expected: false, // S3AccessPointProcessor handles this pattern
		},
		{
			name:     "s3-control service",
			service:  "s3-control",
			host:     "123456789012.example.com",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createS3TestContext(tt.service, "us-east-1", tt.host, "/key")
			got := proc.CanProcess(ctx)
			if got != tt.expected {
				t.Errorf("CanProcess() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestS3Processor_Process(t *testing.T) {
	proxyDomains := []string{"example.com"}
	proc := NewS3Processor(proxyDomains, nil)

	tests := []struct {
		name              string
		host              string
		path              string
		expectedTargetURL string
		expectedHost      string
		expectedPath      string
		expectedStyle     string
	}{
		{
			name:              "virtual-hosted style bucket",
			host:              "mybucket.s3.example.com",
			path:              "gateway/mykey",
			expectedTargetURL: "https://mybucket.s3.us-east-1.amazonaws.com",
			expectedHost:      "mybucket.s3.us-east-1.amazonaws.com",
			expectedPath:      "/mykey",
			expectedStyle:     "virtual-hosted",
		},
		{
			name:              "path style (no bucket in host)",
			host:              "s3.example.com",
			path:              "gateway/mybucket/mykey",
			expectedTargetURL: "https://s3.us-east-1.amazonaws.com",
			expectedHost:      "s3.us-east-1.amazonaws.com",
			expectedPath:      "/mybucket/mykey",
			expectedStyle:     "path",
		},
		{
			name:              "root path",
			host:              "mybucket.s3.example.com",
			path:              "gateway",
			expectedTargetURL: "https://mybucket.s3.us-east-1.amazonaws.com",
			expectedHost:      "mybucket.s3.us-east-1.amazonaws.com",
			expectedPath:      "/",
			expectedStyle:     "virtual-hosted",
		},
		{
			name:              "nested path",
			host:              "mybucket.s3.example.com",
			path:              "gateway/folder/subfolder/file.txt",
			expectedTargetURL: "https://mybucket.s3.us-east-1.amazonaws.com",
			expectedHost:      "mybucket.s3.us-east-1.amazonaws.com",
			expectedPath:      "/folder/subfolder/file.txt",
			expectedStyle:     "virtual-hosted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createS3TestContext("s3", "us-east-1", tt.host, tt.path)
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
			if result.Metadata["style"] != tt.expectedStyle {
				t.Errorf("style = %s, want %s", result.Metadata["style"], tt.expectedStyle)
			}
		})
	}
}

func TestS3Processor_Process_DifferentRegions(t *testing.T) {
	proxyDomains := []string{"example.com"}
	proc := NewS3Processor(proxyDomains, nil)

	regions := []string{"us-east-1", "us-west-2", "eu-west-1", "ap-northeast-1"}

	for _, region := range regions {
		t.Run(region, func(t *testing.T) {
			ctx := createS3TestContext("s3", region, "mybucket.s3.example.com", "gateway/key")
			result, err := proc.Process(ctx)

			if err != nil {
				t.Fatalf("Process() error = %v", err)
			}

			expectedURL := "https://mybucket.s3." + region + ".amazonaws.com"
			if result.TargetURL != expectedURL {
				t.Errorf("TargetURL = %s, want %s", result.TargetURL, expectedURL)
			}
		})
	}
}

func TestS3Processor_Process_AWSGlobalRegion(t *testing.T) {
	proxyDomains := []string{"localhost"}
	proc := NewS3Processor(proxyDomains, nil)

	// aws-global is a pseudo-region used by the AWS SDK for certain global operations
	// It should be normalized to us-east-1 for S3
	ctx := createS3TestContext("s3", "aws-global", "mybucket.localhost", "/gateway/key")
	result, err := proc.Process(ctx)

	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	// aws-global should be normalized to us-east-1
	expectedURL := "https://mybucket.s3.us-east-1.amazonaws.com"
	if result.TargetURL != expectedURL {
		t.Errorf("TargetURL = %s, want %s", result.TargetURL, expectedURL)
	}
}

func TestS3Processor_Process_BucketWithDots(t *testing.T) {
	proxyDomains := []string{"localhost"}
	proc := NewS3Processor(proxyDomains, nil)

	// Test bucket names with dots like "my.bucket.name"
	// Buckets with dots must use path-style because AWS wildcard TLS certificate
	// (*.s3.amazonaws.com) doesn't cover multiple subdomain levels
	ctx := createS3TestContext("s3", "us-east-1", "my.bucket.name.localhost", "/gateway/key")
	result, err := proc.Process(ctx)

	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	// Buckets with dots should use path-style URL
	expectedURL := "https://s3.us-east-1.amazonaws.com"
	if result.TargetURL != expectedURL {
		t.Errorf("TargetURL = %s, want %s", result.TargetURL, expectedURL)
	}

	if result.Metadata["bucket_name"] != "my.bucket.name" {
		t.Errorf("bucket_name = %s, want my.bucket.name", result.Metadata["bucket_name"])
	}

	if result.Metadata["style"] != "path" {
		t.Errorf("style = %s, want path", result.Metadata["style"])
	}

	// Path should include bucket name for path-style
	expectedPath := "/my.bucket.name/key"
	if result.TransformedPath != expectedPath {
		t.Errorf("TransformedPath = %s, want %s", result.TransformedPath, expectedPath)
	}
}

func TestS3Processor_Metadata(t *testing.T) {
	proc := NewS3Processor([]string{}, nil)
	metadata := proc.Metadata()

	if metadata == nil {
		t.Fatal("Metadata() returned nil")
	}
	if len(metadata.ServiceNames) != 1 || metadata.ServiceNames[0] != "s3" {
		t.Errorf("Expected ServiceNames to contain 's3', got %v", metadata.ServiceNames)
	}
	if metadata.Priority != 100 {
		t.Errorf("Expected Priority 100, got %d", metadata.Priority)
	}
}

func TestIsDirectoryBucket(t *testing.T) {
	tests := []struct {
		name       string
		bucketName string
		expected   bool
	}{
		{
			name:       "valid directory bucket",
			bucketName: "mybucket--usw2-az1--x-s3",
			expected:   true,
		},
		{
			name:       "valid directory bucket with different zone",
			bucketName: "test-bucket--use1-az2--x-s3",
			expected:   true,
		},
		{
			name:       "regular bucket",
			bucketName: "my-regular-bucket",
			expected:   false,
		},
		{
			name:       "bucket with dashes",
			bucketName: "my--bucket--name",
			expected:   false,
		},
		{
			name:       "almost directory bucket - wrong suffix",
			bucketName: "mybucket--usw2-az1--x-s4",
			expected:   false,
		},
		{
			name:       "almost directory bucket - missing x-s3",
			bucketName: "mybucket--usw2-az1",
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDirectoryBucket(tt.bucketName)
			if got != tt.expected {
				t.Errorf("isDirectoryBucket(%s) = %v, want %v", tt.bucketName, got, tt.expected)
			}
		})
	}
}

func BenchmarkS3Processor_Process(b *testing.B) {
	proc := NewS3Processor([]string{"example.com"}, nil)
	ctx := createS3TestContext("s3", "us-east-1", "mybucket.s3.example.com", "gateway/key")

	b.ResetTimer()
	for b.Loop() {
		proc.Process(ctx)
	}
}

func BenchmarkS3Processor_CanProcess(b *testing.B) {
	proc := NewS3Processor([]string{"example.com"}, nil)
	ctx := createS3TestContext("s3", "us-east-1", "mybucket.s3.example.com", "gateway/key")

	b.ResetTimer()
	for b.Loop() {
		proc.CanProcess(ctx)
	}
}
