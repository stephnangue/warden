package processor

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stephnangue/warden/logical"
)

func createGenericTestContext(service, region, host, path string) *ProcessorContext {
	req := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
	req.Host = host

	return &ProcessorContext{
		LogicalRequest: &logical.Request{
			HTTPRequest: req,
			Path:        path,
		},
		Service: service,
		Region:  region,
	}
}

func TestNewGenericAWSProcessor(t *testing.T) {
	proxyDomains := []string{"example.com", "test.com"}
	proc := NewGenericAWSProcessor(proxyDomains, nil)

	if proc == nil {
		t.Fatal("NewGenericAWSProcessor returned nil")
	}
	if proc.Name() != "generic-aws" {
		t.Errorf("Expected name 'generic-aws', got '%s'", proc.Name())
	}
	if proc.Priority() != 10 {
		t.Errorf("Expected priority 10, got %d", proc.Priority())
	}
	if len(proc.ProxyDomains) != 2 {
		t.Errorf("Expected 2 proxy domains, got %d", len(proc.ProxyDomains))
	}
	if proc.resolver == nil {
		t.Error("Expected resolver to be initialized")
	}
}

func TestGenericAWSProcessor_CanProcess(t *testing.T) {
	proc := NewGenericAWSProcessor([]string{"example.com"}, nil)

	// GenericAWSProcessor should always return true (it's the catch-all)
	tests := []struct {
		name    string
		service string
		host    string
	}{
		{
			name:    "ec2 service",
			service: "ec2",
			host:    "ec2.example.com",
		},
		{
			name:    "lambda service",
			service: "lambda",
			host:    "lambda.example.com",
		},
		{
			name:    "unknown service",
			service: "unknown-service",
			host:    "unknown.example.com",
		},
		{
			name:    "empty service",
			service: "",
			host:    "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createGenericTestContext(tt.service, "us-east-1", tt.host, "/")
			if !proc.CanProcess(ctx) {
				t.Error("GenericAWSProcessor.CanProcess() should always return true")
			}
		})
	}
}

func TestGenericAWSProcessor_Process(t *testing.T) {
	proc := NewGenericAWSProcessor([]string{"example.com"}, nil)

	tests := []struct {
		name              string
		service           string
		region            string
		path              string
		expectedTargetURL string
		expectedHost      string
		expectedPath      string
	}{
		{
			name:              "EC2 request",
			service:           "ec2",
			region:            "us-east-1",
			path:              "gateway/",
			expectedTargetURL: "https://ec2.us-east-1.amazonaws.com",
			expectedHost:      "ec2.us-east-1.amazonaws.com",
			expectedPath:      "/",
		},
		{
			name:              "Lambda request",
			service:           "lambda",
			region:            "us-west-2",
			path:              "gateway/2015-03-31/functions",
			expectedTargetURL: "https://lambda.us-west-2.amazonaws.com",
			expectedHost:      "lambda.us-west-2.amazonaws.com",
			expectedPath:      "/2015-03-31/functions",
		},
		{
			name:              "DynamoDB request",
			service:           "dynamodb",
			region:            "eu-west-1",
			path:              "gateway",
			expectedTargetURL: "https://dynamodb.eu-west-1.amazonaws.com",
			expectedHost:      "dynamodb.eu-west-1.amazonaws.com",
			expectedPath:      "/",
		},
		{
			name:              "STS request",
			service:           "sts",
			region:            "us-east-1",
			path:              "gateway/",
			expectedTargetURL: "https://sts.us-east-1.amazonaws.com",
			expectedHost:      "sts.us-east-1.amazonaws.com",
			expectedPath:      "/",
		},
		{
			name:              "IAM global request",
			service:           "iam",
			region:            "us-east-1",
			path:              "gateway/",
			expectedTargetURL: "https://iam.amazonaws.com",
			expectedHost:      "iam.amazonaws.com",
			expectedPath:      "/",
		},
		{
			name:              "CloudFront global request",
			service:           "cloudfront",
			region:            "us-east-1",
			path:              "gateway/2020-05-31/distribution",
			expectedTargetURL: "https://cloudfront.amazonaws.com",
			expectedHost:      "cloudfront.amazonaws.com",
			expectedPath:      "/2020-05-31/distribution",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createGenericTestContext(tt.service, tt.region, tt.service+".example.com", tt.path)
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
			if result.Metadata["resolved_via"] != "endpoint_resolver" {
				t.Errorf("resolved_via = %v, want endpoint_resolver", result.Metadata["resolved_via"])
			}
		})
	}
}

func TestGenericAWSProcessor_Process_PathTransformation(t *testing.T) {
	proc := NewGenericAWSProcessor([]string{"example.com"}, nil)

	tests := []struct {
		name         string
		inputPath    string
		expectedPath string
	}{
		{
			name:         "gateway prefix stripped",
			inputPath:    "gateway/test/path",
			expectedPath: "/test/path",
		},
		{
			name:         "gateway only becomes root",
			inputPath:    "gateway",
			expectedPath: "/",
		},
		{
			name:         "gateway/ becomes root",
			inputPath:    "gateway/",
			expectedPath: "/",
		},
		{
			name:         "nested path",
			inputPath:    "gateway/a/b/c/d",
			expectedPath: "/a/b/c/d",
		},
		{
			name:         "path already starting with slash",
			inputPath:    "gateway//test",
			expectedPath: "/test", // Leading slash from gateway/ stripping, then /test
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createGenericTestContext("ec2", "us-east-1", "ec2.example.com", tt.inputPath)
			result, err := proc.Process(ctx)

			if err != nil {
				t.Fatalf("Process() error = %v", err)
			}
			if result.TransformedPath != tt.expectedPath {
				t.Errorf("TransformedPath = %s, want %s", result.TransformedPath, tt.expectedPath)
			}
		})
	}
}

func TestGenericAWSProcessor_Process_Error(t *testing.T) {
	proc := NewGenericAWSProcessor([]string{"example.com"}, nil)

	tests := []struct {
		name    string
		service string
		region  string
	}{
		{
			name:    "empty service",
			service: "",
			region:  "us-east-1",
		},
		{
			name:    "empty region",
			service: "ec2",
			region:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createGenericTestContext(tt.service, tt.region, "test.example.com", "gateway/")
			_, err := proc.Process(ctx)

			if err == nil {
				t.Error("Expected error, got nil")
			}
		})
	}
}

func TestGenericAWSProcessor_Process_DifferentPartitions(t *testing.T) {
	proc := NewGenericAWSProcessor([]string{"example.com"}, nil)

	tests := []struct {
		name              string
		region            string
		expectedURLSuffix string
	}{
		{
			name:              "standard partition",
			region:            "us-east-1",
			expectedURLSuffix: ".amazonaws.com",
		},
		{
			name:              "china partition",
			region:            "cn-north-1",
			expectedURLSuffix: ".amazonaws.com.cn",
		},
		{
			name:              "govcloud partition",
			region:            "us-gov-west-1",
			expectedURLSuffix: ".amazonaws.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createGenericTestContext("ec2", tt.region, "ec2.example.com", "gateway/")
			result, err := proc.Process(ctx)

			if err != nil {
				t.Fatalf("Process() error = %v", err)
			}
			if len(result.TargetURL) < len(tt.expectedURLSuffix) {
				t.Fatalf("TargetURL too short: %s", result.TargetURL)
			}
			suffix := result.TargetURL[len(result.TargetURL)-len(tt.expectedURLSuffix):]
			if suffix != tt.expectedURLSuffix {
				t.Errorf("TargetURL suffix = %s, want %s (full URL: %s)", suffix, tt.expectedURLSuffix, result.TargetURL)
			}
		})
	}
}

func TestGenericAWSProcessor_Metadata(t *testing.T) {
	proc := NewGenericAWSProcessor([]string{}, nil)
	metadata := proc.Metadata()

	if metadata == nil {
		t.Fatal("Metadata() returned nil")
	}
	if len(metadata.ServiceNames) != 0 {
		t.Errorf("Expected empty ServiceNames, got %v", metadata.ServiceNames)
	}
	if !metadata.FallbackOnly {
		t.Error("Expected FallbackOnly to be true")
	}
	if metadata.Priority != 10 {
		t.Errorf("Expected Priority 10, got %d", metadata.Priority)
	}
}

func BenchmarkGenericAWSProcessor_Process(b *testing.B) {
	proc := NewGenericAWSProcessor([]string{"example.com"}, nil)
	ctx := createGenericTestContext("ec2", "us-east-1", "ec2.example.com", "gateway/")

	b.ResetTimer()
	for b.Loop() {
		proc.Process(ctx)
	}
}

func BenchmarkGenericAWSProcessor_CanProcess(b *testing.B) {
	proc := NewGenericAWSProcessor([]string{"example.com"}, nil)
	ctx := createGenericTestContext("ec2", "us-east-1", "ec2.example.com", "gateway/")

	b.ResetTimer()
	for b.Loop() {
		proc.CanProcess(ctx)
	}
}
