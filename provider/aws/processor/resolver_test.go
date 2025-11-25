package processor

import (
	"testing"
)

func TestEndpointResolver(t *testing.T) {
	resolver := NewEndpointResolver()

	tests := []struct {
		name     string
		service  string
		region   string
		expected string
		wantErr  bool
	}{
		// Global services
		{
			name:     "IAM global",
			service:  "iam",
			region:   "us-east-1",
			expected: "https://iam.amazonaws.com",
		},
		{
			name:     "CloudFront global",
			service:  "cloudfront",
			region:   "eu-west-1",
			expected: "https://cloudfront.amazonaws.com",
		},
		{
			name:     "IAM China",
			service:  "iam",
			region:   "cn-north-1",
			expected: "https://iam.cn-north-1.amazonaws.com.cn",
		},
		
		// Regional services
		{
			name:     "EC2 regional",
			service:  "ec2",
			region:   "us-east-1",
			expected: "https://ec2.us-east-1.amazonaws.com",
		},
		{
			name:     "Lambda regional",
			service:  "lambda",
			region:   "eu-west-1",
			expected: "https://lambda.eu-west-1.amazonaws.com",
		},
		
		// S3 special cases
		{
			name:     "S3 us-east-1",
			service:  "s3",
			region:   "us-east-1",
			expected: "https://s3.amazonaws.com",
		},
		{
			name:     "S3 other region",
			service:  "s3",
			region:   "eu-west-1",
			expected: "https://s3.eu-west-1.amazonaws.com",
		},
		{
			name:     "S3 China",
			service:  "s3",
			region:   "cn-north-1",
			expected: "https://s3.cn-north-1.amazonaws.com.cn",
		},
		
		// GovCloud
		{
			name:     "EC2 GovCloud",
			service:  "ec2",
			region:   "us-gov-west-1",
			expected: "https://ec2.us-gov-west-1.amazonaws.com",
		},
		
		// Errors
		{
			name:    "Empty service",
			service: "",
			region:  "us-east-1",
			wantErr: true,
		},
		{
			name:    "Empty region",
			service: "ec2",
			region:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolver.ResolveEndpoint(tt.service, tt.region)
			if (err != nil) != tt.wantErr {
				t.Errorf("ResolveEndpoint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.expected {
				t.Errorf("ResolveEndpoint() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func BenchmarkEndpointResolver(b *testing.B) {
	resolver := NewEndpointResolver()
	
	b.Run("cached", func(b *testing.B) {
		// First call to populate cache
		resolver.ResolveEndpoint("ec2", "us-east-1")
		
		b.ResetTimer()
		for b.Loop() {
			resolver.ResolveEndpoint("ec2", "us-east-1")
		}
	})
	
	b.Run("uncached", func(b *testing.B) {
		for b.Loop() {
			resolver.ClearCache()
			resolver.ResolveEndpoint("ec2", "us-east-1")
		}
	})
}