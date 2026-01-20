package s3

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/provider/aws/processor"
)

var (
	// Regex to detect directory bucket names: {name}--{zone-id}--x-s3
	directoryBucketRegex = regexp.MustCompile(`^(.+)--([a-z0-9]+-az\d+)--x-s3$`)
)

// S3Processor handles standard S3 requests
type S3Processor struct {
	processor.BaseProcessor
	log *logger.GatedLogger
}

// NewS3Processor creates a new S3 processor
func NewS3Processor(proxyDomains []string, log *logger.GatedLogger) *S3Processor {
	return &S3Processor{
		BaseProcessor: processor.BaseProcessor{
			ProcName:     "s3",
			ProcPriority: 100,
			ProxyDomains: proxyDomains,
		},
		log: log,
	}
}

// CanProcess determines if this is a standard S3 request
func (p *S3Processor) CanProcess(ctx *processor.ProcessorContext) bool {
	// Check if service is explicitly s3
	if ctx.Service == "s3" {
		// Make sure it's not a directory bucket or access point or s3 control request
		hostRewrite := p.parseHost(ctx)
		if hostRewrite != nil && hostRewrite.Prefix != "" {
			// Check it's not a directory bucket
			if isDirectoryBucket(hostRewrite.Prefix) {
				return false
			}
			// Check it's not an access point (has 'accesspoint' in name)
			if strings.Contains(hostRewrite.Prefix, "accesspoint") {
				return false
			}
			// Check it's not an s3 control request
			if ctx.Service == "s3-control" {
				return false
			}
		}

		// Check for Access Point ARN in path (for AWS_ENDPOINT_URL usage)
		// These should be handled by S3AccessPointProcessor
		path := ctx.LogicalRequest.HTTPRequest.URL.Path
		if p.containsAccessPointARN(path) {
			return false
		}

		return true
	}

	return false
}

// containsAccessPointARN checks if the path contains an S3 Access Point or MRAP ARN
func (p *S3Processor) containsAccessPointARN(path string) bool {
	// Check for accesspoint in the path which indicates an ARN
	// ARN format: arn:aws:s3:region:account-id:accesspoint/name
	// or MRAP: arn:aws:s3::account-id:accesspoint/alias
	return strings.Contains(path, ":accesspoint/")
}

// Process handles S3 request transformation
func (p *S3Processor) Process(ctx *processor.ProcessorContext) (*processor.ProcessorResult, error) {
	hostRewrite := p.parseHost(ctx)
	// p.log.Debug("Host rewritten",
	// 	logger.Any("new_host", hostRewrite),
	// 	logger.String("request_id", middleware.GetReqID(ctx.Ctx)),
	// )
	result := &processor.ProcessorResult{
		Service:  "s3",
		Metadata: make(map[string]interface{}),
	}

	// Normalize region: aws-global is a pseudo-region that should map to us-east-1 for S3
	region := ctx.Region
	if region == "aws-global" {
		region = "us-east-1"
		// Set SigningRegion so the request is re-signed with the correct region
		result.SigningRegion = region
	}

	// Handle virtual-hosted-style URL
	if hostRewrite != nil && hostRewrite.Prefix != "" {
		bucketName := hostRewrite.Prefix
		result.Metadata["bucket_name"] = bucketName

		// Bucket names with dots cannot use virtual-hosted style over HTTPS
		// because AWS's wildcard certificate (*.s3.amazonaws.com) doesn't cover
		// multiple subdomain levels. Use path-style for these buckets.
		if strings.Contains(bucketName, ".") {
			// Path-style for buckets with dots: s3.region.amazonaws.com/bucket-name/key
			result.TargetURL = fmt.Sprintf("https://s3.%s.amazonaws.com", region)
			result.TargetHost = fmt.Sprintf("s3.%s.amazonaws.com", region)
			result.Metadata["style"] = "path"
			result.Metadata["bucket_with_dots"] = true
		} else {
			// Virtual-hosted-style: bucket-name.s3.region.amazonaws.com
			result.TargetURL = fmt.Sprintf("https://%s.s3.%s.amazonaws.com",
				bucketName, region)
			result.TargetHost = fmt.Sprintf("%s.s3.%s.amazonaws.com",
				bucketName, region)
			result.Metadata["style"] = "virtual-hosted"
		}
	} else {
		// Path-style: s3.region.amazonaws.com/bucket-name/key
		result.TargetURL = fmt.Sprintf("https://s3.%s.amazonaws.com", region)
		result.TargetHost = fmt.Sprintf("s3.%s.amazonaws.com", region)
		result.Metadata["style"] = "path"
	}

	// Compute the AWS path relative to the streaming path.
	// Use EscapedPath() to preserve URL encoding for S3 object keys that may
	// contain special characters.
	httpPath := ctx.LogicalRequest.HTTPRequest.URL.EscapedPath()

	// Strip mount prefix to get the actual AWS path
	// The path format is: /v1/{mount}/gateway/{aws-path}
	actualPath := httpPath

	// Find and strip the gateway prefix
	gatewayIdx := strings.Index(httpPath, "/gateway/")
	if gatewayIdx != -1 {
		actualPath = httpPath[gatewayIdx+len("/gateway"):]
	} else if strings.HasSuffix(httpPath, "/gateway") {
		actualPath = "/"
	}

	// Ensure path starts with / for AWS
	if actualPath == "" {
		actualPath = "/"
	} else if !strings.HasPrefix(actualPath, "/") {
		actualPath = "/" + actualPath
	}

	// For buckets with dots using path-style, prepend bucket name to path
	if result.Metadata["bucket_with_dots"] == true {
		bucketName := result.Metadata["bucket_name"].(string)
		if actualPath == "/" {
			actualPath = "/" + bucketName
		} else {
			actualPath = "/" + bucketName + actualPath
		}
	}

	result.TransformedPath = actualPath
	result.TransformedPathIsEncoded = true

	// p.log.Debug("S3 Standard request",
	// 	logger.String("target", result.TargetURL),
	// 	logger.String("path", result.TransformedPath),
	// 	logger.String("request_id", middleware.GetReqID(ctx.Ctx)),
	// )

	return result, nil
}

// parseHost extracts bucket information from the host
func (p *S3Processor) parseHost(ctx *processor.ProcessorContext) *processor.HostRewrite {
	host := ctx.LogicalRequest.HTTPRequest.Host

	// Remove port if present
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// Split host into parts
	parts := strings.Split(host, ".")

	// Need at least 2 parts
	if len(parts) < 2 {
		return nil
	}

	// Skip if already an AWS domain
	if strings.Contains(host, ".amazonaws.com") {
		return nil
	}

	// Find the proxy domain by trying different suffixes
	// Start with the smallest suffix (most prefix parts for bucket name)
	// This handles bucket names with dots like "my.bucket.name.localhost"
	// where we need to find "localhost" as the proxy domain and keep "my.bucket.name" as bucket
	var proxyDomainParts int
	for i := 1; i <= len(parts)-1 && i <= 3; i++ {
		// Try the last i parts as the proxy domain
		candidate := strings.Join(parts[len(parts)-i:], ".")
		if p.IsProxyDomain(candidate) {
			proxyDomainParts = i
			break // Stop at first match to maximize bucket name parts
		}
	}

	if proxyDomainParts == 0 {
		return nil
	}

	// Everything before the proxy domain is the bucket prefix
	prefixParts := parts[:len(parts)-proxyDomainParts]

	// No prefix parts means path-style URL (e.g., just proxy-domain)
	if len(prefixParts) == 0 {
		return nil
	}

	// Pattern 1: bucket.s3.proxy-domain (explicit S3)
	// Check if the part just before proxy domain is "s3"
	if len(prefixParts) >= 2 && prefixParts[len(prefixParts)-1] == "s3" {
		bucketName := strings.Join(prefixParts[:len(prefixParts)-1], ".")
		return &processor.HostRewrite{
			Service: "s3",
			Prefix:  bucketName,
		}
	}

	// Pattern 2: s3.proxy-domain (path-style, no bucket)
	// If there's only one prefix part and it's "s3", treat as path-style
	if len(prefixParts) == 1 && prefixParts[0] == "s3" {
		return nil
	}

	// Pattern 3: bucket.proxy-domain (implicit S3)
	// The bucket name might contain dots
	bucketName := strings.Join(prefixParts, ".")

	// Pattern 4: Check if it looks like an AWS account ID (12 digits, no dots)
	if len(prefixParts) == 1 && len(prefixParts[0]) == 12 {
		allDigits := true
		for _, ch := range prefixParts[0] {
			if ch < '0' || ch > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return &processor.HostRewrite{
				Service: "s3-control",
				Prefix:  prefixParts[0],
			}
		}
	}

	return &processor.HostRewrite{
		Prefix: bucketName,
	}
}

func (p *S3Processor) Metadata() *processor.ProcessorMetadata {
	return &processor.ProcessorMetadata{
		ServiceNames: []string{"s3"},
		HostPatterns: []string{"*.s3.*"},
		Priority:     100,
	}
}

// isDirectoryBucket checks if a bucket name follows the directory bucket naming pattern
func isDirectoryBucket(bucketName string) bool {
	return directoryBucketRegex.MatchString(bucketName)
}
