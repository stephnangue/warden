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
	log logger.Logger
}

// NewS3Processor creates a new S3 processor
func NewS3Processor(proxyDomains []string, log logger.Logger) *S3Processor {
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
		return true
	}

	return false
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

	// Handle virtual-hosted-style URL
	if hostRewrite != nil && hostRewrite.Prefix != "" {
		// Virtual-hosted-style: bucket-name.s3.region.amazonaws.com
		result.TargetURL = fmt.Sprintf("https://%s.s3.%s.amazonaws.com",
			hostRewrite.Prefix, ctx.Region)
		result.TargetHost = fmt.Sprintf("%s.s3.%s.amazonaws.com",
			hostRewrite.Prefix, ctx.Region)
		result.Metadata["bucket_name"] = hostRewrite.Prefix
		result.Metadata["style"] = "virtual-hosted"
	} else {
		// Path-style: s3.region.amazonaws.com/bucket-name/key
		result.TargetURL = fmt.Sprintf("https://s3.%s.amazonaws.com", ctx.Region)
		result.TargetHost = fmt.Sprintf("s3.%s.amazonaws.com", ctx.Region)
		result.Metadata["style"] = "path"
	}

	// compute the AWS path relative to the provider path
	actualPath := ctx.OriginalPath
	if after, ok := strings.CutPrefix(ctx.OriginalPath, ctx.RelativePath); ok {
		actualPath = after
	}

	// Ensure path starts with / for AWS
	if actualPath == "" {
		actualPath = "/"
	} else if !strings.HasPrefix(actualPath, "/") {
		actualPath = "/" + actualPath
	}

	result.TransformedPath = actualPath

	// p.log.Debug("S3 Standard request",
	// 	logger.String("target", result.TargetURL),
	// 	logger.String("path", result.TransformedPath),
	// 	logger.String("request_id", middleware.GetReqID(ctx.Ctx)),
	// )

	return result, nil
}

// parseHost extracts bucket information from the host
func (p *S3Processor) parseHost(ctx *processor.ProcessorContext) *processor.HostRewrite {
	host := ctx.Request.Host

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

	// Check if the base domain matches proxy domains
	baseDomain := strings.Join(parts[len(parts)-2:], ".")
	if !p.IsProxyDomain(baseDomain) {
		return nil
	}

	// Pattern 1: bucket.s3.proxy-domain (explicit S3)
	if len(parts) >= 3 && parts[1] == "s3" {
		return &processor.HostRewrite{
			Service: "s3",
			Prefix:  parts[0],
		}
	}

	// Pattern 2: bucket.proxy-domain (implicit S3)
	if len(parts) == 2 {
		return &processor.HostRewrite{
			Prefix: parts[0],
		}
	}

	// Pattern 3: account-id.proxy-domain
	// Check if first part looks like an AWS account ID (12 digits)
	if len(parts) == 2 && len(parts[0]) == 12 {
		// Verify it's all digits
		allDigits := true
		for _, ch := range parts[0] {
			if ch < '0' || ch > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return &processor.HostRewrite{
				Service: "s3-control",
				Prefix:  parts[0],
			}
		}
	}

	return nil
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
