package s3

import (
	"fmt"
	"strings"

	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/provider/aws/processor"
)

// S3ControlProcessor handles S3 Control API requests (account-level operations)
type S3ControlProcessor struct {
	processor.BaseProcessor
	log logger.Logger
}

func NewS3ControlProcessor(proxyDomains []string, log logger.Logger) *S3ControlProcessor {
	return &S3ControlProcessor{
		BaseProcessor: processor.BaseProcessor{
			ProcName:     "s3-control",
			ProcPriority: 150, 
			ProxyDomains: proxyDomains,
		},
		log: log,
	}
}

// CanProcess determines if this is an S3 Control request
func (p *S3ControlProcessor) CanProcess(ctx *processor.ProcessorContext) bool {
	// Check if service is explicitly s3-control
	if ctx.Service == "s3-control" {
		return true
	}
	
	// Check if host pattern matches account ID format
	hostRewrite := p.parseHost(ctx)
	// p.log.Debug("Host rewritten",
	// 	logger.Any("new_host", hostRewrite),
	// 	logger.String("request_id", middleware.GetReqID(ctx.Ctx)),
	// )
	if hostRewrite != nil && hostRewrite.Service == "s3-control" {
		return true
	}
	
	return false
}

// Process handles S3 Control request transformation
func (p *S3ControlProcessor) Process(ctx *processor.ProcessorContext) (*processor.ProcessorResult, error) {
	hostRewrite := p.parseHost(ctx)
	
	if hostRewrite == nil || hostRewrite.Prefix == "" {
		return nil, fmt.Errorf("cannot extract account ID from host")
	}
	
	accountID := hostRewrite.Prefix
	
	// Validate account ID format (12 digits)
	if len(accountID) != 12 {
		return nil, fmt.Errorf("invalid account ID format: %s", accountID)
	}
	
	for _, ch := range accountID {
		if ch < '0' || ch > '9' {
			return nil, fmt.Errorf("invalid account ID (must be 12 digits): %s", accountID)
		}
	}
	
	result := &processor.ProcessorResult{
		Service:  "s3-control", // Keep as s3-control for routing
		Metadata: make(map[string]interface{}),
	}
	
	// S3 Control endpoint: account-id.s3-control.region.amazonaws.com
	result.TargetURL = fmt.Sprintf("https://%s.s3-control.%s.amazonaws.com",
		accountID, ctx.Region)
	result.TargetHost = fmt.Sprintf("%s.s3-control.%s.amazonaws.com",
		accountID, ctx.Region)
	
	result.Metadata["account_id"] = accountID
	result.Metadata["api_type"] = "control"
	
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

	result.TransformedPath  = actualPath

	// p.log.Debug("S3 Control request",
	// 	logger.String("target", result.TargetURL),
	// 	logger.String("path", result.TransformedPath),
	// 	logger.String("request_id", middleware.GetReqID(ctx.Ctx)),
	// )
	
	return result, nil
}

// parseHost extracts account ID from the host
func (p *S3ControlProcessor) parseHost(ctx *processor.ProcessorContext) *processor.HostRewrite {
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

	// Pattern: account-id.proxy-domain
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

func (p *S3ControlProcessor) Metadata() *processor.ProcessorMetadata {
	return &processor.ProcessorMetadata{
		ServiceNames: []string{"s3", "s3-control"},
		Priority:     150,
	}
}