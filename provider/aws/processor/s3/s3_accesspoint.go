package s3

import (
	"fmt"
	"strings"

	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/provider/aws/processor"
)

// S3AccessPointProcessor handles S3 Access Point requests
type S3AccessPointProcessor struct {
	processor.BaseProcessor
	log *logger.GatedLogger
}

// NewS3AccessPointProcessor creates a new S3 Access Point processor
func NewS3AccessPointProcessor(proxyDomains []string, log *logger.GatedLogger) *S3AccessPointProcessor {
	return &S3AccessPointProcessor{
		BaseProcessor: processor.BaseProcessor{
			ProcName:     "s3-accesspoint",
			ProcPriority: 180,
			ProxyDomains: proxyDomains,
		},
		log: log,
	}
}

// CanProcess determines if this is an S3 Access Point request
func (p *S3AccessPointProcessor) CanProcess(ctx *processor.ProcessorContext) bool {
	// Check if service is s3
	if ctx.Service != "s3" {
		return false
	}

	hostRewrite := p.parseHost(ctx)
	if hostRewrite != nil && hostRewrite.Service == "s3-accesspoint" {
		return true
	}

	// Also check ARN format in path or header
	// Access point ARNs: arn:aws:s3:region:account-id:accesspoint/access-point-name
	// if strings.Contains(ctx.Request.URL.Path, "accesspoint") {
	// 	return true
	// }

	return false
}

// Process handles S3 Access Point request transformation
func (p *S3AccessPointProcessor) Process(ctx *processor.ProcessorContext) (*processor.ProcessorResult, error) {
	hostRewrite := p.parseHost(ctx)
	// p.log.Debug("Host rewritten",
	// 	logger.Any("new_host", hostRewrite),
	// 	logger.String("request_id", middleware.GetReqID(ctx.Ctx)),
	// )

	if hostRewrite == nil || hostRewrite.Prefix == "" {
		return nil, fmt.Errorf("cannot extract access point information from host")
	}

	// Parse access point name and account ID
	// Format: access-point-name-account-id or just access-point-name
	accessPointInfo := p.parseAccessPointName(hostRewrite.Prefix)

	result := &processor.ProcessorResult{
		Service:  "s3", // Access points use s3 service for signing
		Metadata: make(map[string]interface{}),
	}

	// Access point endpoint formats:
	// 1. access-point-name-account-id.s3-accesspoint.region.amazonaws.com
	// 2. For multi-region: mrap-alias.accesspoint.s3-global.amazonaws.com

	if accessPointInfo.IsMultiRegion {
		result.TargetURL = fmt.Sprintf("https://%s.accesspoint.s3-global.amazonaws.com",
			accessPointInfo.Name)
		result.TargetHost = fmt.Sprintf("%s.accesspoint.s3-global.amazonaws.com",
			accessPointInfo.Name)
		result.Metadata["type"] = "multi-region"
	} else {
		result.TargetURL = fmt.Sprintf("https://%s.s3-accesspoint.%s.amazonaws.com",
			hostRewrite.Prefix, ctx.Region)
		result.TargetHost = fmt.Sprintf("%s.s3-accesspoint.%s.amazonaws.com",
			hostRewrite.Prefix, ctx.Region)
		result.Metadata["type"] = "single-region"
	}

	result.Metadata["access_point_name"] = accessPointInfo.Name
	if accessPointInfo.AccountID != "" {
		result.Metadata["account_id"] = accessPointInfo.AccountID
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

	// p.log.Debug("S3 Access Point request",
	// 	logger.String("access_point", accessPointInfo.Name),
	// 	logger.String("account_id", accessPointInfo.AccountID),
	// 	logger.Bool("multi_region", accessPointInfo.IsMultiRegion),
	// 	logger.String("target", result.TargetURL),
	// 	logger.String("path", result.TransformedPath),
	// 	logger.String("request_id", middleware.GetReqID(ctx.Ctx)),
	// )

	return result, nil
}

// AccessPointInfo contains parsed access point information
type AccessPointInfo struct {
	Name          string
	AccountID     string
	IsMultiRegion bool
}

// parseAccessPointName extracts access point name and account ID
func (p *S3AccessPointProcessor) parseAccessPointName(prefix string) *AccessPointInfo {
	info := &AccessPointInfo{}

	// Check for multi-region access point (starts with "mrap")
	if strings.HasPrefix(prefix, "mrap-") {
		info.Name = prefix
		info.IsMultiRegion = true
		return info
	}

	// Single-region format: access-point-name-account-id
	// Try to extract account ID from the end (12 digits)
	parts := strings.Split(prefix, "-")
	if len(parts) > 1 {
		lastPart := parts[len(parts)-1]
		if len(lastPart) == 12 && isAllDigits(lastPart) {
			info.AccountID = lastPart
			info.Name = strings.TrimSuffix(prefix, "-"+lastPart)
		} else {
			info.Name = prefix
		}
	} else {
		info.Name = prefix
	}

	return info
}

// parseHost extracts access point information from the host
func (p *S3AccessPointProcessor) parseHost(ctx *processor.ProcessorContext) *processor.HostRewrite {
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

	// Pattern 1: access-point.s3-accesspoint.proxy-domain
	if len(parts) >= 3 && parts[1] == "s3-accesspoint" {
		return &processor.HostRewrite{
			Service: "s3-accesspoint",
			Prefix:  parts[0],
		}
	}

	// Pattern 2: mrap-alias.accesspoint.proxy-domain (multi-region)
	if len(parts) >= 3 && parts[1] == "accesspoint" {
		return &processor.HostRewrite{
			Service: "s3-accesspoint",
			Prefix:  parts[0],
		}
	}

	// Pattern 3: Check if prefix contains "accesspoint" keyword
	if len(parts) >= 2 && strings.Contains(parts[0], "accesspoint") {
		return &processor.HostRewrite{
			Service: "s3-accesspoint",
			Prefix:  parts[0],
		}
	}

	return nil
}

func (p *S3AccessPointProcessor) Metadata() *processor.ProcessorMetadata {
	return &processor.ProcessorMetadata{
		ServiceNames: []string{"s3"},
		HostPatterns: []string{
			"*.s3-accesspoint.*",
			"*.accesspoint.*",
			"*accesspoint*",
		},
		Priority: 180,
	}
}

// isAllDigits checks if a string contains only digits
func isAllDigits(s string) bool {
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}
