package s3

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/provider/aws/processor"
)

var (
	// Regex to match S3 Access Point ARN in path
	// Format: arn:aws:s3:region:account-id:accesspoint/access-point-name
	accessPointARNRegex = regexp.MustCompile(`arn:aws:s3:([^:]*):(\d{12}):accesspoint/([^/]+)`)
	// Regex to match Multi-Region Access Point ARN in path
	// Format: arn:aws:s3::account-id:accesspoint/mrap-alias.mrap
	mrapARNRegex = regexp.MustCompile(`arn:aws:s3::(\d{12}):accesspoint/([^/]+)`)
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

	// Skip S3 Control requests - they have x-amz-account-id header
	// These should be handled by S3ControlProcessor even if the path contains an access point ARN
	// (e.g., ListTagsForResource for an access point)
	if ctx.LogicalRequest != nil && ctx.LogicalRequest.HTTPRequest != nil {
		if ctx.LogicalRequest.HTTPRequest.Header.Get("x-amz-account-id") != "" {
			return false
		}
	}

	// Check host-based detection (virtual-hosted style)
	hostRewrite := p.parseHost(ctx)
	if hostRewrite != nil && hostRewrite.Service == "s3-accesspoint" {
		return true
	}

	// Check for Access Point ARN in path (for AWS_ENDPOINT_URL usage)
	// When using AWS_ENDPOINT_URL with an Access Point ARN as bucket,
	// the ARN is included in the path: /v1/aws/gateway/arn:aws:s3:region:account:accesspoint/name/key
	path := ctx.LogicalRequest.HTTPRequest.URL.Path
	if p.containsAccessPointARN(path) {
		return true
	}

	return false
}

// containsAccessPointARN checks if the path contains an S3 Access Point or MRAP ARN
func (p *S3AccessPointProcessor) containsAccessPointARN(path string) bool {
	// Check for standard Access Point ARN
	if accessPointARNRegex.MatchString(path) {
		return true
	}
	// Check for Multi-Region Access Point ARN
	if mrapARNRegex.MatchString(path) {
		return true
	}
	return false
}

// Process handles S3 Access Point request transformation
func (p *S3AccessPointProcessor) Process(ctx *processor.ProcessorContext) (*processor.ProcessorResult, error) {
	result := &processor.ProcessorResult{
		Service:  "s3", // Access points use s3 service for signing
		Metadata: make(map[string]interface{}),
	}

	// Get the path for ARN detection
	httpPath := ctx.LogicalRequest.HTTPRequest.URL.EscapedPath()

	// Strip mount prefix to get the path after gateway
	pathAfterGateway := httpPath
	gatewayIdx := strings.Index(httpPath, "/gateway/")
	if gatewayIdx != -1 {
		pathAfterGateway = httpPath[gatewayIdx+len("/gateway"):]
	} else if strings.HasSuffix(httpPath, "/gateway") {
		pathAfterGateway = "/"
	}

	// Try to parse ARN from path first (for AWS_ENDPOINT_URL usage)
	arnInfo := p.parseARNFromPath(pathAfterGateway)
	if arnInfo != nil {
		// ARN-based request: extract target URL and object key from ARN
		if arnInfo.IsMultiRegion {
			result.TargetURL = fmt.Sprintf("https://%s.accesspoint.s3-global.amazonaws.com",
				arnInfo.Alias)
			result.TargetHost = fmt.Sprintf("%s.accesspoint.s3-global.amazonaws.com",
				arnInfo.Alias)
			result.Metadata["type"] = "multi-region"
		} else {
			// Standard Access Point: {access-point-name}-{account-id}.s3-accesspoint.{region}.amazonaws.com
			result.TargetURL = fmt.Sprintf("https://%s-%s.s3-accesspoint.%s.amazonaws.com",
				arnInfo.Name, arnInfo.AccountID, arnInfo.Region)
			result.TargetHost = fmt.Sprintf("%s-%s.s3-accesspoint.%s.amazonaws.com",
				arnInfo.Name, arnInfo.AccountID, arnInfo.Region)
			result.Metadata["type"] = "single-region"
		}

		result.Metadata["access_point_name"] = arnInfo.Name
		result.Metadata["account_id"] = arnInfo.AccountID
		if arnInfo.Region != "" {
			result.Metadata["region"] = arnInfo.Region
		}

		// The object key is everything after the ARN in the path
		result.TransformedPath = arnInfo.ObjectKey
		if result.TransformedPath == "" {
			result.TransformedPath = "/"
		} else if !strings.HasPrefix(result.TransformedPath, "/") {
			result.TransformedPath = "/" + result.TransformedPath
		}
		result.TransformedPathIsEncoded = true

		if p.log != nil {
			p.log.Debug("S3 Access Point ARN request",
				logger.String("access_point", arnInfo.Name),
				logger.String("account_id", arnInfo.AccountID),
				logger.String("region", arnInfo.Region),
				logger.Bool("multi_region", arnInfo.IsMultiRegion),
				logger.String("target", result.TargetURL),
				logger.String("object_key", result.TransformedPath),
			)
		}

		return result, nil
	}

	// Fall back to host-based detection (virtual-hosted style)
	hostRewrite := p.parseHost(ctx)
	if hostRewrite == nil || hostRewrite.Prefix == "" {
		return nil, fmt.Errorf("cannot extract access point information from host or path")
	}

	// Parse access point name and account ID from host prefix
	accessPointInfo := p.parseAccessPointName(hostRewrite.Prefix)

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

	// Compute the object key path
	actualPath := pathAfterGateway
	if actualPath == "" {
		actualPath = "/"
	} else if !strings.HasPrefix(actualPath, "/") {
		actualPath = "/" + actualPath
	}

	result.TransformedPath = actualPath
	result.TransformedPathIsEncoded = true

	if p.log != nil {
		p.log.Debug("S3 Access Point host-based request",
			logger.String("access_point", accessPointInfo.Name),
			logger.String("account_id", accessPointInfo.AccountID),
			logger.Bool("multi_region", accessPointInfo.IsMultiRegion),
			logger.String("target", result.TargetURL),
			logger.String("path", result.TransformedPath),
		)
	}

	return result, nil
}

// AccessPointInfo contains parsed access point information (from host)
type AccessPointInfo struct {
	Name          string
	AccountID     string
	IsMultiRegion bool
}

// ARNInfo contains parsed ARN information from path
type ARNInfo struct {
	Region        string
	AccountID     string
	Name          string
	Alias         string // For MRAP
	ObjectKey     string
	IsMultiRegion bool
}

// parseARNFromPath extracts Access Point ARN components from the request path
// Path format: /arn:aws:s3:region:account-id:accesspoint/access-point-name/object-key
// or for MRAP: /arn:aws:s3::account-id:accesspoint/mrap-alias.mrap/object-key
func (p *S3AccessPointProcessor) parseARNFromPath(path string) *ARNInfo {
	// Remove leading slash if present
	path = strings.TrimPrefix(path, "/")

	// Try standard Access Point ARN first
	// Format: arn:aws:s3:region:account-id:accesspoint/access-point-name
	matches := accessPointARNRegex.FindStringSubmatch(path)
	if len(matches) == 4 {
		region := matches[1]
		accountID := matches[2]
		accessPointName := matches[3]

		// Find where the ARN ends and the object key begins
		// The ARN is: arn:aws:s3:region:account-id:accesspoint/access-point-name
		arnPattern := fmt.Sprintf("arn:aws:s3:%s:%s:accesspoint/%s", region, accountID, accessPointName)
		arnIdx := strings.Index(path, arnPattern)
		objectKey := ""
		if arnIdx != -1 {
			remaining := path[arnIdx+len(arnPattern):]
			if len(remaining) > 0 {
				objectKey = remaining // Includes leading slash if present
			}
		}

		return &ARNInfo{
			Region:        region,
			AccountID:     accountID,
			Name:          accessPointName,
			ObjectKey:     objectKey,
			IsMultiRegion: false,
		}
	}

	// Try Multi-Region Access Point ARN
	// Format: arn:aws:s3::account-id:accesspoint/mrap-alias.mrap
	matches = mrapARNRegex.FindStringSubmatch(path)
	if len(matches) == 3 {
		accountID := matches[1]
		mrapAlias := matches[2]

		// Find where the ARN ends and the object key begins
		arnPattern := fmt.Sprintf("arn:aws:s3::%s:accesspoint/%s", accountID, mrapAlias)
		arnIdx := strings.Index(path, arnPattern)
		objectKey := ""
		if arnIdx != -1 {
			remaining := path[arnIdx+len(arnPattern):]
			if len(remaining) > 0 {
				objectKey = remaining
			}
		}

		return &ARNInfo{
			AccountID:     accountID,
			Alias:         mrapAlias,
			Name:          mrapAlias,
			ObjectKey:     objectKey,
			IsMultiRegion: true,
		}
	}

	return nil
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

	// NOTE: Pattern 4 (detecting {access-point-name}-{account-id}.proxy-domain) was removed
	// because it incorrectly matched regular S3 bucket names that happen to end with
	// a 12-digit account ID (e.g., "bucket-tutorial-us-east-1-905418489750").
	//
	// Access Point requests via AWS_ENDPOINT_URL are handled by containsAccessPointARN()
	// in CanProcess() which checks for the ARN in the request path. The AWS SDK places
	// the Access Point ARN in the path when using AWS_ENDPOINT_URL.

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
