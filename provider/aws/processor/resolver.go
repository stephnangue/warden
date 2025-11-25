package processor

import (
	"fmt"
	"strings"
	"sync"
)

type EndpointResolver struct {
	cache sync.Map
}

func NewEndpointResolver() *EndpointResolver {
	return &EndpointResolver{}
}

func (r *EndpointResolver) ResolveEndpoint(service, region string) (string, error) {
	if service == "" {
		return "", fmt.Errorf("service cannot be empty")
	}
	if region == "" {
		return "", fmt.Errorf("region cannot be empty")
	}

	key := service + ":" + region
	if val, ok := r.cache.Load(key); ok {
		return val.(string), nil
	}

	// Normalize service name (handle aliases)
	service = normalizeServiceName(service)

	// Determine partition
	partition := getPartition(region)

	// Resolve endpoint based on service type
	var endpoint string

	if isGlobalService(service) {
		endpoint = resolveGlobalService(service, partition)
	} else if customResolver := getCustomResolver(service); customResolver != nil {
		endpoint = customResolver(region, partition)
	} else {
		endpoint = resolveRegionalService(service, region, partition)
	}

	r.cache.Store(key, endpoint)
	return endpoint, nil
}

// ClearCache clears the endpoint cache
func (r *EndpointResolver) ClearCache() {
	r.cache = sync.Map{}
}

// Partition represents an AWS partition
type Partition struct {
	Name      string
	DNSSuffix string
}

var (
	partitionStandard = Partition{Name: "aws", DNSSuffix: "amazonaws.com"}
	partitionChina    = Partition{Name: "aws-cn", DNSSuffix: "amazonaws.com.cn"}
	partitionGovCloud = Partition{Name: "aws-us-gov", DNSSuffix: "amazonaws.com"}
)

// getPartition determines the AWS partition based on region
func getPartition(region string) Partition {
	if strings.HasPrefix(region, "cn-") {
		return partitionChina
	}
	if strings.HasPrefix(region, "us-gov-") {
		return partitionGovCloud
	}
	return partitionStandard
}

// Global services that don't use regional endpoints
var globalServices = map[string]struct{}{
	"iam":                {},
	"cloudfront":         {},
	"route53":            {},
	"route53domains":     {},
	"waf":                {},
	"shield":             {},
	"globalaccelerator":  {},
	"organizations":      {},
	"budgets":            {},
	"importexport":       {},
	"artifact":           {},
	"health":             {},
	"ce":                 {}, // Cost Explorer
	"cur":                {}, // Cost and Usage Report
	"marketplacecommerceanalytics": {},
}

// isGlobalService checks if a service is global
func isGlobalService(service string) bool {
	_, exists := globalServices[service]
	return exists
}

// resolveGlobalService resolves endpoints for global services
func resolveGlobalService(service string, partition Partition) string {
	switch partition.Name {
	case "aws-cn":
		// China-specific global endpoints
		switch service {
		case "iam":
			return "https://iam.cn-north-1.amazonaws.com.cn"
		case "organizations":
			return "https://organizations.cn-northwest-1.amazonaws.com.cn"
		default:
			// Most global services not available in China
			return fmt.Sprintf("https://%s.amazonaws.com.cn", service)
		}

	case "aws-us-gov":
		// GovCloud-specific global endpoints
		switch service {
		case "iam":
			return "https://iam.us-gov.amazonaws.com"
		case "organizations":
			return "https://organizations.us-gov-west-1.amazonaws.com"
		case "route53":
			return "https://route53.us-gov.amazonaws.com"
		case "globalaccelerator":
			return "https://globalaccelerator.us-west-2.amazonaws.com" // Not in GovCloud
		default:
			return fmt.Sprintf("https://%s.us-gov.%s", service, partition.DNSSuffix)
		}

	default:
		// Standard AWS partition
		switch service {
		case "iam":
			return "https://iam.amazonaws.com"
		case "cloudfront":
			return "https://cloudfront.amazonaws.com"
		case "route53":
			return "https://route53.amazonaws.com"
		case "route53domains":
			return "https://route53domains.us-east-1.amazonaws.com"
		case "waf":
			return "https://waf.amazonaws.com"
		case "shield":
			return "https://shield.us-east-1.amazonaws.com"
		case "globalaccelerator":
			return "https://globalaccelerator.us-west-2.amazonaws.com"
		case "organizations":
			return "https://organizations.us-east-1.amazonaws.com"
		case "budgets":
			return "https://budgets.amazonaws.com"
		case "importexport":
			return "https://importexport.amazonaws.com"
		case "artifact":
			return "https://artifact.us-east-1.amazonaws.com"
		case "health":
			return "https://health.us-east-1.amazonaws.com"
		case "ce":
			return "https://ce.us-east-1.amazonaws.com"
		case "cur":
			return "https://cur.us-east-1.amazonaws.com"
		default:
			return fmt.Sprintf("https://%s.%s", service, partition.DNSSuffix)
		}
	}
}

// resolveRegionalService resolves endpoints for regional services
func resolveRegionalService(service, region string, partition Partition) string {
	return fmt.Sprintf("https://%s.%s.%s", service, region, partition.DNSSuffix)
}

// CustomResolverFunc is a function that resolves custom endpoint patterns
type CustomResolverFunc func(region string, partition Partition) string

// getCustomResolver returns a custom resolver for services with special patterns
func getCustomResolver(service string) CustomResolverFunc {
	customResolvers := map[string]CustomResolverFunc{
		"s3": resolveS3,
		"s3-control": resolveS3Control,
		"s3-outposts": resolveS3Outposts,
		"sts": resolveSTS,
		"chime": resolveChime,
		"execute-api": resolveExecuteAPI,
		"iot": resolveIoT,
		"iotdata": resolveIoTData,
	}

	return customResolvers[service]
}

// S3 has special endpoint patterns
func resolveS3(region string, partition Partition) string {
	// S3 dual-stack and FIPS variations exist, but we use standard here
	switch partition.Name {
	case "aws-cn":
		return fmt.Sprintf("https://s3.%s.%s", region, partition.DNSSuffix)
	case "aws-us-gov":
		return fmt.Sprintf("https://s3.%s.%s", region, partition.DNSSuffix)
	default:
		// us-east-1 has special endpoint
		if region == "us-east-1" {
			return "https://s3.amazonaws.com"
		}
		return fmt.Sprintf("https://s3.%s.%s", region, partition.DNSSuffix)
	}
}

// S3 Control has regional endpoints
func resolveS3Control(region string, partition Partition) string {
	return fmt.Sprintf("https://s3-control.%s.%s", region, partition.DNSSuffix)
}

// S3 Outposts has regional endpoints
func resolveS3Outposts(region string, partition Partition) string {
	return fmt.Sprintf("https://s3-outposts.%s.%s", region, partition.DNSSuffix)
}

// STS has both regional and global endpoints (regional is recommended)
func resolveSTS(region string, partition Partition) string {
	switch partition.Name {
	case "aws-cn":
		return fmt.Sprintf("https://sts.%s.%s", region, partition.DNSSuffix)
	case "aws-us-gov":
		return fmt.Sprintf("https://sts.%s.%s", region, partition.DNSSuffix)
	default:
		// Regional STS endpoints are recommended
		return fmt.Sprintf("https://sts.%s.%s", region, partition.DNSSuffix)
	}
}

// Chime has global and regional endpoints
func resolveChime(region string, partition Partition) string {
	// Chime control plane is global (us-east-1)
	// Media/messaging is regional
	if partition.Name == "aws" {
		return "https://chime.us-east-1.amazonaws.com"
	}
	return fmt.Sprintf("https://chime.%s.%s", region, partition.DNSSuffix)
}

// API Gateway execute-api endpoints
func resolveExecuteAPI(region string, partition Partition) string {
	return fmt.Sprintf("https://execute-api.%s.%s", region, partition.DNSSuffix)
}

// IoT has regional endpoints with unique format
func resolveIoT(region string, partition Partition) string {
	return fmt.Sprintf("https://iot.%s.%s", region, partition.DNSSuffix)
}

// IoT Data has account-specific endpoints (return base pattern)
func resolveIoTData(region string, partition Partition) string {
	// Note: Actual IoT Data endpoints include account-specific prefix
	// Format: https://<account-specific-prefix>.iot.region.amazonaws.com
	return fmt.Sprintf("https://data.iot.%s.%s", region, partition.DNSSuffix)
}

// normalizeServiceName handles service name variations and aliases
func normalizeServiceName(service string) string {
	aliases := map[string]string{
		"elasticloadbalancing": "elasticloadbalancing",
		"elb":                  "elasticloadbalancing",
		"elbv2":                "elasticloadbalancing",
		"monitoring":           "monitoring",
		"cloudwatch":           "monitoring",
		"logs":                 "logs",
		"cloudwatch-logs":      "logs",
		"events":               "events",
		"eventbridge":          "events",
		"application-autoscaling": "application-autoscaling",
		"autoscaling":             "autoscaling",
		"autoscaling-plans":       "autoscaling-plans",
		"email":                   "email",
		"ses":                     "email",
		"sms-voice":               "sms-voice",
		"pinpoint-sms-voice":      "sms-voice",
	}

	if normalized, exists := aliases[strings.ToLower(service)]; exists {
		return normalized
	}

	return strings.ToLower(service)
}

// IsValidRegion checks if a region string looks valid
func IsValidRegion(region string) bool {
	// Basic validation - AWS regions follow patterns
	if region == "" {
		return false
	}

	// Standard regions: us-east-1, eu-west-2, ap-southeast-1, etc.
	// China regions: cn-north-1, cn-northwest-1
	// GovCloud: us-gov-west-1, us-gov-east-1
	// Local zones: us-east-1-bos-1a, etc.
	
	validPrefixes := []string{
		"us-", "eu-", "ap-", "sa-", "ca-", "me-", "af-", "cn-",
	}

	for _, prefix := range validPrefixes {
		if strings.HasPrefix(region, prefix) {
			return true
		}
	}

	return false
}

// GetSupportedPartitions returns list of supported AWS partitions
func GetSupportedPartitions() []string {
	return []string{
		partitionStandard.Name,
		partitionChina.Name,
		partitionGovCloud.Name,
	}
}