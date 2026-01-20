package processor

import (
	"fmt"
	"strings"

	"github.com/stephnangue/warden/logger"
)

// GenericAWSProcessor handles generic AWS service requests
type GenericAWSProcessor struct {
	BaseProcessor
	resolver *EndpointResolver
	log      *logger.GatedLogger
}

// NewGenericAWSProcessor creates a new generic AWS processor
func NewGenericAWSProcessor(proxyDomains []string, log *logger.GatedLogger) *GenericAWSProcessor {
	return &GenericAWSProcessor{
		BaseProcessor: BaseProcessor{
			ProcName:     "generic-aws",
			ProcPriority: 10, // Lowest priority - fallback processor
			ProxyDomains: proxyDomains,
		},
		resolver: NewEndpointResolver(),
		log:      log,
	}
}

// CanProcess always returns true as this is the fallback processor
func (p *GenericAWSProcessor) CanProcess(ctx *ProcessorContext) bool {
	// This is a catch-all processor
	return true
}

// Process handles generic AWS service request transformation
func (p *GenericAWSProcessor) Process(ctx *ProcessorContext) (*ProcessorResult, error) {
	result := &ProcessorResult{
		Service:  ctx.Service,
		Metadata: make(map[string]interface{}),
	}

	// Try to resolve endpoint using the resolver
	targetURL, err := p.resolver.ResolveEndpoint(ctx.Service, ctx.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve endpoint for service %s in region %s: %w",
			ctx.Service, ctx.Region, err)
	}

	result.TargetURL = targetURL

	// Extract host from URL
	if strings.HasPrefix(targetURL, "https://") {
		result.TargetHost = strings.TrimPrefix(targetURL, "https://")
		if idx := strings.Index(result.TargetHost, "/"); idx != -1 {
			result.TargetHost = result.TargetHost[:idx]
		}
	} else if strings.HasPrefix(targetURL, "http://") {
		result.TargetHost = strings.TrimPrefix(targetURL, "http://")
		if idx := strings.Index(result.TargetHost, "/"); idx != -1 {
			result.TargetHost = result.TargetHost[:idx]
		}
	}

	result.Metadata["resolved_via"] = "endpoint_resolver"

	// p.log.Debug("Generic AWS service request",
	// 	logger.String("service", ctx.Service),
	// 	logger.String("region", ctx.Region),
	// 	logger.String("target", result.TargetURL),
	// 	logger.String("original_path", ctx.OriginalPath),
	// 	logger.String("relative_path", ctx.RelativePath),
	// 	logger.String("target", result.TargetURL),
	// 	logger.String("request_id", middleware.GetReqID(ctx.Ctx)),
	// )

	// Compute the AWS path relative to the streaming path.
	// req.Path is already relative to the mount (e.g., "gateway/ec2-multiple-sg/terraform.tfstate")
	// We need to strip the "gateway" or "gateway/" prefix to get the actual AWS service path.
	actualPath := ctx.LogicalRequest.Path

	// Strip "gateway/" or "gateway" prefix
	if after, ok := strings.CutPrefix(actualPath, "gateway/"); ok {
		actualPath = after
	} else if actualPath == "gateway" {
		actualPath = ""
	}

	// Ensure path starts with / for AWS
	if actualPath == "" {
		actualPath = "/"
	} else if !strings.HasPrefix(actualPath, "/") {
		actualPath = "/" + actualPath
	}

	result.TransformedPath = actualPath

	return result, nil
}

func (p *GenericAWSProcessor) Metadata() *ProcessorMetadata {
	return &ProcessorMetadata{
		ServiceNames: []string{}, // Handles any service
		FallbackOnly: true,       // Only checked in fallback
		Priority:     10,
	}
}
