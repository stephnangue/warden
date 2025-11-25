package processor

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// ProcessorContext contains all the information needed by processors
type ProcessorContext struct {
	// Request information
	Request       *http.Request
	BodyBytes     []byte
	OriginalPath  string
	RelativePath  string
	
	// Authentication
	Credentials   aws.Credentials
	AWSCreds      aws.Credentials
	AccessKeyID   string
	RoleName      string
	PrincipalID   string
	TokenTTL      time.Duration
	
	// AWS metadata
	Service       string
	Region        string
	
	// Context
	Ctx           context.Context
}

// ProcessorResult contains the result of processing
type ProcessorResult struct {
	// Endpoint information
	TargetURL     string
	TargetHost    string
	
	// Path transformation
	TransformedPath string
	
	// Service override (if processor changes the service)
	Service       string
	
	// Additional metadata
	Metadata      map[string]any
}

// RequestProcessor defines the interface for request processors
type RequestProcessor interface {
	// Name returns the processor name for logging
	Name() string
	
	// CanProcess determines if this processor can handle the request
	// It examines the request, headers, host, etc. to make this determination
	CanProcess(ctx *ProcessorContext) bool
	
	// Process handles the request transformation
	// Returns the result or an error
	Process(ctx *ProcessorContext) (*ProcessorResult, error)
	
	// Priority returns the processor priority (higher = checked first)
	// This allows certain processors to take precedence
	Priority() int

	// IsProxyDomain checks if a domain matches any of the configured proxy domains
	IsProxyDomain(domain string) bool

	// Metadata returns registration hints for optimization
	Metadata() *ProcessorMetadata
}

// BaseProcessor provides common functionality for all processors
type BaseProcessor struct {
	ProcName     string
	ProcPriority int
	ProxyDomains  []string
}

func (bp *BaseProcessor) Name() string {
	return bp.ProcName
}

func (bp *BaseProcessor) Priority() int {
	return bp.ProcPriority
}

func (bp *BaseProcessor)IsProxyDomain(domain string) bool {
	for _, proxyDomain := range bp.ProxyDomains {
		if domain == proxyDomain || strings.HasSuffix(domain, "."+proxyDomain) {
			return true
		}
	}
	return false
}

// HostRewrite contains information about virtual-hosted-style URL rewrites
type HostRewrite struct {
	Service string
	Region  string
	Prefix  string // Bucket name, account ID, API ID, etc.
}

// ProcessorRegistry manages all registered processors
// uses multiple strategies to quickly find processors
type ProcessorRegistry struct {
	// Strategy 1: Direct service name lookup (O(1))
	serviceMap map[string][]RequestProcessor
	
	// Strategy 2: Host pattern lookup (O(1))
	hostPatternMap map[string][]RequestProcessor
	
	// Strategy 3: Priority-ordered fallback list (O(n) for edge cases)
	fallbackProcessors []RequestProcessor
	
	// All processors for iteration
	allProcessors []RequestProcessor
	
	// Stats for monitoring
	stats ProcessorStats
	mu    sync.RWMutex
}

// ProcessorStats tracks processor usage
type ProcessorStats struct {
	ServiceMapHits     int64
	HostPatternHits    int64
	FallbackHits       int64
	ProcessorCallCount map[string]int64
	mu                 sync.RWMutex
}

// ProcessorMetadata describes how a processor should be registered
type ProcessorMetadata struct {
	// Service names this processor handles (for direct lookup)
	ServiceNames []string
	
	// Host patterns this processor handles (e.g., "*.s3-accesspoint.*")
	HostPatterns []string
	
	// If true, this processor is only checked in fallback
	FallbackOnly bool
	
	// Priority for ordering
	Priority int
}

// NewProcessorRegistry creates a new processor registry
func NewProcessorRegistry() *ProcessorRegistry {
	return &ProcessorRegistry{
		serviceMap:         make(map[string][]RequestProcessor),
		hostPatternMap:     make(map[string][]RequestProcessor),
		fallbackProcessors: make([]RequestProcessor, 0),
		allProcessors:      make([]RequestProcessor, 0),
		stats: ProcessorStats{
			ProcessorCallCount: make(map[string]int64),
		},
	}
}

// Register adds a processor with optimization hints
func (pr *ProcessorRegistry) Register(processor RequestProcessor) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	
	pr.allProcessors = append(pr.allProcessors, processor)
	
	// Check if processor provides metadata
	metadata := processor.Metadata()
	if metadata != nil {	
		// Register by service name
		for _, serviceName := range metadata.ServiceNames {
			pr.serviceMap[serviceName] = append(pr.serviceMap[serviceName], processor)
		}
		
		// Register by host pattern
		for _, pattern := range metadata.HostPatterns {
			pr.hostPatternMap[pattern] = append(pr.hostPatternMap[pattern], processor)
		}
		
		// Register in fallback if needed
		if metadata.FallbackOnly {
			pr.fallbackProcessors = append(pr.fallbackProcessors, processor)
		}
	} else {
		// No metadata - add to fallback
		pr.fallbackProcessors = append(pr.fallbackProcessors, processor)
	}
	
	// Sort fallback processors by priority
	pr.sortProcessors()
}

// FindProcessor uses multiple strategies to quickly find the right processor
func (pr *ProcessorRegistry) FindProcessor(ctx *ProcessorContext) RequestProcessor {
	// Strategy 1: Direct service name lookup (O(1))
	if processor := pr.findByService(ctx); processor != nil {
		pr.recordHit("service_map")
		pr.recordProcessorUse(processor.Name())
		return processor
	}
	
	// Strategy 2: Host pattern lookup (O(1))
	if processor := pr.findByHostPattern(ctx); processor != nil {
		pr.recordHit("host_pattern")
		pr.recordProcessorUse(processor.Name())
		return processor
	}
	
	// Strategy 3: Fallback linear search (O(n))
	if processor := pr.findByFallback(ctx); processor != nil {
		pr.recordHit("fallback")
		pr.recordProcessorUse(processor.Name())
		return processor
	}
	
	return nil
}

// findByService does O(1) service name lookup
func (pr *ProcessorRegistry) findByService(ctx *ProcessorContext) RequestProcessor {
	pr.mu.RLock()
	processors, exists := pr.serviceMap[ctx.Service]
	pr.mu.RUnlock()
	
	if !exists {
		return nil
	}
	
	// Check processors registered for this service
	for _, processor := range processors {
		if processor.CanProcess(ctx) {
			return processor
		}
	}
	
	return nil
}

// findByHostPattern does O(1) host pattern lookup
func (pr *ProcessorRegistry) findByHostPattern(ctx *ProcessorContext) RequestProcessor {
	if ctx.Request == nil {
		return nil
	}
	
	host := ctx.Request.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	
	// Try exact matches first
	if processors, exists := pr.hostPatternMap[host]; exists {
		for _, processor := range processors {
			if processor.CanProcess(ctx) {
				return processor
			}
		}
	}
	
	// Try pattern matches
	for pattern, processors := range pr.hostPatternMap {
		if matchHostPattern(host, pattern) {
			for _, processor := range processors {
				if processor.CanProcess(ctx) {
					return processor
				}
			}
		}
	}
	
	return nil
}

// findByFallback does linear search through fallback processors
func (pr *ProcessorRegistry) findByFallback(ctx *ProcessorContext) RequestProcessor {
	pr.mu.RLock()
	processors := pr.fallbackProcessors
	pr.mu.RUnlock()
	
	for _, processor := range processors {
		if processor.CanProcess(ctx) {
			return processor
		}
	}
	
	return nil
}

// matchHostPattern checks if a host matches a pattern
// Supports wildcards: *.s3-accesspoint.*, etc.
func matchHostPattern(host, pattern string) bool {
	if pattern == "*" {
		return true
	}
	
	// Simple wildcard matching
	if strings.Contains(pattern, "*") {
		parts := strings.Split(pattern, "*")
		pos := 0
		for _, part := range parts {
			if part == "" {
				continue
			}
			idx := strings.Index(host[pos:], part)
			if idx == -1 {
				return false
			}
			pos += idx + len(part)
		}
		return true
	}
	
	return host == pattern
}

// sortProcessors sorts processors by priority
func (pr *ProcessorRegistry) sortProcessors() {
	// Sort all processors
	for i := 0; i < len(pr.allProcessors)-1; i++ {
		for j := i + 1; j < len(pr.allProcessors); j++ {
			if pr.allProcessors[j].Priority() > pr.allProcessors[i].Priority() {
				pr.allProcessors[i], pr.allProcessors[j] = pr.allProcessors[j], pr.allProcessors[i]
			}
		}
	}
	
	// Sort fallback processors
	for i := 0; i < len(pr.fallbackProcessors)-1; i++ {
		for j := i + 1; j < len(pr.fallbackProcessors); j++ {
			if pr.fallbackProcessors[j].Priority() > pr.fallbackProcessors[i].Priority() {
				pr.fallbackProcessors[i], pr.fallbackProcessors[j] = pr.fallbackProcessors[j], pr.fallbackProcessors[i]
			}
		}
	}
}

// recordHit records which strategy found the processor
func (pr *ProcessorRegistry) recordHit(strategy string) {
	pr.stats.mu.Lock()
	defer pr.stats.mu.Unlock()
	
	switch strategy {
	case "service_map":
		pr.stats.ServiceMapHits++
	case "host_pattern":
		pr.stats.HostPatternHits++
	case "fallback":
		pr.stats.FallbackHits++
	}
}

// recordProcessorUse tracks processor usage
func (pr *ProcessorRegistry) recordProcessorUse(name string) {
	pr.stats.mu.Lock()
	defer pr.stats.mu.Unlock()
	pr.stats.ProcessorCallCount[name]++
}

// GetStats returns usage statistics
func (pr *ProcessorRegistry) GetStats() map[string]interface{} {
	pr.stats.mu.RLock()
	defer pr.stats.mu.RUnlock()
	
	total := pr.stats.ServiceMapHits + pr.stats.HostPatternHits + pr.stats.FallbackHits
	
	return map[string]interface{}{
		"total_requests":       total,
		"service_map_hits":     pr.stats.ServiceMapHits,
		"host_pattern_hits":    pr.stats.HostPatternHits,
		"fallback_hits":        pr.stats.FallbackHits,
		"service_map_percent":  percentage(pr.stats.ServiceMapHits, total),
		"host_pattern_percent": percentage(pr.stats.HostPatternHits, total),
		"fallback_percent":     percentage(pr.stats.FallbackHits, total),
		"processor_usage":      pr.stats.ProcessorCallCount,
		"total_processors":     len(pr.allProcessors),
	}
}

func percentage(part, total int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) / float64(total) * 100
}

// GetProcessors returns all registered processors
func (pr *ProcessorRegistry) GetProcessors() []RequestProcessor {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	return pr.allProcessors
}
