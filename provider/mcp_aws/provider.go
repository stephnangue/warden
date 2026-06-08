package mcp_aws

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// Compile-time assertion: mcp_aws opts into CBP `mcp { }` body-authoritative
// policy enforcement. Without this assertion the core's request handler type-
// asserts to logical.MCPPolicyEnforced, fails silently, skips body extraction,
// and any mcp { } block bound to an mcp_aws path becomes a no-op. The unit
// test in provider_test.go also asserts this at the type level so an
// accidental refactor that drops the method surfaces as a compile error in
// the test, not as a quiet over-permission at runtime.
var _ logical.MCPPolicyEnforced = (*mcpAWSBackend)(nil)

// ShouldEnforceMCPPolicy reports whether this request is subject to mcp { }
// body-authoritative policy enforcement. The gate matches the generic mcp
// provider exactly: JSON-RPC POSTs only. GET (SSE reconnect) and DELETE (session
// close), and any non-JSON Content-Type, decline and pass through under
// credential-scope-only enforcement (IAM here, bearer-token scopes there).
//
// The body cap returned is the backend's MaxBodySize as of THIS call, read
// through snapshot() to match the rest of the hot path. A config-write that
// lands between this call and the SigV4 read in handleGateway may produce
// different caps for the same request; both caps lead to the same correct
// decision under any operator-set value, so the brief inconsistency is
// harmless. The lock protects against tearing a torn-read of a partial
// int64 — not against config-write atomicity across the whole request.
func (b *mcpAWSBackend) ShouldEnforceMCPPolicy(req *logical.Request) (bool, int64) {
	if req == nil || req.HTTPRequest == nil {
		return false, 0
	}
	r := req.HTTPRequest
	if r.Method != http.MethodPost {
		return false, 0
	}
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return false, 0
	}
	// Strip a charset / boundary parameter (e.g. "application/json; charset=utf-8")
	// before comparing to the bare media type.
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(strings.ToLower(ct))
	if ct != "application/json" {
		return false, 0
	}
	return true, b.snapshot().maxBody
}

// DefaultMCPAWSURL is the GA endpoint for AWS's hosted MCP Server.
const DefaultMCPAWSURL = "https://aws-mcp.us-east-1.api.aws/mcp"

// DefaultMCPAWSTimeout caps a single MCP session. MCP responses may stream
// over SSE across many tool calls, so the default matches the generic mcp provider.
const DefaultMCPAWSTimeout = 10 * time.Minute

// mcpAWSBackend is the streaming backend for mcp_aws.
//
// Implicit auth is wired by the embedded *framework.StreamingBackend via
// SetTransparentConfig: core populates req.Credential before handleGateway
// runs. The backend itself only consumes the credential and signs the
// outgoing request.
//
// Do NOT declare a local maxBodySize field — MaxBodySize is promoted from
// the embedded *framework.StreamingBackend; a lowercase shadow would
// silently desync the MCP policy body cap from the SigV4 body cap.
type mcpAWSBackend struct {
	*framework.StreamingBackend

	// signer is shared across requests. v4.Signer's derived-key cache is
	// keyed on (secretKey, date, region, service); one signer per mount
	// makes cache reuse a feature.
	signer *v4.Signer

	mu          sync.RWMutex
	upstreamURL *url.URL
	// configRegion is the operator-supplied region (empty if not set).
	// Persisted as-is so a URL-only update can re-infer region from the new
	// host instead of sticking to the previously resolved value.
	configRegion string
	// region is the resolved signing region: coalesce(configRegion, URL-inferred).
	// This is the value passed to sigv4.ResignRequest.
	region        string
	tlsSkipVerify bool
	caData        string
}

// shared transport, initialized once per process.
var (
	sharedTransport   *http.Transport
	transportShutdown func()
	transportOnce     sync.Once
)

func initTransport() {
	transportOnce.Do(func() {
		sharedTransport, transportShutdown = httpproxy.DefaultNewTransport()
	})
}

// ShutdownHTTPTransport closes idle connections on the shared transport.
func ShutdownHTTPTransport() {
	if transportShutdown != nil {
		transportShutdown()
	}
}

// Factory creates a new mcp_aws provider backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &mcpAWSBackend{
		signer: v4.NewSigner(),
	}

	b.StreamingBackend = &framework.StreamingBackend{
		StreamingPaths: []*framework.StreamingPath{
			{
				Pattern:         "gateway",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "AWS MCP gateway proxy",
				HelpDescription: "Proxies MCP traffic to AWS-hosted MCP endpoints with SigV4 signing.",
			},
			{
				Pattern:         "gateway/.*",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "AWS MCP gateway proxy",
				HelpDescription: "Proxies MCP traffic to AWS-hosted MCP endpoints with SigV4 signing.",
			},
			{
				Pattern:         "role/[^/]+/gateway",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "AWS MCP transparent gateway",
				HelpDescription: "Proxies MCP traffic with the role embedded in the URL path.",
			},
			{
				Pattern:         "role/[^/]+/gateway/.*",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "AWS MCP transparent gateway",
				HelpDescription: "Proxies MCP traffic with the role embedded in the URL path.",
			},
		},
		// ParseStreamBody intentionally left at false. MCP-enforcing specs
		// must not pre-parse the body — the core's MCP extractor reads the
		// body itself when ShouldEnforceMCPPolicy returns true.
		Backend: &framework.Backend{
			Help:         mcpAWSBackendHelp,
			BackendType:  "mcp_aws",
			BackendClass: logical.ClassProvider,
			Paths: []*framework.Path{
				b.pathConfig(),
			},
		},
	}

	b.Logger = conf.Logger.WithSubsystem("mcp_aws")
	b.StorageView = conf.StorageView

	initTransport()
	b.StreamingBackend.InitProxy(sharedTransport)

	if conf.RegisterShutdownHook != nil {
		conf.RegisterShutdownHook("mcp_aws-transport", ShutdownHTTPTransport)
	}

	if err := b.StreamingBackend.Setup(ctx, conf); err != nil {
		return nil, err
	}

	// Seed an empty transparent config so isTransparentRequest can route
	// once auto_auth_path is configured via handleConfigWrite.
	b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{})

	// Defaults until Initialize loads persisted config.
	b.SetMaxBodySize(framework.DefaultMaxBodySize)
	b.SetTimeout(DefaultMCPAWSTimeout)
	if u, err := url.Parse(DefaultMCPAWSURL); err == nil {
		b.upstreamURL = u
		_, b.region = serviceAndRegion(u)
	}

	if len(conf.Config) > 0 {
		if err := httpproxy.ValidateConfig(conf.Config, "mcp_aws_url"); err != nil {
			return nil, fmt.Errorf("invalid configuration: %w", err)
		}
		if _, err := b.applyParsedConfig(conf.Config); err != nil {
			return nil, err
		}
	}

	return b, nil
}

// applyParsedConfig parses conf, validates it, builds the new transport,
// and installs all resolved values under a single write lock. Returns the
// canonical data to persist (computed from the input alone, never from b.*,
// so it can't be stale by the time the caller calls Put).
//
// Validation + transport build happen BEFORE the lock is taken so a failure
// in either leaves b.* untouched — no half-mutated state if the CA bundle
// is malformed or a TLS-toggle build fails.
//
// TLS handling covers both directions: a config that drops tls_skip_verify
// or clears ca_data falls back to the shared default transport (the prior
// implementation only rebuilt when the NEW config had overrides, which left
// a stuck-state bug where toggling skip-verify off kept the old skip-verify
// transport in place).
func (b *mcpAWSBackend) applyParsedConfig(conf map[string]any) (map[string]any, error) {
	parsed := httpproxy.ParseConfig(conf, "mcp_aws_url", DefaultMCPAWSURL, DefaultMCPAWSTimeout)
	u, err := url.Parse(parsed.ProviderURL)
	if err != nil {
		return nil, fmt.Errorf("invalid mcp_aws_url: %w", err)
	}
	// Strip a trailing slash on the upstream path so r.URL.Path = u.Path + tail
	// never produces "//" when tail begins with "/" (the gateway-suffix
	// extractor always returns "" or a leading-slash string).
	u.Path = strings.TrimRight(u.Path, "/")

	_, inferredRegion := serviceAndRegion(u)
	configRegion, _ := conf["region"].(string)
	configRegion = strings.TrimSpace(configRegion)
	resolvedRegion := configRegion
	if resolvedRegion == "" {
		resolvedRegion = inferredRegion
	}
	if resolvedRegion == "" {
		return nil, fmt.Errorf("region is required: upstream host %q does not yield a region; set the region config field", u.Host)
	}

	// Build the transport BEFORE touching state. Either branch returns a
	// valid http.RoundTripper, so a config-write that removes TLS overrides
	// successfully falls back to sharedTransport.
	var newTransport http.RoundTripper
	if parsed.TLSSkipVerify || parsed.CAData != "" {
		tr, err := httpproxy.NewTransportWithTLS(parsed.CAData, parsed.TLSSkipVerify)
		if err != nil {
			return nil, fmt.Errorf("invalid TLS configuration: %w", err)
		}
		newTransport = tr
	} else {
		newTransport = sharedTransport
	}

	maxBody := parsed.MaxBodySize
	if maxBody == 0 {
		maxBody = framework.DefaultMaxBodySize
	}
	timeout := parsed.Timeout
	if timeout == 0 {
		timeout = DefaultMCPAWSTimeout
	}

	persist := map[string]any{
		"mcp_aws_url":     u.String(),
		"region":          configRegion,
		"max_body_size":   maxBody,
		"timeout":         timeout.String(),
		"auto_auth_path":  parsed.AutoAuthPath,
		"default_role":    parsed.DefaultAuthRole,
		"tls_skip_verify": parsed.TLSSkipVerify,
		"ca_data":         parsed.CAData,
	}

	b.mu.Lock()
	b.upstreamURL = u
	b.configRegion = configRegion
	b.region = resolvedRegion
	b.tlsSkipVerify = parsed.TLSSkipVerify
	b.caData = parsed.CAData
	b.mu.Unlock()

	// Framework-side fields are atomic; no lock needed.
	b.SetMaxBodySize(maxBody)
	b.SetTimeout(timeout)
	b.SetTransport(newTransport)

	// SetTransparentConfig is the framework's own writer; it does its own
	// pointer swap on b.TransparentConfig. Concurrent readers see either the
	// old or new pointer, never a torn one — TransparentConfig is replaced
	// wholesale, not mutated in place.
	b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{
		AutoAuthPath:    parsed.AutoAuthPath,
		DefaultAuthRole: parsed.DefaultAuthRole,
	})

	return persist, nil
}

// Initialize loads persisted configuration from storage. The embedded
// StreamingBackend.Initialize only delegates to Backend.Initialize and does
// not load persisted config or call SetTransparentConfig — so this is a
// wholly custom override, not a partial extension.
func (b *mcpAWSBackend) Initialize(ctx context.Context) error {
	if b.StorageView == nil {
		return nil
	}

	entry, err := b.StorageView.Get(ctx, "config")
	if err != nil {
		return fmt.Errorf("failed to read config from storage: %w", err)
	}
	if entry == nil {
		return nil
	}

	var stored map[string]any
	if err := entry.DecodeJSON(&stored); err != nil {
		return fmt.Errorf("failed to decode config: %w", err)
	}

	_, err = b.applyParsedConfig(stored)
	return err
}

// handleGatewayStreaming wraps handleGateway for the streaming path handler.
func (b *mcpAWSBackend) handleGatewayStreaming(ctx context.Context, req *logical.Request, _ *framework.FieldData) error {
	b.handleGateway(ctx, req)
	return nil
}

// backendSnapshot is the read-locked view consumed by handleGateway. Capturing
// every per-request field at one lock acquisition prevents tearing under a
// concurrent config-write.
type backendSnapshot struct {
	upstreamURL *url.URL
	region      string
	maxBody     int64
	timeout     time.Duration
	transport   http.RoundTripper
}

func (b *mcpAWSBackend) snapshot() backendSnapshot {
	b.mu.RLock()
	upstream := b.upstreamURL
	region := b.region
	b.mu.RUnlock()
	// Framework-side fields are atomic; no lock needed.
	return backendSnapshot{
		upstreamURL: upstream,
		region:      region,
		maxBody:     b.MaxBodySize(),
		timeout:     b.Timeout(),
		transport:   b.Transport(),
	}
}

// SensitiveConfigFields returns the list of config fields masked in output.
func (b *mcpAWSBackend) SensitiveConfigFields() []string {
	return []string{"ca_data"}
}

const mcpAWSBackendHelp = `
The mcp_aws provider proxies requests to AWS-hosted MCP endpoints, signing
the outgoing request with AWS SigV4 using credentials minted by the aws
source driver.

Two AWS deployment patterns are supported via the same provider:

  - AWS's hosted MCP Server product (aws-mcp.{region}.api.aws/mcp)
  - Customer-owned MCP servers on Bedrock AgentCore Runtime or Gateway
    (runtime|gateway.bedrock-agentcore.{region}.amazonaws.com/...)

The SigV4 service name and signing region are derived from the upstream
URL host using a structured DNS-label match. The mount's region is only
the signing region for the MCP endpoint itself; it does not restrict the
AWS region of API calls the agent makes — the agent selects target
regions inside the MCP tool arguments.

The gateway path format is:

  /mcp_aws/gateway/{mcp-path}
  /mcp_aws/role/{role}/gateway/{mcp-path}

JSON-RPC bodies, the Accept header, and the Mcp-Session-Id header pass
through unchanged. Streamable HTTP responses (JSON or SSE) stream
without buffering.

Configuration:
- mcp_aws_url:    MCP endpoint base URL (default: https://aws-mcp.us-east-1.api.aws/mcp)
- region:         SigV4 signing region. Optional when the URL host yields one
                  via DNS-label inference; required for hosts that don't
                  (GovCloud, China partition, custom test hosts).
- max_body_size:  Maximum request body size (default: 10MB, max: 100MB)
- timeout:        Session timeout (default: 10m)
- auto_auth_path: Auth mount path for implicit authentication (required)
- default_role:   Fallback role when not specified by header or URL path
`
