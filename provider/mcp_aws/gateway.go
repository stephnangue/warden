package mcp_aws

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/mcpfilter"
	"github.com/stephnangue/warden/provider/sdk/sigv4"
)

// headersToStrip removes client-supplied auth/identity headers before signing.
// SigV4-irrelevant hop-by-hop and proxy headers are removed by
// sigv4.NormalizeRequest, so we only need the Warden-specific set here.
var headersToStrip = []string{
	"Authorization",
	"X-Warden-Token",
	"X-Warden-Namespace",
	"X-Warden-Provider",
	"X-Warden-Role",
	"X-Warden-On-Behalf-Of",
	"X-Warden-Subject-Token",
	"X-Warden-Actor-Token",
	// Cookie carries client session identity that AWS will ignore but that
	// would otherwise bleed across the trust boundary. Strip explicitly —
	// sigv4.NormalizeRequest doesn't touch it.
	"Cookie",
}

// handleGateway signs the incoming MCP request with AWS SigV4 using credentials
// minted by core's implicit-auth pipeline, then forwards to the upstream MCP
// endpoint and streams the response back — pruning list responses to the
// callable items when the policy layer attached an MCP list filter.
//
// Pipeline:
//  1. Read body (capped by MaxBodySize, the same value ShouldEnforceMCPPolicy
//     returns to core's MCP body extractor — single source of truth).
//  2. Read AWS credentials from req.Credential (populated by core).
//  3. Strip Warden auth / identity headers.
//  4. Rewrite request URL onto the upstream — plumb scheme/host/path/host
//     explicitly, never path.Join (which mutates escapes and breaks SigV4).
//  5. Normalize headers (drop hop-by-hop + proxy-forwarded set).
//  6. Sign with sigv4.ResignRequest using the URL-derived service name and the
//     resolved region.
//  7. Forward via sigv4.ForwardDirect — or ForwardDirectFiltered when a list
//     filter is set, which buffers and prunes the list response — bypassing
//     httputil.ReverseProxy so headers and the signed body reach the upstream
//     byte-for-byte.
func (b *mcpAWSBackend) handleGateway(ctx context.Context, req *logical.Request) {
	r := req.HTTPRequest
	w := req.ResponseWriter

	snap := b.snapshot()
	if snap.upstreamURL == nil {
		http.Error(w, "mcp_aws not configured", http.StatusServiceUnavailable)
		return
	}

	// Apply the timeout BEFORE reading the body so a slow client upload
	// can't stall a worker indefinitely.
	if snap.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, snap.timeout)
		defer cancel()
		r = r.WithContext(ctx)
		req.HTTPRequest = r
	}

	bodyBytes, err := sigv4.ReadRequestBody(r, snap.maxBody)
	if err != nil {
		// sigv4.ReadRequestBody returns "request body exceeds maximum size"
		// when the cap is hit; everything else is an IO error. 413 is the
		// right code for the former; 400 is acceptable for the latter.
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "exceeds maximum size") {
			status = http.StatusRequestEntityTooLarge
		}
		http.Error(w, "Failed to read request body", status)
		return
	}
	if bodyBytes == nil {
		bodyBytes = []byte{}
	}

	creds, err := extractAWSCredentials(req)
	if err != nil {
		// Wrong credential type bound to the role is a programmer error,
		// not a client error — return 500 so it surfaces as an alert, not
		// a silently-suppressed 401.
		b.Logger.Error("AWS credential extraction failed", logger.Err(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	for _, h := range headersToStrip {
		r.Header.Del(h)
	}

	rewriteUpstreamURL(r, snap.upstreamURL)

	bodyBytes = sigv4.NormalizeRequest(b.Logger, r, bodyBytes)

	service, _ := serviceAndRegion(snap.upstreamURL)
	if err := sigv4.ResignRequest(ctx, b.signer, r, creds, service, snap.region, bodyBytes); err != nil {
		b.Logger.Error("Failed to sign request", logger.Err(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	b.Logger.Trace("Proxying mcp_aws request",
		logger.String("method", r.Method),
		logger.String("host", snap.upstreamURL.Host),
		logger.String("inbound_path", req.Path),
		logger.String("outbound_path", r.URL.Path),
		logger.String("service", service),
		logger.String("region", snap.region),
		logger.String("request_id", req.RequestID),
	)

	transport := snap.transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	// When the policy layer attached an MCP list filter, prune the response to
	// the callable items. The outbound Accept-Encoding was already dropped by
	// sigv4.NormalizeRequest, so the transport delivers a decompressed body the
	// filter can parse. Nil filter → verbatim streaming, unchanged.
	if f := req.MCPListFilter; f != nil {
		modify := func(contentType string, respBody []byte) ([]byte, error) {
			out, _, err := mcpfilter.FilterListResponse(f.ListMethod, contentType, respBody, f.Keep)
			return out, err
		}
		// snap.maxBody is defaulted to DefaultMaxBodySize at config time; guard
		// here too so the response buffer is always bounded (fail closed on a
		// list response larger than the cap).
		maxBody := snap.maxBody
		if maxBody <= 0 {
			maxBody = framework.DefaultMaxBodySize
		}
		sigv4.ForwardDirectFiltered(b.Logger, w, r, bodyBytes, transport, maxBody, modify)
		return
	}
	sigv4.ForwardDirect(b.Logger, w, r, bodyBytes, transport)
}

// rewriteUpstreamURL mutates r in place to target the upstream MCP endpoint.
// Path composition uses string concatenation, NOT path.Join, because path.Join
// collapses ".." segments, repeated slashes, and re-escapes — all of which
// invalidate the SigV4 canonical request. RawQuery is preserved verbatim.
func rewriteUpstreamURL(r *http.Request, upstream *url.URL) {
	tail := pathAfterGateway(r.URL.Path)

	r.URL.Scheme = upstream.Scheme
	r.URL.Host = upstream.Host
	r.URL.Path = upstream.Path + tail
	// RawPath is left empty so net/http re-derives it from Path. The inbound
	// request's RawPath only matters if the client used non-canonical escapes
	// in the gateway segment itself, which mcp_aws clients do not.
	r.URL.RawPath = ""

	r.Host = upstream.Host
	// RequestURI must be empty on outbound client requests.
	r.RequestURI = ""
}
