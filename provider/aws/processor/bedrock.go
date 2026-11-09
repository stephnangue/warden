package processor

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/stephnangue/warden/logger"
)

// bedrockRuntimePrefixes are the paths of the Bedrock Runtime operations:
// Converse, InvokeModel and their streaming forms and CountTokens under
// /model/, ApplyGuardrail under /guardrail/, and InvokeGuardrailChecks under
// /guardrail-checks/; the async invocations are /async-invoke itself and the
// paths under it. The Bedrock control plane has none of them: its guardrails
// live under /guardrails and its model resources under hyphenated /model-*
// paths.
var bedrockRuntimePrefixes = []string{"/model/", "/async-invoke/", "/guardrail/", "/guardrail-checks/"}

// regionRe is the shape of an AWS region. The region comes from the client's
// own credential scope and becomes part of the upstream host, so nothing else
// may pass.
var regionRe = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)

// BedrockRuntimeProcessor sends Bedrock Runtime calls to their own endpoint.
// Bedrock Runtime signs with the service name of the Bedrock control plane,
// "bedrock", so the generic resolver would send a model call to the control
// plane's host; the operation's path is what tells them apart.
type BedrockRuntimeProcessor struct {
	BaseProcessor
	log *logger.GatedLogger
}

// NewBedrockRuntimeProcessor creates a Bedrock Runtime processor.
func NewBedrockRuntimeProcessor(proxyDomains []string, log *logger.GatedLogger) *BedrockRuntimeProcessor {
	return &BedrockRuntimeProcessor{
		BaseProcessor: BaseProcessor{
			ProcName:     "bedrock-runtime",
			ProcPriority: 100,
			ProxyDomains: proxyDomains,
		},
		log: log,
	}
}

// CanProcess claims a "bedrock" request whose path is a runtime operation's.
// Anything else signed as "bedrock" is a control plane call, left to the
// generic processor.
func (p *BedrockRuntimeProcessor) CanProcess(ctx *ProcessorContext) bool {
	if ctx.Service != "bedrock" {
		return false
	}
	path := awsPath(ctx)
	if path == "/async-invoke" {
		return true
	}
	for _, prefix := range bedrockRuntimePrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// Process targets bedrock-runtime.<region> and keeps the path as the client
// escaped it. Model ids carry ':' (amazon.nova-lite-v1:0) and inference
// profile ARNs '/', both of which the SDKs escape; sending the decoded path
// would put a literal ':' on the wire, and turn an escaped '/' into a path
// separator AWS does not route.
func (p *BedrockRuntimeProcessor) Process(ctx *ProcessorContext) (*ProcessorResult, error) {
	if !regionRe.MatchString(ctx.Region) {
		return nil, fmt.Errorf("invalid region %q", ctx.Region)
	}
	partition := getPartition(ctx.Region)
	host := fmt.Sprintf("bedrock-runtime.%s.%s", ctx.Region, partition.DNSSuffix)

	result := &ProcessorResult{
		TargetURL:  "https://" + host,
		TargetHost: host,
		Service:    "bedrock",
		Metadata:   map[string]any{"resolved_via": "bedrock_runtime"},
	}
	result.TransformedPath, result.TransformedPathIsEncoded = escapedAWSPath(ctx)
	return result, nil
}

// Metadata registers the processor for the "bedrock" signing name, so the
// service lookup reaches it before the generic fallback.
func (p *BedrockRuntimeProcessor) Metadata() *ProcessorMetadata {
	return &ProcessorMetadata{
		ServiceNames: []string{"bedrock"},
		Priority:     100,
	}
}

// awsPath is the AWS path of the request, decoded: the mount-relative path
// with its "gateway" segment removed, always starting with '/'.
func awsPath(ctx *ProcessorContext) string {
	path := ctx.LogicalRequest.Path
	if after, ok := strings.CutPrefix(path, "gateway/"); ok {
		path = after
	} else if path == "gateway" {
		path = ""
	}
	return "/" + strings.TrimPrefix(path, "/")
}

// escapedAWSPath is the AWS path as the client escaped it, and whether it is.
// The decoded AWS path ends the request's decoded URL path; whatever precedes
// it there — the API prefix, namespace and mount — is plain text, so it
// starts the escaped path too, and what follows it is the client's escaping
// of the AWS path. Cutting at a fixed "/gateway/" instead would cut early on
// a namespace or mount itself named gateway. When the two do not line up the
// decoded path is returned, which is what the generic processor sends.
func escapedAWSPath(ctx *ProcessorContext) (string, bool) {
	decoded := awsPath(ctx)
	u := ctx.LogicalRequest.HTTPRequest.URL
	prefix, ok := strings.CutSuffix(u.Path, decoded)
	if !ok {
		return decoded, false
	}
	escaped, ok := strings.CutPrefix(u.EscapedPath(), prefix)
	if !ok {
		return decoded, false
	}
	if unescaped, err := url.PathUnescape(escaped); err != nil || unescaped != decoded {
		return decoded, false
	}
	return escaped, true
}
