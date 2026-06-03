// Package mcp_aws proxies MCP traffic from Warden-token-bearing clients to
// AWS-hosted MCP endpoints, signing the outgoing request with AWS SigV4 using
// credentials minted by the aws source driver.
package mcp_aws

import (
	"net/url"
	"strings"
)

// serviceAndRegion derives the SigV4 service name and region from an upstream
// MCP endpoint URL using a structured DNS-label match. Mirrors AWS's own
// client-side proxy: aws/mcp-proxy-for-aws utils.py
// get_service_name_and_region_from_endpoint.
//
// Arm 1 — Bedrock AgentCore (Gateway or Runtime):
//
//	[..., "bedrock-agentcore", region, "amazonaws", "com"]
//	  → ("bedrock-agentcore", region)
//
// Arm 2 — AWS-hosted MCP product (e.g. aws-mcp.us-east-1.api.aws):
//
//	[service, region, "api", "aws"]
//	  → (service, region)
//
// Arm 3 — fallback:
//
//	[service, ...]
//	  → (service, "")  // operator must supply region via config
//
// Hosts that don't fit any arm (FIPS-flavored, GovCloud, China partition,
// dualstack labels, IPv6 literals) land in arm 3 with an empty region.
func serviceAndRegion(u *url.URL) (service, region string) {
	if u == nil {
		return "", ""
	}
	host := u.Hostname()
	if host == "" {
		return "", ""
	}
	labels := strings.Split(host, ".")
	n := len(labels)

	if n >= 4 &&
		labels[n-1] == "com" &&
		labels[n-2] == "amazonaws" &&
		labels[n-4] == "bedrock-agentcore" {
		return "bedrock-agentcore", labels[n-3]
	}

	if n == 4 && labels[2] == "api" && labels[3] == "aws" {
		return labels[0], labels[1]
	}

	return labels[0], ""
}
