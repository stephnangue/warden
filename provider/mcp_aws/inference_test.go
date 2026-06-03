package mcp_aws

import (
	"net/url"
	"testing"
)

func TestServiceAndRegion(t *testing.T) {
	cases := []struct {
		name        string
		raw         string
		wantService string
		wantRegion  string
	}{
		// Arm 2 — the GA AWS MCP Server product.
		{
			name:        "aws_mcp_us_east_1",
			raw:         "https://aws-mcp.us-east-1.api.aws/mcp",
			wantService: "aws-mcp",
			wantRegion:  "us-east-1",
		},
		{
			name:        "aws_mcp_eu_frankfurt",
			raw:         "https://aws-mcp.eu-frankfurt-1.api.aws/mcp",
			wantService: "aws-mcp",
			wantRegion:  "eu-frankfurt-1",
		},

		// Arm 1 — Bedrock AgentCore (Runtime + Gateway).
		{
			name:        "bedrock_agentcore_runtime",
			raw:         "https://runtime.bedrock-agentcore.us-east-1.amazonaws.com/agents/myMcp/invocations",
			wantService: "bedrock-agentcore",
			wantRegion:  "us-east-1",
		},
		{
			name:        "bedrock_agentcore_gateway",
			raw:         "https://gateway.bedrock-agentcore.eu-west-1.amazonaws.com/mcp",
			wantService: "bedrock-agentcore",
			wantRegion:  "eu-west-1",
		},

		// Arm 3 — fallback paths the plan calls out explicitly.
		{
			name:        "generic_amazonaws_no_region_inferable",
			raw:         "https://your-service.us-east-1.amazonaws.com/mcp",
			wantService: "your-service",
			wantRegion:  "",
		},
		{
			name:        "localhost_for_tests",
			raw:         "http://localhost:8080/mcp",
			wantService: "localhost",
			wantRegion:  "",
		},

		// Edge cases the plan documents as falling through to arm 3.
		{
			// FIPS hits arm 2 because the suffix is still .api.aws —
			// service label includes the -fips marker, region is correct.
			name:        "fips_label_kept_in_service_name",
			raw:         "https://aws-mcp-fips.us-east-1.api.aws/mcp",
			wantService: "aws-mcp-fips",
			wantRegion:  "us-east-1",
		},
		{
			// GovCloud commercial-style hostname — neither arm matches; arm 3.
			name:        "govcloud_amazonaws_us_gov",
			raw:         "https://aws-mcp.us-gov-west-1.amazonaws-us-gov.com/mcp",
			wantService: "aws-mcp",
			wantRegion:  "",
		},
		{
			// China partition — .com.cn breaks arm 1's [..., amazonaws, com] match.
			name:        "china_partition_amazonaws_com_cn",
			raw:         "https://aws-mcp.cn-north-1.amazonaws.com.cn/mcp",
			wantService: "aws-mcp",
			wantRegion:  "",
		},
		{
			// Extra "dualstack" label between region and amazonaws breaks arm 1.
			name:        "dualstack_label_breaks_bedrock_match",
			raw:         "https://runtime.bedrock-agentcore.us-east-1.dualstack.amazonaws.com/mcp",
			wantService: "runtime",
			wantRegion:  "",
		},

		// IPv6 literal — Hostname() strips brackets and port.
		{
			name:        "ipv6_literal",
			raw:         "http://[::1]:8080/mcp",
			wantService: "::1",
			wantRegion:  "",
		},

		// Defensive: empty host.
		{
			name:        "empty_url",
			raw:         "",
			wantService: "",
			wantRegion:  "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var u *url.URL
			if tc.raw != "" {
				parsed, err := url.Parse(tc.raw)
				if err != nil {
					t.Fatalf("parse %q: %v", tc.raw, err)
				}
				u = parsed
			}
			gotService, gotRegion := serviceAndRegion(u)
			if gotService != tc.wantService {
				t.Errorf("service = %q, want %q", gotService, tc.wantService)
			}
			if gotRegion != tc.wantRegion {
				t.Errorf("region = %q, want %q", gotRegion, tc.wantRegion)
			}
		})
	}
}

func TestServiceAndRegion_NilSafe(t *testing.T) {
	s, r := serviceAndRegion(nil)
	if s != "" || r != "" {
		t.Fatalf("nil URL: got (%q,%q), want empty pair", s, r)
	}
}
