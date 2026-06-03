package mcp_aws

import "testing"

func TestPathAfterGateway(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		// Mount-relative — no leading slash. This is the shape req.Path takes
		// after the framework strips the mount prefix.
		{"mount_relative_bare", "gateway", ""},
		{"mount_relative_trailing_slash", "gateway/", "/"},
		{"mount_relative_with_tail", "gateway/tools/call", "/tools/call"},
		{"mount_relative_tail_trailing_slash", "gateway/tools/call/", "/tools/call/"},

		// Mount-relative with role prefix.
		{"role_prefix_bare", "role/s3-reader/gateway", ""},
		{"role_prefix_trailing_slash", "role/s3-reader/gateway/", "/"},
		{"role_prefix_with_tail", "role/s3-reader/gateway/tools/call", "/tools/call"},
		{"role_prefix_tail_trailing_slash", "role/s3-reader/gateway/tools/call/", "/tools/call/"},

		// Absolute — the shape req.HTTPRequest.URL.Path takes.
		{"absolute_bare", "/v1/team-data/mcp_aws/gateway", ""},
		{"absolute_trailing_slash", "/v1/team-data/mcp_aws/gateway/", "/"},
		{"absolute_with_tail", "/v1/team-data/mcp_aws/gateway/tools/call", "/tools/call"},
		{"absolute_tail_trailing_slash", "/v1/team-data/mcp_aws/gateway/tools/call/", "/tools/call/"},
		{"absolute_role_with_tail", "/v1/team-data/mcp_aws/role/s3-reader/gateway/tools/call", "/tools/call"},

		// Deep tails (the AgentCore /agents/.../invocations shape).
		{"agentcore_invocations", "role/s3-reader/gateway/agents/my-mcp/invocations", "/agents/my-mcp/invocations"},

		// Defensive: nothing to find.
		{"no_gateway_segment", "config", ""},
		{"empty", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pathAfterGateway(tc.in)
			if got != tc.want {
				t.Errorf("pathAfterGateway(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
