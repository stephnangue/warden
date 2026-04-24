package alicloud

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveTargetHost(t *testing.T) {
	cases := []struct {
		name    string
		host    string
		proxies []string
		want    string
		errMsg  string // substring expected in the error
	}{
		// --- direct form ---
		{
			name: "direct Alicloud host",
			host: "ecs.cn-hangzhou.aliyuncs.com",
			want: "ecs.cn-hangzhou.aliyuncs.com",
		},
		{
			name: "direct host, uppercase normalized",
			host: "ECS.cn-HANGZHOU.aliyuncs.com",
			want: "ecs.cn-hangzhou.aliyuncs.com",
		},
		{
			name: "direct host with port",
			host: "ram.aliyuncs.com:443",
			want: "ram.aliyuncs.com",
		},
		{
			name: "direct OSS host",
			host: "oss-cn-beijing.aliyuncs.com",
			want: "oss-cn-beijing.aliyuncs.com",
		},
		{
			name: "direct virtual-hosted OSS bucket",
			host: "my-bucket.oss-cn-beijing.aliyuncs.com",
			want: "my-bucket.oss-cn-beijing.aliyuncs.com",
		},

		// --- subdomain form ---
		{
			name:    "subdomain form rewrites to real host",
			host:    "ecs.cn-hangzhou.aliyuncs.com.warden.example.com",
			proxies: []string{"warden.example.com"},
			want:    "ecs.cn-hangzhou.aliyuncs.com",
		},
		{
			name:    "subdomain form with port",
			host:    "kms.cn-beijing.aliyuncs.com.warden.example.com:443",
			proxies: []string{"warden.example.com"},
			want:    "kms.cn-beijing.aliyuncs.com",
		},
		{
			name:    "subdomain form with uppercase proxy domain",
			host:    "sts.aliyuncs.com.WARDEN.example.com",
			proxies: []string{"warden.example.com"},
			want:    "sts.aliyuncs.com",
		},
		{
			name:    "direct Alicloud host ignores proxy_domains",
			host:    "ecs.cn-hangzhou.aliyuncs.com",
			proxies: []string{"warden.example.com"},
			want:    "ecs.cn-hangzhou.aliyuncs.com",
		},
		{
			name:    "first matching proxy_domain wins",
			host:    "ecs.cn-hangzhou.aliyuncs.com.a.example.com",
			proxies: []string{"b.example.com", "a.example.com"},
			want:    "ecs.cn-hangzhou.aliyuncs.com",
		},

		// --- rejections ---
		{
			name:   "empty host",
			host:   "",
			errMsg: "empty",
		},
		{
			name:   "non-Alicloud, no proxy_domains",
			host:   "evil.example.com",
			errMsg: "not a recognised Alicloud target",
		},
		{
			name:    "non-Alicloud, no proxy_domain match",
			host:    "evil.example.com",
			proxies: []string{"warden.example.com"},
			errMsg:  "not a recognised Alicloud target",
		},
		{
			name:    "proxy_domain matches but prefix is not Alicloud",
			host:    "fake.evil.com.warden.example.com",
			proxies: []string{"warden.example.com"},
			errMsg:  "not a valid Alicloud service endpoint",
		},
		{
			name:    "proxy_domain matches but prefix contains aliyuncs only as substring",
			host:    "fakealiyuncs.com.warden.example.com",
			proxies: []string{"warden.example.com"},
			errMsg:  "not a valid Alicloud service endpoint",
		},
		{
			name:   "IP address is not a valid direct host",
			host:   "169.254.169.254",
			errMsg: "not a recognised Alicloud target",
		},
		{
			name:   "metadata service is not a valid direct host",
			host:   "100.100.100.200",
			errMsg: "not a recognised Alicloud target",
		},
		{
			name:    "localhost is never accepted",
			host:    "localhost",
			proxies: []string{"warden.example.com"},
			errMsg:  "not a recognised Alicloud target",
		},
		{
			name:    "suffix-only match is not a proxy_domain match",
			host:    "warden.example.com",
			proxies: []string{"warden.example.com"},
			errMsg:  "not a recognised Alicloud target",
		},
		{
			name:    "embedded aliyuncs.com in the middle is not a match",
			host:    "ecs.cn-hangzhou.aliyuncs.com.attacker.evil.com",
			proxies: []string{"warden.example.com"},
			errMsg:  "not a recognised Alicloud target",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveTargetHost(tc.host, tc.proxies)
			if tc.errMsg != "" {
				assert.Error(t, err)
				if err != nil {
					assert.Contains(t, err.Error(), tc.errMsg, "error = %v", err)
				}
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"  ", ""},
		{"Example.COM", "example.com"},
		{"example.com:443", "example.com"},
		{"  example.com:80  ", "example.com"},
		{"example.com", "example.com"},
		// IPv6 literals are mangled by the naive port strip, but we don't care:
		// they're never valid Alicloud hosts and get rejected downstream.
		{"[::1]:443", "["},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, normalizeHost(tc.in))
	}
}

func TestValidateProxyDomain(t *testing.T) {
	ok := []string{
		"warden.example.com",
		"gw.internal",
		"proxy.warden.corp",
	}
	for _, s := range ok {
		assert.NoError(t, validateProxyDomain(s), "expected %q to be valid", s)
	}

	bad := map[string]string{
		"":                    "empty",
		"   ":                 "empty",
		".warden.example.com": "must not start or end with '.'",
		"warden.example.com.": "must not start or end with '.'",
		"/warden":             "bare DNS name",
		"warden example":      "bare DNS name",
		"aliyuncs.com":        "aliyuncs.com",
		"fake.aliyuncs.com":   "aliyuncs.com",
	}
	for s, expect := range bad {
		err := validateProxyDomain(s)
		assert.Error(t, err, "expected %q to be rejected", s)
		if err != nil {
			assert.True(t, strings.Contains(err.Error(), expect),
				"error for %q = %q; want substring %q", s, err.Error(), expect)
		}
	}
}

func TestValidateConfig_ProxyDomains(t *testing.T) {
	// valid list
	assert.NoError(t, ValidateConfig(map[string]any{
		"auto_auth_path": "auth/jwt/",
		"proxy_domains":  []any{"warden.example.com", "gw.internal"},
	}))

	// wrong type rejected
	assert.Error(t, ValidateConfig(map[string]any{
		"auto_auth_path": "auth/jwt/",
		"proxy_domains":  "warden.example.com",
	}))

	// invalid entry rejected
	assert.Error(t, ValidateConfig(map[string]any{
		"auto_auth_path": "auth/jwt/",
		"proxy_domains":  []any{"ok.example.com", "fake.aliyuncs.com"},
	}))

	// non-string inside array rejected
	assert.Error(t, ValidateConfig(map[string]any{
		"auto_auth_path": "auth/jwt/",
		"proxy_domains":  []any{"ok.example.com", 42},
	}))
}
