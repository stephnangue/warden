package alicloud

import (
	"fmt"
	"strings"
)

// alicloudHostSuffix is the DNS suffix of every public Alicloud service
// endpoint. Used as both the accept-criterion for direct-form hosts and the
// required tail of any host reached via a configured proxy_domain.
const alicloudHostSuffix = ".aliyuncs.com"

// resolveTargetHost translates the incoming HTTP Host into the real Alicloud
// host that Warden should forward to. Two forms are accepted:
//
//  1. Direct form: the client signs with (and the reverse proxy preserves) the
//     real Alicloud host — e.g. "ecs.cn-hangzhou.aliyuncs.com". Returned as-is.
//
//  2. Subdomain form: the client uses "<real-alicloud-host>.<proxy-domain>" as
//     the SDK endpoint. If the suffix matches a configured proxy_domain *and*
//     the part before it is a valid "*.aliyuncs.com" host, the suffix is
//     stripped. This lets clients use native Alicloud SDKs unmodified when
//     Warden is behind a reverse proxy / wildcard DNS setup.
//
// Anything else is rejected, providing an SSRF guard: even if a client
// produces a valid signature, the provider refuses to forward to arbitrary
// destinations.
//
// proxyDomains entries are expected to have already been validated by
// validateProxyDomain (no leading/trailing dot, not *.aliyuncs.com).
func resolveTargetHost(incoming string, proxyDomains []string) (string, error) {
	host := normalizeHost(incoming)
	if host == "" {
		return "", fmt.Errorf("empty Host header")
	}

	// Direct form: a real Alicloud host.
	if strings.HasSuffix(host, alicloudHostSuffix) {
		return host, nil
	}

	// Subdomain form: "<real>.<proxy-domain>" where <real> ends in .aliyuncs.com.
	for _, pd := range proxyDomains {
		pd = strings.ToLower(strings.TrimSpace(pd))
		if pd == "" {
			continue
		}
		dotted := "." + pd
		if !strings.HasSuffix(host, dotted) {
			continue
		}
		real := strings.TrimSuffix(host, dotted)
		if strings.HasSuffix(real, alicloudHostSuffix) {
			return real, nil
		}
		return "", fmt.Errorf(
			"host %q matches proxy_domain %q but the prefix %q is not a valid Alicloud service endpoint",
			incoming, pd, real,
		)
	}

	return "", fmt.Errorf(
		"host %q is not a recognised Alicloud target: expected a *.aliyuncs.com host "+
			"or a *.aliyuncs.com.<proxy_domain> host with a configured proxy_domain",
		incoming,
	)
}

// normalizeHost lowercases and strips the port segment from a Host value.
// Alicloud hostnames are case-insensitive and signatures canonicalize to
// lowercase; stripping the port matches how the ACS3 canonical host is
// computed (Alicloud SDKs omit the port for the default 443).
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.IndexByte(h, ':'); i != -1 {
		h = h[:i]
	}
	return h
}
