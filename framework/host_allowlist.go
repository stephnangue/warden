package framework

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// HostAllowlistKey is the config key of a gateway's host allowlist.
const HostAllowlistKey = "allowed_host_suffixes"

// hostnameRe is a hostname: dot-joined labels of letters, digits and inner
// hyphens, at least two of them. No port, userinfo, path or IP literal can
// pass.
var hostnameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// ValidateTargetHost checks that host, taken from a gateway path, is a plain
// lowercase hostname: the request leaves for it carrying a credential.
func ValidateTargetHost(host string) error {
	if host == "" {
		return fmt.Errorf("missing target host in path")
	}
	if len(host) > 253 {
		return fmt.Errorf("target host too long")
	}
	if net.ParseIP(host) != nil {
		return fmt.Errorf("target host %q must be a hostname, not an IP address", host)
	}
	if !hostnameRe.MatchString(host) {
		return fmt.Errorf("target host %q is not a lowercase hostname", host)
	}
	return nil
}

// HostAllowed reports whether host is in the allowlist. An entry ".example.com"
// allows example.com itself and every host under it, and nothing else:
// not notexample.com, nor example.com.attacker.test.
func HostAllowed(host string, allowlist []string) bool {
	for _, entry := range allowlist {
		if host == entry[1:] || strings.HasSuffix(host, entry) {
			return true
		}
	}
	return false
}

// ParseHostAllowlist reads a host allowlist from config: a list, or a
// comma-separated string. Each entry is a hostname with a leading dot. An
// entry without one is refused rather than dropped, since ".example.com" and
// "example.com" would read alike and allow differently.
func ParseHostAllowlist(raw any) ([]string, error) {
	var items []string
	switch v := raw.(type) {
	case nil:
		return nil, nil
	case []string:
		items = v
	case []any:
		for _, x := range v {
			s, ok := x.(string)
			if !ok {
				return nil, fmt.Errorf("%s entries must be strings", HostAllowlistKey)
			}
			items = append(items, s)
		}
	case string:
		items = strings.Split(v, ",")
	default:
		return nil, fmt.Errorf("%s must be a list of host suffixes", HostAllowlistKey)
	}

	var out []string
	for _, item := range items {
		entry := strings.ToLower(strings.TrimSpace(item))
		if entry == "" {
			continue
		}
		if !strings.HasPrefix(entry, ".") || !hostnameRe.MatchString(entry[1:]) {
			return nil, fmt.Errorf("%s entry %q must be a hostname with a leading dot, such as \".example.com\"", HostAllowlistKey, item)
		}
		out = append(out, entry)
	}
	return out, nil
}
