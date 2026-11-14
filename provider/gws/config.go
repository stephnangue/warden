package gws

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/stephnangue/warden/framework"
)

// hostConfigFields is the mount's host allowlist setting.
var hostConfigFields = map[string]*framework.FieldSchema{
	framework.HostAllowlistKey: {
		Type: framework.TypeCommaStringSlice,
		Description: "Hosts this mount sends user tokens to, each with a leading dot and under .googleapis.com: " +
			"\".gmail.googleapis.com\" allows gmail.googleapis.com and hosts under it. Empty means the Workspace API hosts",
	},
}

// parseAllowlist reads allowed_host_suffixes. Every entry must be under
// googleapis.com: a mount that sends a person's token anywhere else is not one
// this provider builds.
func parseAllowlist(raw any) ([]string, error) {
	entries, err := framework.ParseHostAllowlist(raw)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e != googleAPIsSuffix && !strings.HasSuffix(e, googleAPIsSuffix) {
			return nil, fmt.Errorf("%s entry %q must be under %s", framework.HostAllowlistKey, e, googleAPIsSuffix)
		}
	}
	return entries, nil
}

// configuredAllowlist is the allowlist as configured, empty for the default.
func configuredAllowlist(state map[string]any) []string {
	entries, _ := state[framework.HostAllowlistKey].([]string)
	if entries == nil {
		return []string{}
	}
	return entries
}

// allowlist is the allowlist in force: the configured one, or the Workspace API
// hosts. Read on every request; it allocates nothing.
func allowlist(state map[string]any) []string {
	if entries, _ := state[framework.HostAllowlistKey].([]string); len(entries) > 0 {
		return entries
	}
	return defaultAllowedHostSuffixes
}

// checkOverrideURL accepts gws_url only in a build that names hosts
// it may point at (the end-to-end suite's), and then only as a bare https origin
// on one of them.
func checkOverrideURL(raw string, allowed []string) error {
	if len(allowed) == 0 {
		return fmt.Errorf("%s is for the end-to-end suite only: name the Google API host in the gateway path instead", urlConfigKey)
	}
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil {
		return fmt.Errorf("%s: %w", urlConfigKey, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%s must use https", urlConfigKey)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("%s must be a bare origin", urlConfigKey)
	}
	if !slices.Contains(allowed, strings.ToLower(u.Hostname())) {
		return fmt.Errorf("%s must name one of %s", urlConfigKey, strings.Join(allowed, ", "))
	}
	return nil
}
