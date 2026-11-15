//go:build warden_e2e_gws_hosts

package gws

// buildTagHosts lets the end-to-end suite point gws_url at a local
// stand-in for Google, which then receives each request's whole path, host
// segment first. Only the end-to-end build sets this tag; a binary built any
// other way refuses the setting (TestDefaultBuildRefusesOverride).
var buildTagHosts = []string{"127.0.0.1", "localhost"}
