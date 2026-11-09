//go:build !warden_e2e_graph_hosts

package msgraph

// buildTagHosts widens graph_url beyond Microsoft Graph. It is empty in every
// build but the end-to-end suite's (see hosts_e2e.go).
var buildTagHosts []string
