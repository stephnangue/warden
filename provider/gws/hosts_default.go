//go:build !warden_e2e_gws_hosts

package gws

// buildTagHosts are the hosts gws_url may name. It is empty in every
// build but the end-to-end suite's (see hosts_e2e.go), so no mount can send a
// user's token anywhere but the Google host its request path names.
var buildTagHosts []string
