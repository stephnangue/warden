//go:build warden_e2e_graph_hosts

package msgraph

// buildTagHosts lets the end-to-end suite point graph_url at a local stub, so
// link rewriting can be driven through a real cluster. Only e2e/setup.sh builds
// with this tag; a binary built any other way accepts Microsoft Graph alone
// (TestDefaultBuildAllowsGraphOnly).
var buildTagHosts = []string{"127.0.0.1", "localhost"}
