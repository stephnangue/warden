//go:build e2e

// Package identity drives the identity store end to end: the native
// identities auth mounts derive for the callers they admit, the entities of
// record that claim them, and the commands an operator manages both with.
package identity

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stephnangue/warden/audit"
	h "github.com/stephnangue/warden/e2e/helpers"
)

// secretPath is the upstream secret every gateway request of this package
// reads.
const secretPath = "v1/secret/data/e2e/app-config"

// gatewayURL is the URL of the upstream secret through provider under role.
func gatewayURL(port int, provider, role string) string {
	return fmt.Sprintf("%s/v1/%s/role/%s/gateway/%s", h.NodeURL(port), provider, role, secretPath)
}

// expectStatus fails the test unless a request answered want.
func expectStatus(t *testing.T, what string, status int, body []byte, want int) {
	t.Helper()
	if status != want {
		t.Fatalf("%s: status %d, want %d: %s", what, status, want, body)
	}
}

// mountAccessor returns the accessor of the auth mount at mount in the root
// namespace.
func mountAccessor(t *testing.T, port int, mount string) string {
	t.Helper()
	body := h.MustNS(t, port, "", "GET", "sys/"+strings.TrimSuffix(h.AuthMountPath(mount), "/"), "")
	accessor := h.JSONString(t, body, "data.accessor")
	if accessor == "" {
		t.Fatalf("auth mount %s has no accessor: %s", mount, body)
	}
	return accessor
}

// cli runs the warden CLI against the node at port with the root token and
// returns its stdout, failing the test unless it succeeded.
func cli(t *testing.T, port int, args ...string) string {
	t.Helper()
	stdout, stderr, err := cliResult(t, port, args...)
	if err != nil {
		t.Fatalf("warden %s: %v\nstdout: %s\nstderr: %s", strings.Join(args, " "), err, stdout, stderr)
	}
	return stdout
}

// cliResult runs the warden CLI against the node at port with the root token
// and returns its stdout, stderr and error.
func cliResult(t *testing.T, port int, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	return h.WardenCLISplitWithPort(t, port, map[string]string{"WARDEN_TOKEN": h.RootToken(t)}, args...)
}

// cliJSON runs the warden CLI with -o json and decodes its stdout into out.
func cliJSON(t *testing.T, port int, out any, args ...string) {
	t.Helper()
	stdout := cli(t, port, append(args, "-o", "json")...)
	if err := json.Unmarshal([]byte(stdout), out); err != nil {
		t.Fatalf("warden %s -o json: %v: %s", strings.Join(args, " "), err, stdout)
	}
}

// entityAlias is a native identity as entity read and list print it.
type entityAlias struct {
	Mount         string `json:"mount"`
	MountAccessor string `json:"mount_accessor"`
	Name          string `json:"name"`
}

// entity is an entity as entity read and list print it.
type entity struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Kind       string        `json:"kind"`
	State      string        `json:"state"`
	GovernedBy string        `json:"governed_by"`
	Aliases    []entityAlias `json:"aliases"`
}

// lookup is what entity lookup prints.
type lookup struct {
	Entity     string `json:"entity"`
	EntityID   string `json:"entity_id"`
	Kind       string `json:"kind"`
	State      string `json:"state"`
	GovernedBy string `json:"governed_by"`
}

// deleteEntityAtEnd deletes entity name when the test ends, retired or not.
// Registered after the auth mounts it claims on, it runs before they are
// disabled, which its claims would otherwise refuse.
func deleteEntityAtEnd(t *testing.T, port int, name string) {
	t.Helper()
	t.Cleanup(func() { h.NSRequestBestEffort(port, "", "DELETE", "sys/identity/entity/"+name+"?force=true") })
}

// auditEntries waits for at least n audit response entries whose request path
// contains segment, logged on the node at port since since and matching
// match, and returns them in the order they were logged.
func auditEntries(t *testing.T, port int, segment string, since time.Time, n int, match func(audit.LogEntry) bool) []audit.LogEntry {
	t.Helper()
	return h.AwaitAuditEntries(t, h.NodeNumberForPort(port), segment, n, func(e audit.LogEntry) bool {
		return e.Type == string(audit.EntryTypeResponse) && e.Auth != nil && e.Request != nil &&
			!e.Timestamp.Before(since) && strings.Contains(e.Request.Path, segment) && (match == nil || match(e))
	})
}
