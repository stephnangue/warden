//go:build e2e

// Package roles drives namespace roles, virtual groups and per-request role
// grants end to end, across the auth methods that admit callers: a role names
// what a caller may do, a group decides who may assume it from the facts an
// auth mount verified, and each request is granted its role afresh on the
// caller's cached admission.
package roles

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
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

// writeRole (re)creates role in namespace and deletes it when the test ends.
func writeRole(t *testing.T, port int, namespace, role string, r h.Role) {
	t.Helper()
	h.WriteRoleInNS(t, port, namespace, role, r)
	t.Cleanup(func() { h.NSRequestBestEffort(port, namespace, "DELETE", "sys/roles/"+role) })
}

// gatewayURL is the URL of the upstream secret through provider under role.
func gatewayURL(port int, provider, role string) string {
	return fmt.Sprintf("%s/v1/%s/role/%s/gateway/%s", h.NodeURL(port), provider, role, secretPath)
}

// bearer presents a JWT.
func bearer(jwt string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + jwt}
}

// forwardedCert presents a client certificate as a trusted proxy forwards it.
func forwardedCert(certPEM string) map[string]string {
	return map[string]string{"X-SSL-Client-Cert": h.URLEncodePEM(certPEM)}
}

// get sends a GET to u with headers.
func get(t *testing.T, u string, headers map[string]string) (int, []byte) {
	t.Helper()
	return h.DoRequest(t, "GET", u, headers, "")
}

// expectStatus fails the test unless a request answered want.
func expectStatus(t *testing.T, what string, status int, body []byte, want int) {
	t.Helper()
	if status != want {
		t.Fatalf("%s: status %d, want %d: %s", what, status, want, body)
	}
}

// expectRefused fails the test unless a request was refused with status and
// an error naming reason.
func expectRefused(t *testing.T, what string, status int, body []byte, want int, reason string) {
	t.Helper()
	if status != want || !strings.Contains(h.ErrorText(body), reason) {
		t.Fatalf("%s: status %d, want %d naming %q: %s", what, status, want, reason, body)
	}
}

// caFingerprint is the ca fact of a certificate chaining to caPEM: the
// lowercase hex SHA-256 of the anchor's DER.
func caFingerprint(t *testing.T, caPEM string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(caPEM))
	if block == nil {
		t.Fatal("CA PEM does not decode")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("CA does not parse: %v", err)
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

// newCA returns a fresh CA.
func newCA(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	return h.GenerateTestCA(t)
}

// gatewayEntries waits for at least n audit response entries of gateway
// requests under role on the node at port, granted or refused, logged since
// since, and returns them in the order they were logged.
func gatewayEntries(t *testing.T, port int, role string, since time.Time, n int) []audit.LogEntry {
	t.Helper()
	segment := "role/" + role + "/gateway"
	return h.AwaitAuditEntries(t, h.NodeNumberForPort(port), segment, n, func(e audit.LogEntry) bool {
		return e.Type == string(audit.EntryTypeResponse) && e.Auth != nil && e.Request != nil &&
			!e.Timestamp.Before(since) && strings.Contains(e.Request.Path, segment)
	})
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	return h.JSON(t, v)
}
