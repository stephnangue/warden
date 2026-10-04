package server

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"

	"github.com/stephnangue/warden/config"
	"github.com/stephnangue/warden/core"
	"github.com/stephnangue/warden/internal/playground"
)

// startPlayground starts the playground's fixtures for a dev server listening as
// listener describes. The authorization server reaches Warden's JWKS the way a
// client on this host would, trusting the dev listener's certificate when it
// serves TLS.
func startPlayground(listener config.ListenerBlock) (*playground.Playground, error) {
	scheme := "http"
	var wardenCAPEM string
	if !listener.TLSDisable {
		scheme = "https"
		if listener.TLSCertFile != "" {
			pem, err := os.ReadFile(listener.TLSCertFile)
			if err != nil {
				return nil, fmt.Errorf("dev playground: read the dev TLS certificate: %w", err)
			}
			wardenCAPEM = string(pem)
			if err := checkPlaygroundTrust(wardenCAPEM, devClientAddr(scheme, listener.Address)); err != nil {
				return nil, fmt.Errorf("dev playground: %w", err)
			}
		}
	}

	auditDir, err := os.MkdirTemp("", "warden-playground-*")
	if err != nil {
		return nil, fmt.Errorf("dev playground: create the audit directory: %w", err)
	}
	pg, err := playground.Start(playground.Options{
		ASAddr:      flagDevPlaygroundASAddr,
		BankAddr:    flagDevPlaygroundBankAddr,
		WardenAddr:  devClientAddr(scheme, listener.Address),
		WardenCAPEM: wardenCAPEM,
		AuditPath:   filepath.Join(auditDir, "audit.log"),
	})
	if err != nil {
		os.RemoveAll(auditDir)
		return nil, fmt.Errorf("dev playground: %w", err)
	}
	return pg, nil
}

// playgroundFlags are the server flags that bear on the playground.
type playgroundFlags struct {
	playground        bool
	addrSet           bool // -dev-playground-as-addr or -dev-playground-bank-addr
	spiffe            bool
	requireClientCert bool
	clientCAFile      string
}

// checkPlaygroundFlags refuses flag combinations the playground cannot run
// with. Its authorization server fetches Warden's JWKS from the dev listener,
// so that listener has to be one it can reach: no SPIFFE-only trust, and no
// client certificate required — which the flag only demands with a client CA,
// so only that pair is refused.
func checkPlaygroundFlags(f playgroundFlags) error {
	switch {
	case !f.playground && f.addrSet:
		return fmt.Errorf("-dev-playground-as-addr and -dev-playground-bank-addr can only be used with -dev-playground")
	case f.playground && f.spiffe:
		return fmt.Errorf("-dev-playground cannot be used with -dev-tls-spiffe")
	case f.playground && f.requireClientCert && f.clientCAFile != "":
		return fmt.Errorf("-dev-playground cannot be used with -dev-tls-require-client-cert")
	}
	return nil
}

// checkPlaygroundTrust fails unless the dev certificate file is, on its own,
// enough to trust the dev listener at wardenAddr: the authorization server
// trusts that file and nothing else when it fetches Warden's keys. A
// certificate for another name, or an expired one, would otherwise start
// cleanly and break only at the first token exchange, mid-scenario. (A leaf
// is pinned by being in the pool, so one a CA signed verifies without the CA.)
func checkPlaygroundTrust(certPEM, wardenAddr string) error {
	pool := x509.NewCertPool()
	var leaf *x509.Certificate
	rest := []byte(certPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse the dev TLS certificate: %w", err)
		}
		if leaf == nil {
			leaf = cert
		}
		pool.AddCert(cert)
	}
	if leaf == nil {
		return fmt.Errorf("the dev TLS certificate file holds no certificate")
	}
	u, err := url.Parse(wardenAddr)
	if err != nil {
		return fmt.Errorf("parse the dev listener address: %w", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: u.Hostname(), Roots: pool}); err != nil {
		return fmt.Errorf("the playground's authorization server trusts the dev TLS certificate file alone, "+
			"and it does not verify the dev listener at %s: %w", u.Hostname(), err)
	}
	return nil
}

// playgroundRoles are the roles the self-check expects discovery to list.
var playgroundRoles = []string{playground.RoleATM, playground.RoleAssistant, playground.RoleTeller, playground.RoleGitHub}

// bootstrapPlayground wires Warden to the playground as the root token, then
// checks discovery shows what the scenarios tell a newcomer to expect. Either
// failing stops startup: a playground that half works teaches the wrong thing.
func bootstrapPlayground(ctx context.Context, c *core.Core, rootToken string, pg *playground.Playground) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := c.RunDevBootstrap(ctx, rootToken, pg.Bootstrap()); err != nil {
		return fmt.Errorf("dev playground: %w", err)
	}
	if err := c.CheckDevPlaygroundDiscovery(ctx, playgroundRoles); err != nil {
		return fmt.Errorf("dev playground self-check: %w", err)
	}
	return nil
}

// printPlaygroundBanner tells a newcomer where things are and where to start.
func printPlaygroundBanner(w io.Writer, pg *playground.Playground, wardenAddr string) {
	fmt.Fprintf(w, "==> Playground\n")
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "A bank protected by Warden, and the identity provider that signs your\n")
	fmt.Fprintf(w, "agents and users, are running:\n")
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "  Identity provider:  %s\n", pg.ASURL())
	fmt.Fprintf(w, "  Bank (MCP + REST):  %s\n", pg.BankURL())
	fmt.Fprintf(w, "  Audit log:          %s\n", pg.AuditPath())
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "Try it:\n")
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "  $ export WARDEN_ADDR=%s\n", wardenAddr)
	fmt.Fprintf(w, "  $ export WARDEN_TOKEN=<the root token above>\n")
	fmt.Fprintf(w, "  $ warden dev scenarios\n")
	fmt.Fprintf(w, "\n")
}
