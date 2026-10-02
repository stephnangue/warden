package server

import (
	"context"
	"fmt"
	"io"
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

// playgroundRoles are the roles the self-check expects discovery to list.
var playgroundRoles = []string{playground.RoleATM, playground.RoleAssistant, playground.RoleTeller}

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
