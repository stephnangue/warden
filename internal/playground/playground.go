package playground

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Default addresses of the fixtures. They bind loopback only, even in a
// container: Warden reaches them in-process, and nothing else needs to.
const (
	DefaultASAddr   = "127.0.0.1:8410"
	DefaultBankAddr = "127.0.0.1:8420"
)

// Options configure a playground.
type Options struct {
	// ASAddr and BankAddr are the listen addresses of the IdP and authorization
	// server, and of the bank. A port of 0 picks a free one.
	ASAddr   string
	BankAddr string
	// WardenAddr is the address a client on this host reaches Warden at, for
	// example http://127.0.0.1:8400. It is Warden's OIDC issuer URL, and its
	// JWKS is served under it.
	WardenAddr string
	// WardenCAPEM is the CA of Warden's listener, when it serves TLS.
	WardenCAPEM string
	// AuditPath is where the playground's audit device writes.
	AuditPath string
}

// Playground is a running set of fixtures.
type Playground struct {
	tls      *TLS
	idp      *IdP
	settings Settings
	servers  []*http.Server
}

// Start makes the fixtures and starts serving them. The listeners are bound
// before Start returns, so the URLs it reports are live.
func Start(opts Options) (*Playground, error) {
	if opts.WardenAddr == "" {
		return nil, fmt.Errorf("Warden's address is required")
	}
	if opts.ASAddr == "" {
		opts.ASAddr = DefaultASAddr
	}
	if opts.BankAddr == "" {
		opts.BankAddr = DefaultBankAddr
	}

	tlsID, err := NewTLS()
	if err != nil {
		return nil, err
	}
	asLn, err := net.Listen("tcp", opts.ASAddr)
	if err != nil {
		return nil, fmt.Errorf("playground authorization server: %w", err)
	}
	bankLn, err := net.Listen("tcp", opts.BankAddr)
	if err != nil {
		asLn.Close()
		return nil, fmt.Errorf("playground bank: %w", err)
	}
	asURL, bankURL := localhostURL(asLn.Addr()), localhostURL(bankLn.Addr())
	closeListeners := func() { asLn.Close(); bankLn.Close() }

	idp, err := NewIdP(asURL)
	if err != nil {
		closeListeners()
		return nil, err
	}
	bank, err := NewBank(bankURL, idp.Issuer(), idp.PublicKey())
	if err != nil {
		closeListeners()
		return nil, err
	}
	wardenAddr := strings.TrimRight(opts.WardenAddr, "/")
	as, err := NewAuthServer(AuthServerConfig{
		IdP:           idp,
		WardenIssuer:  wardenAddr,
		WardenJWKSURL: wardenAddr + "/oidc/jwks",
		WardenCAPEM:   opts.WardenCAPEM,
		Audiences:     []string{bank.MCPURL(), bank.APIURL()},
	})
	if err != nil {
		closeListeners()
		return nil, err
	}

	p := &Playground{
		tls: tlsID,
		idp: idp,
		settings: Settings{
			WardenIssuer: wardenAddr,
			ASURL:        asURL,
			BankURL:      bankURL,
			CAPEM:        tlsID.CAPEM,
			AuditPath:    opts.AuditPath,
		},
	}
	for _, s := range []struct {
		ln net.Listener
		h  http.Handler
	}{{asLn, as.Handler()}, {bankLn, bank.Handler()}} {
		srv := &http.Server{Handler: s.h, TLSConfig: tlsID.ServerConfig(), ReadHeaderTimeout: 10 * time.Second}
		p.servers = append(p.servers, srv)
		go func(srv *http.Server, ln net.Listener) {
			_ = srv.ServeTLS(ln, "", "") // ErrServerClosed on shutdown
		}(srv, s.ln)
	}
	return p, nil
}

// localhostURL is the https URL of a loopback listener, named by host so
// verified TLS to it passes the SSRF guard on credential sources.
func localhostURL(addr net.Addr) string {
	_, port, _ := net.SplitHostPort(addr.String())
	if _, err := strconv.Atoi(port); err != nil {
		return "https://localhost"
	}
	return "https://localhost:" + port
}

// Settings are what the bootstrap is built from.
func (p *Playground) Settings() Settings { return p.settings }

// Bootstrap is the ordered set of writes that wires Warden to the playground.
func (p *Playground) Bootstrap() []Step { return Bootstrap(p.settings) }

// MintIdentity signs an agent or user identity with the playground IdP.
func (p *Playground) MintIdentity(id Identity) (string, error) { return p.idp.Mint(id) }

// Scenarios is the playground's tour.
func (p *Playground) Scenarios() []Scenario { return Scenarios() }

// AuditPath is where the playground's audit device writes.
func (p *Playground) AuditPath() string { return p.settings.AuditPath }

// ASURL and BankURL are where the fixtures are served.
func (p *Playground) ASURL() string   { return p.settings.ASURL }
func (p *Playground) BankURL() string { return p.settings.BankURL }

// Close stops the fixtures.
func (p *Playground) Close(ctx context.Context) error {
	var errs []error
	for _, srv := range p.servers {
		if err := srv.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
