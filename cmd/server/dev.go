package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/stephnangue/warden/core"
)

// devModeInit performs auto-initialization and auto-unseal for dev mode.
// If customRootToken is non-empty, the generated root token is replaced with it.
func devModeInit(c *core.Core, customRootToken string) (*core.InitResult, error) {
	ctx := context.Background()

	// Initialize with 1 share / 1 threshold (simplest config).
	// AutoSeal requires a RecoveryConfig, so provide one with the same minimal setup.
	initParams := &core.InitParams{
		BarrierConfig: &core.SealConfig{
			SecretShares:    1,
			SecretThreshold: 1,
		},
		RecoveryConfig: &core.SealConfig{
			SecretShares:    1,
			SecretThreshold: 1,
		},
	}

	result, err := c.Initialize(ctx, initParams)
	if err != nil {
		return nil, fmt.Errorf("auto-initialization failed: %w", err)
	}

	// Auto-unseal using stored keys (works because we use TestSeal / AutoSeal)
	if err := c.UnsealWithStoredKeys(ctx); err != nil {
		return nil, fmt.Errorf("auto-unseal failed: %w", err)
	}

	// If a custom root token was specified, replace the generated one
	if customRootToken != "" {
		if err := c.GetTokenStore().ReplaceRootTokenValue(customRootToken); err != nil {
			return nil, fmt.Errorf("failed to set custom root token: %w", err)
		}
		result.RootToken = customRootToken
	}

	return result, nil
}

// printDevBanner prints the dev mode startup banner with unseal keys and root token.
// If devTLSCertDir is non-empty, it also prints the paths to the auto-generated
// TLS certificate and key, along with usage instructions. If devTLSSpiffe is set,
// it notes that the listener serves a SPIFFE SVID from the Workload API instead.
// It warns when listenAddr binds beyond loopback, since the root token is then
// usable by anyone who can reach the listener.
func printDevBanner(w io.Writer, result *core.InitResult, listenAddr, devTLSCertDir string, devTLSSpiffe bool) {
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "==> Warden server started in dev mode! <==\n")
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "WARNING! dev mode is enabled! In this mode, Warden runs entirely\n")
	fmt.Fprintf(w, "in-memory and starts automatically initialized and unsealed.\n")
	fmt.Fprintf(w, "All data is lost on restart. Do NOT run dev mode in production!\n")
	fmt.Fprintf(w, "\n")

	for i, share := range result.SecretShares {
		fmt.Fprintf(w, "Unseal Key %d: %x\n", i+1, share)
	}
	if len(result.SecretShares) > 0 {
		fmt.Fprintf(w, "\n")
	}

	fmt.Fprintf(w, "Root Token: %s\n", result.RootToken)
	fmt.Fprintf(w, "\n")

	if !isLoopbackListenAddr(listenAddr) {
		fmt.Fprintf(w, "WARNING! The dev listener binds %s, beyond this host's loopback\n", listenAddr)
		fmt.Fprintf(w, "interface. Anyone who can reach it can use the root token above.\n")
		fmt.Fprintf(w, "\n")
	}

	if devTLSCertDir != "" {
		fmt.Fprintf(w, "Dev TLS Certificate:  %s/cert.pem\n", devTLSCertDir)
		fmt.Fprintf(w, "Dev TLS Private Key:  %s/key.pem\n", devTLSCertDir)
		fmt.Fprintf(w, "\n")
		fmt.Fprintf(w, "The certificate is self-signed, clients need to trust it:\n")
		fmt.Fprintf(w, "\n")
		fmt.Fprintf(w, "  $ export WARDEN_CACERT=%s/cert.pem\n", devTLSCertDir)
		fmt.Fprintf(w, "  $ export WARDEN_ADDR=%s\n", devClientAddr("https", listenAddr))
		fmt.Fprintf(w, "\n")
	}

	if devTLSSpiffe {
		fmt.Fprintf(w, "Dev TLS Source: SPIFFE Workload API (auto-rotating SVID, no key on disk)\n")
		fmt.Fprintf(w, "\n")
		fmt.Fprintf(w, "The server presents a SPIFFE SVID; clients must be SPIFFE-aware\n")
		fmt.Fprintf(w, "(trust the SPIRE bundle and skip hostname verification).\n")
		fmt.Fprintf(w, "\n")
	}

	fmt.Fprintf(w, "Development mode should NOT be used in production installations!\n")
	fmt.Fprintf(w, "\n")
}

// isLoopbackListenAddr reports whether a listener on addr is reachable only
// from this host. An empty or unspecified host binds every interface.
func isLoopbackListenAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// devClientAddr returns the URL a client on the same host uses to reach the
// dev listener. A listener bound to every interface is reached on loopback.
func devClientAddr(scheme, listenAddr string) string {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return scheme + "://" + listenAddr
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}
