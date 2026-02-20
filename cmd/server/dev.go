package server

import (
	"context"
	"fmt"
	"io"

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
func printDevBanner(w io.Writer, result *core.InitResult) {
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
	fmt.Fprintf(w, "Development mode should NOT be used in production installations!\n")
	fmt.Fprintf(w, "\n")
}
