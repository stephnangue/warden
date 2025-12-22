package operator

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	// Flags for init parameters
	pgpKeys           []string
	rootTokenPGPKey   string
	secretShares      int
	secretThreshold   int
	storedShares      int
	recoveryShares    int
	recoveryThreshold int
	recoveryPGPKeys   []string

	initCmd = &cobra.Command{
		Use:           "init",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Initialize Warden and generate root token",
		Long: `
Initialize a Warden server using Shamir secret sharing to split the root key.

The root token is used to perform system admin operations such as:
  - Mounting/unmounting auth methods
  - Mounting/unmounting providers
  - Configuring system settings

Shamir Secret Sharing:
  The root key is split into multiple shares using Shamir's secret sharing algorithm.
  A threshold number of shares is required to reconstruct the root key and unseal Warden.

  Default: 5 shares with a threshold of 3 (5 shares generated, 3 needed to unseal)

Usage:
  # Initialize with default settings (5 shares, threshold 3)
  $ warden operator init

  # Initialize with custom shares and threshold
  $ warden operator init --secret-shares=7 --secret-threshold=4

  # Initialize with PGP encryption for unseal keys
  $ warden operator init --pgp-keys="keybase:user1,keybase:user2,keybase:user3,keybase:user4,keybase:user5"

  # Initialize with PGP-encrypted root token
  $ warden operator init --root-token-pgp-key="keybase:admin"

IMPORTANT: The unseal keys and root token are displayed only once. Store them securely.
You will need the threshold number of unseal keys to unseal Warden after restart.
`,
		RunE: run,
	}
)

func init() {
	// Shamir secret sharing parameters
	initCmd.Flags().IntVar(&secretShares, "secret-shares", 5, "Number of key shares to generate")
	initCmd.Flags().IntVar(&secretThreshold, "secret-threshold", 3, "Number of key shares required to unseal")

	// PGP encryption parameters
	initCmd.Flags().StringSliceVar(&pgpKeys, "pgp-keys", nil, "Comma-separated list of PGP public keys for encrypting unseal keys (base64-encoded or keybase:username)")
	initCmd.Flags().StringVar(&rootTokenPGPKey, "root-token-pgp-key", "", "PGP public key for encrypting the root token (base64-encoded or keybase:username)")

	// Auto-unseal parameters (advanced)
	initCmd.Flags().IntVar(&storedShares, "stored-shares", 0, "Number of shares to store (auto-unseal only)")
	initCmd.Flags().IntVar(&recoveryShares, "recovery-shares", 5, "Number of recovery key shares (auto-unseal only)")
	initCmd.Flags().IntVar(&recoveryThreshold, "recovery-threshold", 3, "Number of recovery shares required (auto-unseal only)")
	initCmd.Flags().StringSliceVar(&recoveryPGPKeys, "recovery-pgp-keys", nil, "Comma-separated list of PGP public keys for encrypting recovery keys (auto-unseal only)")
}

func run(cmd *cobra.Command, args []string) error {
	// Create the client
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	// Build the init request
	initReq := &api.InitRequest{
		SecretShares:      secretShares,
		SecretThreshold:   secretThreshold,
		PGPKeys:           pgpKeys,
		RootTokenPGPKey:   rootTokenPGPKey,
		StoredShares:      storedShares,
		RecoveryShares:    recoveryShares,
		RecoveryThreshold: recoveryThreshold,
		RecoveryPGPKeys:   recoveryPGPKeys,
	}

	// Call Init API with request
	initResp, err := c.Sys().InitWithRequest(initReq)
	if err != nil {
		return fmt.Errorf("initialization failed: %w", err)
	}

	// Display initialization results
	fmt.Println()
	fmt.Println("=========================================")
	fmt.Println("   WARDEN INITIALIZATION COMPLETE")
	fmt.Println("=========================================")
	fmt.Println()

	// Display unseal keys
	if len(initResp.Keys) > 0 {
		fmt.Println("Unseal Keys:")
		for i, key := range initResp.Keys {
			fmt.Printf("Unseal Key %d: %s\n", i+1, key)
		}
		fmt.Println()
	}

	// Display recovery keys (if auto-unseal)
	if len(initResp.RecoveryKeys) > 0 {
		fmt.Println("Recovery Keys:")
		for i, key := range initResp.RecoveryKeys {
			fmt.Printf("Recovery Key %d: %s\n", i+1, key)
		}
		fmt.Println()
	}

	// Display root token
	fmt.Println("Root Token:")
	fmt.Println(initResp.RootToken)
	fmt.Println()

	fmt.Println("IMPORTANT: These keys will not be shown again!")
	fmt.Println("Store them securely. You will need:")
	if len(initResp.Keys) > 0 {
		fmt.Printf("  - %d of %d unseal keys to unseal Warden\n", secretThreshold, secretShares)
	}
	fmt.Println("  - The root token for system administration")
	fmt.Println()

	fmt.Println("The root token can be used to:")
	fmt.Println("  - Mount/unmount auth methods")
	fmt.Println("  - Mount/unmount providers")
	fmt.Println("  - Perform system administration")
	fmt.Println()

	fmt.Println("Export root token to environment:")
	fmt.Printf("  export WARDEN_TOKEN=%s\n", initResp.RootToken)
	fmt.Println("=========================================")
	fmt.Println()

	return nil
}
