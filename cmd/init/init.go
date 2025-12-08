package init

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	InitCmd = &cobra.Command{
		Use:           "init",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Initialize Warden and generate root token",
		Long: `
Initialize a Warden server by generating a root token for system administration.

The root token is used to perform system admin operations such as:
  - Mounting/unmounting auth methods
  - Mounting/unmounting providers
  - Configuring system settings

Usage:
  $ warden init

IMPORTANT: The root token is displayed only once. Store it securely.
The root token is stored in-memory only and will be cleared on server restart.
You must run 'warden init' again after restarting the server.
`,
		RunE: run,
	}
)

func run(cmd *cobra.Command, args []string) error {
	// Create the client
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	// Call Init API
	initResp, err := c.Sys().Init()
	if err != nil {
		return fmt.Errorf("initialization failed: %w", err)
	}

	// Display root token prominently
	fmt.Println()
	fmt.Println("=========================================")
	fmt.Println("   WARDEN INITIALIZATION COMPLETE")
	fmt.Println("=========================================")
	fmt.Println()
	fmt.Println("Root Token:")
	fmt.Println(initResp.RootToken)
	fmt.Println()
	fmt.Println("IMPORTANT: This token will not be shown again!")
	fmt.Println("Store it securely. You can use it to:")
	fmt.Println("  - Mount/unmount auth methods")
	fmt.Println("  - Mount/unmount providers")
	fmt.Println("  - Perform system administration")
	fmt.Println()
	fmt.Println("The root token is stored in-memory only.")
	fmt.Println("After server restart, run 'warden init' again.")
	fmt.Println()
	fmt.Println("Export to environment:")
	fmt.Printf("  export WARDEN_TOKEN=%s\n", initResp.RootToken)
	fmt.Println("=========================================")
	fmt.Println()

	return nil
}
