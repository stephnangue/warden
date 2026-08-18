package protectedresource

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var DisableCmd = &cobra.Command{
	Use:           "disable",
	SilenceUsage:  true,
	SilenceErrors: true,
	Short:         "Stop serving protected resource metadata",
	Long: `
Usage: warden protected-resource disable

  Clear resource_url, so no metadata document is served and every well-known
  path returns 404. Mounts keep their user_auth_path and continue to accept a
  user credential — only discovery stops. Root namespace only.

  The rest of the configuration is retained, so a later 'configure
  -resource-url=...' restores it without re-supplying the other fields.

      $ warden protected-resource disable
`,
	Args: cobra.NoArgs,
	RunE: runDisable,
}

func runDisable(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	payload := map[string]any{"resource_url": ""}

	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "POST", protectedResourceConfigPath, payload)
	}

	if _, err := c.Operator().Write(protectedResourceConfigPath, payload); err != nil {
		return fmt.Errorf("error disabling protected resource metadata: %w", err)
	}

	return helpers.RenderMap(map[string]any{"enabled": false}, func() {
		fmt.Println("Success! Protected resource metadata disabled.")
	})
}
