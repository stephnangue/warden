package login

import (
	"context"
	"fmt"
	"os"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/client"
)

var (
	LoginCmd = &cobra.Command{
		Use:   "server",
		Short: "This command is used to authenticate to Warden server.",
		Long:  `
Usage: warden login [options] [AUTH K=V...]

  Authenticates users or machines to Warden using the provided arguments. A
  successful authentication results in a Warden token - conceptually similar to
  a session token on a website. A token can take many forms : it can be a 
  username-password or aws-access-keys, depending on the role provided
  during the authentication. By default, this token is cached on the local
  machine for future requests, and store into environment variables.

  There is no default auth method. You should provide the auth method using
  the --method flag. For these, additional "K=V" pairs may be required. For example, to
  authenticate to the jwt auth method:

      $ warden login --method=jwt --token="$JWT_TOKEN" --role="<your_role_name>"

  For more information about the list of configuration parameters available for
  a given auth method, use the "warden auth help TYPE" command. You can also use
  "warden auth list" to see the list of enabled auth methods.

  If an auth method is enabled at a non-standard path, the --method flag still
  refers to the canonical type, but the --path flag refers to the enabled path.
  If a jwt auth method was enabled at "jwt-prod", authenticate like this:

      $ warden login --method=jwt --path=jwt-prod
`,
		RunE:  run,
	}

	flagMethod  string
	flagPath    string
	flagRole    string

	flagToken   string

	Handlers = map[string]LoginHandler{
		"jwt": JWTHandler{},
	}

)

// LoginHandler is the interface that any auth handlers must implement to enable
// auth via the CLI.
type LoginHandler interface {
	Auth(context.Context, *api.Client, map[string]string) (*api.Resource, error)
}

func init() {
	LoginCmd.Flags().StringVarP(&flagMethod, "method", "m", "", "The auth method to use")
	LoginCmd.Flags().StringVarP(&flagPath, "path", "p", "", "The path on which the method was enabled")
	LoginCmd.Flags().StringVarP(&flagRole, "role", "r", "", "The role the assume after successful authentication")
	LoginCmd.Flags().StringVarP(&flagToken, "token", "t", "", "The JWT to use with JWT auth method")
}

func run(cmd *cobra.Command, args []string) error {
	if flagMethod == "" {
		return fmt.Errorf("auth method is required. Use -m or --method flag")
	}

	// Get the handler function
	authHandler, ok := Handlers[flagMethod]
	if !ok {
		return fmt.Errorf("Unknown auth method: %s. Use \"warden auth list\" to see the "+
				"complete list of auth methods. Additionally, some "+
				"auth methods are only available via the CLI.", flagMethod)
	}

	if flagRole == "" {
		return fmt.Errorf("role name is required. Use -r or --role flag")
	}

	config := make(map[string]string)
	config["role"] = flagRole

	if flagPath !=  "" {
		config["mount"] = flagPath
	}

	switch flagMethod {
	case "jwt":
		if flagToken == "" {
			return fmt.Errorf("token is required for jwt auth method. Use -t or --token flag")
		}
		config["token"] = flagToken
	default:
		return fmt.Errorf("unsupported auth method: %s", flagMethod)
	}

	// Create the client
	c, err := client.Client()
	if err != nil {
		return err
	}

	// Authenticate delegation to the auth handler
	result, err := authHandler.Auth(cmd.Context(), c, config)
	if err != nil {
		return fmt.Errorf("Error authenticating: %s", err)
	}

	// Print result in table format
	printResultTable(result)

	return nil
}

// printResultTable prints the result.Data in a formatted table similar to Vault CLI
func printResultTable(result *api.Resource) {
	if result == nil || result.Data == nil {
		fmt.Println("No data to display")
		return
	}

	table := tablewriter.NewWriter(os.Stdout)

	// Configure table to look like Vault CLI output
	table.SetAutoWrapText(false)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetTablePadding("    ") // 4 spaces padding like Vault
	table.SetNoWhiteSpace(true)
	table.SetAutoFormatHeaders(false)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)

	// Add rows without header (Vault style)
	for key, value := range result.Data {
		formattedValue := formatValue(value)
		table.Append([]string{key, formattedValue})
	}

	table.Render()
}

// formatValue formats a value for display, handling nested structures
func formatValue(value interface{}) string {
	switch v := value.(type) {
	case map[string]interface{}:
		// Format nested maps with indentation
		var parts []string
		for k, val := range v {
			parts = append(parts, fmt.Sprintf("%s=%v", k, val))
		}
		return fmt.Sprintf("map[%s]", fmt.Sprint(parts))
	case []interface{}:
		// Format slices
		return fmt.Sprintf("%v", v)
	case nil:
		return "n/a"
	default:
		return fmt.Sprintf("%v", v)
	}
}