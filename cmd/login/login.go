package login

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	LoginCmd = &cobra.Command{
		Use:           "login",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "This command is used to authenticate to Warden server.",
		Long: `
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

  To authenticate using a client certificate:

      $ warden login --method=cert --role=agent --cert=./agent.pem --key=./agent-key.pem

  Or with environment variables:

      $ export WARDEN_CLIENT_CERT=./agent.pem
      $ export WARDEN_CLIENT_KEY=./agent-key.pem
      $ export WARDEN_ROLE=agent
      $ warden login --method=cert

  For more information about the list of configuration parameters available for
  a given auth method, use the "warden auth help TYPE" command. You can also use
  "warden auth list" to see the list of enabled auth methods.

  If an auth method is enabled at a non-standard path, the --method flag still
  refers to the canonical type, but the --path flag refers to the enabled path.
  If a jwt auth method was enabled at "jwt-prod", authenticate like this:

      $ warden login --method=jwt --path=jwt-prod

  Alternatively, you can provide the path as a positional argument:

      $ warden login --method=jwt jwt-prod
`,
		RunE: run,
	}

	flagMethod string
	flagPath   string

	flagToken string
	flagCert  string
	flagKey   string

	Handlers = map[string]LoginHandler{
		"jwt":  JWTHandler{},
		"cert": CertHandler{},
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
	LoginCmd.Flags().StringVarP(&flagToken, "token", "t", "", "The JWT to use with JWT auth method")
	LoginCmd.Flags().StringVar(&flagCert, "cert", "", "The client certificate file for cert auth method")
	LoginCmd.Flags().StringVar(&flagKey, "key", "", "The client key file for cert auth method")
	LoginCmd.MarkFlagRequired("method")
}

func run(cmd *cobra.Command, args []string) error {
	// Get the handler function
	authHandler, ok := Handlers[flagMethod]
	if !ok {
		return fmt.Errorf("unknown auth method: %s. Use 'warden auth list' to see the complete list of auth methods. Additionally, some "+
			"auth methods are only available via the API.", flagMethod)
	}

	// Resolve role from global --role flag (set as WARDEN_ROLE env var) or env var directly
	role := api.ReadWardenVariable(api.EnvWardenRole)
	if role == "" {
		return fmt.Errorf("role is required. Use --role flag or set the WARDEN_ROLE environment variable")
	}

	config := make(map[string]string)
	config["role"] = role

	// Support both --path flag and positional argument
	path := flagPath
	if path == "" && len(args) > 0 {
		path = args[0]
	}

	if path != "" {
		config["mount"] = path
	}

	switch flagMethod {
	case "jwt":
		if flagToken == "" {
			return fmt.Errorf("token is required for jwt auth method. Use -t or --token flag")
		}
		config["token"] = flagToken
	case "cert":
		if flagCert != "" {
			config["cert"] = flagCert
			config["key"] = flagKey
		}
	default:
		return fmt.Errorf("unsupported auth method: %s", flagMethod)
	}

	// Create the client
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	// Authenticate delegation to the auth handler
	result, err := authHandler.Auth(cmd.Context(), c, config)
	if err != nil {
		return fmt.Errorf("error authenticating: %s", err)
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

	helpers.PrintMapAsTable(result.Data)
}
