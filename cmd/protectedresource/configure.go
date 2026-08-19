package protectedresource

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	configureResourceURL string
	configureAuthServers []string
	configureDocaURL     string
	configureCacheTTL    string
	configureJSON        string

	ConfigureCmd = &cobra.Command{
		Use:           "configure",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Configure protected resource metadata",
		Long: `
Usage: warden protected-resource configure [flags]

  Set the deployment-wide protected resource metadata configuration. Writes are
  partial: a flag you omit keeps its stored value. Root namespace only.

  -resource-url is the master switch. It must be the external HTTPS address
  clients actually reach Warden at, because each document's "resource" field is
  this joined with the mount's API path, and clients compare that literally.
  Warden never derives it from a request's Host header, which a client controls.

      $ warden protected-resource configure -resource-url=https://warden.example.com

  Leave -authorization-server unset to derive each mount's issuer from the auth
  method at its user_auth_path — the usual case. Set it only when the derived
  value is wrong, such as an identity provider behind a proxy.

      $ warden protected-resource configure \
          -resource-url=https://warden.example.com \
          -documentation=https://docs.example.com/mcp \
          -cache-ttl=1h

      $ warden protected-resource configure -json '{"resource_url":"https://warden.example.com"}'

  Combine with -dry-run to preview the request without sending it.
`,
		Args: cobra.NoArgs,
		RunE: runConfigure,
	}
)

func init() {
	ConfigureCmd.Flags().StringVar(&configureResourceURL, "resource-url", "",
		"External HTTPS base URL clients reach Warden at (enables metadata)")
	ConfigureCmd.Flags().StringSliceVar(&configureAuthServers, "authorization-server", nil,
		"Override the advertised authorization server(s); repeatable")
	ConfigureCmd.Flags().StringVar(&configureDocaURL, "documentation", "",
		"Optional human-facing documentation URL echoed in every document")
	ConfigureCmd.Flags().StringVar(&configureCacheTTL, "cache-ttl", "",
		"Cache-Control max-age of a served document (default: 1h)")
	ConfigureCmd.Flags().StringVarP(&configureJSON, "json", "j", "",
		"Full JSON payload — '<json>', '@file.json', or '-' for stdin (mutually exclusive with the field flags)")
}

func runConfigure(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	jsonPayload, err := helpers.ResolveJSONInput(configureJSON)
	if err != nil {
		return err
	}

	var payload map[string]any
	if jsonPayload != nil {
		for _, f := range []string{"resource-url", "authorization-server", "documentation", "cache-ttl"} {
			if cmd.Flags().Changed(f) {
				return fmt.Errorf("-json is mutually exclusive with -%s: %w", f, helpers.ErrUsage)
			}
		}
		payload = jsonPayload
	} else {
		payload = map[string]any{}
		// Only send fields the caller actually set: the server treats an absent
		// field as "keep", so sending zero values would silently clear them.
		if cmd.Flags().Changed("resource-url") {
			payload["resource_url"] = configureResourceURL
		}
		if cmd.Flags().Changed("authorization-server") {
			payload["authorization_servers"] = configureAuthServers
		}
		if cmd.Flags().Changed("documentation") {
			payload["resource_documentation"] = configureDocaURL
		}
		if cmd.Flags().Changed("cache-ttl") {
			payload["cache_ttl"] = configureCacheTTL
		}
		if len(payload) == 0 {
			return fmt.Errorf("supply at least one field (or use -json): %w", helpers.ErrUsage)
		}
	}

	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "POST", protectedResourceConfigPath, payload)
	}

	if _, err := c.Operator().Write(protectedResourceConfigPath, payload); err != nil {
		return fmt.Errorf("error configuring protected resource metadata: %w", err)
	}

	resource, err := c.Operator().Read(protectedResourceConfigPath)
	if err != nil {
		return fmt.Errorf("error reading back configuration: %w", err)
	}
	return helpers.RenderMap(resource.Data, func() {
		fmt.Println("Success! Protected resource metadata configured.")
		printConfigTable(resource.Data)
	})
}
