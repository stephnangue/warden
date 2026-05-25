package basic

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	writePath string

	WriteCmd = &cobra.Command{
		Use:           "write",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Write data to a path",
		Long: `
Usage: warden write [PATH] [DATA]

  Write data to the given path. The PATH may be supplied either positionally
  or via -path (pick one — combining both is rejected). When -path is used,
  all remaining positional arguments are treated as DATA. The data can be
  provided as JSON via stdin, as JSON arguments, or as key=value pairs. The
  path should be in the format "provider_mount/resource" or
  "auth/auth_mount/resource" or "sys/path/to/resource" and will be converted
  to the appropriate API path.

  Write configuration using JSON via stdin:

      $ warden write aws/config <<EOF
      {
        "proxy_domains": ["localhost", "warden"],
        "max_body_size": 10485760,
        "timeout": "60s"
      }
      EOF

  Write configuration using key=value format:

      $ warden write aws/config token_ttl=1h proxy_domains='["localhost","warden"]'
      $ warden write -path=aws/config token_ttl=1h

  Use @file to read a value from a file (useful for PEM certificates, large payloads, etc.):

      $ warden write auth/cert/config trusted_ca_pem=@/path/to/ca.pem default_role=my-role
`,
		RunE: runWrite,
	}
)

func init() {
	WriteCmd.Flags().StringVar(&writePath, "path", "", "API path (alternative to the positional PATH argument)")
}

func runWrite(cmd *cobra.Command, args []string) error {
	// -path frees args[0] for DATA; without -path, args[0] is the PATH.
	var path string
	var dataArgs []string
	if writePath != "" {
		path = writePath
		dataArgs = args
	} else {
		p, err := helpers.RequirePath(args, "")
		if err != nil {
			return err
		}
		path = p
		dataArgs = args[1:]
	}
	if err := helpers.ValidatePath(path); err != nil {
		return err
	}

	// Create the client
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	// Read data from stdin or args
	var data map[string]interface{}

	// Check if data is being piped via stdin
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		// Data is being piped
		bytes, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read from stdin: %w", err)
		}

		if len(bytes) > 0 {
			if err := json.Unmarshal(bytes, &data); err != nil {
				return fmt.Errorf("failed to parse JSON: %w", err)
			}
		}
	} else if len(dataArgs) > 0 {
		// Try to parse remaining args as key=value pairs or JSON
		data = make(map[string]interface{})

		// Check if first arg looks like key=value format
		if strings.Contains(dataArgs[0], "=") {
			// Parse as key=value pairs with type inference
			for _, arg := range dataArgs {
				parts := strings.SplitN(arg, "=", 2)
				if len(parts) != 2 {
					return fmt.Errorf("invalid key=value format %q: %w", arg, helpers.ErrInvalidInput)
				}
				key := parts[0]
				value := parts[1]

				// Check for @file reference — read file contents as string
				if strings.HasPrefix(value, "@") {
					fileData, err := os.ReadFile(value[1:])
					if err != nil {
						return fmt.Errorf("failed to read file for key %q: %w", key, err)
					}
					data[key] = string(fileData)
					continue
				}

				// Try to infer the type of the value
				data[key] = inferType(value)
			}
		} else {
			// Try to parse as JSON
			jsonStr := strings.Join(dataArgs, " ")
			if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
				return fmt.Errorf("failed to parse JSON from arguments: %w", err)
			}
		}
	}

	// -dry-run: validate the payload locally against the server's published
	// schema and stop here. Nothing leaves the process.
	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "POST", path, data)
	}

	// The Operator().Write method automatically adds /v1/ prefix
	_, err = c.Operator().Write(path, data)
	if err != nil {
		return fmt.Errorf("failed to write to %s: %w", path, err)
	}

	return helpers.RenderMap(map[string]any{"path": path, "written": true}, func() {
		fmt.Printf("Success! Data written to: %s\n", path)
	})
}

// inferType attempts to infer the type of a string value
func inferType(value string) interface{} {
	// Try parsing as JSON (arrays, objects)
	if strings.HasPrefix(value, "[") || strings.HasPrefix(value, "{") {
		var jsonValue interface{}
		if err := json.Unmarshal([]byte(value), &jsonValue); err == nil {
			return jsonValue
		}
	}

	// Try parsing as integer
	if i, err := strconv.ParseInt(value, 10, 64); err == nil {
		return i
	}

	// Try parsing as float
	if f, err := strconv.ParseFloat(value, 64); err == nil {
		return f
	}

	// Try parsing as boolean
	if b, err := strconv.ParseBool(value); err == nil {
		return b
	}

	// Default to string
	return value
}
