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
	WriteCmd = &cobra.Command{
		Use:           "write",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Write data to a path",
		Long: `
Usage: warden write PATH [DATA]

  Write data to the given path. The data can be provided as JSON via stdin,
  as JSON arguments, or as key=value pairs. The path should be in the format
  "provider_mount/resource" or "auth/auth_mount/resource" or "sys/path/to/resource"
  and will be converted to the appropriate API path.

  Write configuration using JSON via stdin:

      $ warden write aws/config <<EOF
      {
        "proxy_domains": ["localhost", "warden"],
        "max_body_size": 10485760,
        "timeout": "60s"
      }
      EOF

  Write configuration using key=value format:

      $ warden write sys/auth/jwt/config auth_deadline=30s token_ttl=1h proxy_domains='["localhost","warden"]'
`,
		Args: cobra.MinimumNArgs(1),
		RunE: runWrite,
	}
)

func runWrite(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("path argument is required")
	}

	path := args[0]

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
	} else if len(args) > 1 {
		// Try to parse remaining args as key=value pairs or JSON
		data = make(map[string]interface{})

		// Check if first arg looks like key=value format
		if strings.Contains(args[1], "=") {
			// Parse as key=value pairs with type inference
			for _, arg := range args[1:] {
				parts := strings.SplitN(arg, "=", 2)
				if len(parts) != 2 {
					return fmt.Errorf("invalid key=value format: %s", arg)
				}
				key := parts[0]
				value := parts[1]

				// Try to infer the type of the value
				data[key] = inferType(value)
			}
		} else {
			// Try to parse as JSON
			jsonStr := strings.Join(args[1:], " ")
			if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
				return fmt.Errorf("failed to parse JSON from arguments: %w", err)
			}
		}
	}

	// The Operator().Write method automatically adds /v1/ prefix
	_, err = c.Operator().Write(path, data)
	if err != nil {
		return fmt.Errorf("failed to write to %s: %w", path, err)
	}

	fmt.Printf("Success! Data written to: %s\n", path)
	return nil
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

