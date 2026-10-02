package dev

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

const devJWTPath = "sys/dev/jwt"

var (
	jwtMayAct string
	jwtTTL    time.Duration
	jwtClaims string
	jwtJSON   string

	JWTCmd = &cobra.Command{
		Use:           "jwt [agent|user] [sub]",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Mint an agent or user identity signed by the playground IdP",
		Long: `
Usage: warden dev jwt <agent|user> <sub> [options]

  Mint a JWT from the playground's identity provider. An agent presents its
  own; a user's is presented alongside an agent's when the agent acts for
  them. The token is printed bare, so it can be captured:

      $ AGENT=$(warden dev jwt agent agent-1)

  A user can name the agent allowed to act for them (the may_act claim the
  playground's policy checks):

      $ ALICE=$(warden dev jwt user alice -may-act agent-1)

  Extra claims and a lifetime (default 1h, at most 24h):

      $ warden dev jwt agent agent-1 -claims '{"team": "ops"}' -ttl 4h

  Or the whole request as JSON:

      $ warden dev jwt -json '{
          "kind": "user",
          "sub": "alice",
          "may_act": { "sub": "agent-1" },
          "ttl": "1h"
        }'

  With -o json, the token is printed with its decoded claims.
`,
		Args: cobra.MaximumNArgs(2),
		RunE: runJWT,
	}
)

func init() {
	JWTCmd.Flags().StringVar(&jwtMayAct, "may-act", "", "For a user: the agent allowed to act for them")
	JWTCmd.Flags().DurationVar(&jwtTTL, "ttl", 0, "Lifetime of the token (default 1h, at most 24h)")
	JWTCmd.Flags().StringVar(&jwtClaims, "claims", "", "Extra claims as a JSON object")
	JWTCmd.Flags().StringVar(&jwtJSON, "json", "", "The whole request as JSON ('<json>', @file or - for stdin)")
}

func runJWT(cmd *cobra.Command, args []string) error {
	payload, err := jwtPayload(cmd, args)
	if err != nil {
		return err
	}
	c, err := helpers.Client()
	if err != nil {
		return err
	}
	resource, err := c.Operator().Write(devJWTPath, payload)
	if err != nil {
		return fmt.Errorf("error minting a playground identity: %w", err)
	}
	if resource == nil || resource.Data == nil {
		return fmt.Errorf("the server returned no token; is it running with -dev-playground?")
	}
	token, _ := resource.Data["token"].(string)

	// Bare by default, so $(...) works even though captured output is not a
	// terminal. Structured output only when asked for explicitly.
	if !structuredOutputRequested() {
		fmt.Fprintln(cmd.OutOrStdout(), token)
		return nil
	}
	return helpers.RenderMap(map[string]any{"token": token, "claims": decodeClaims(token)}, nil)
}

// jwtPayload builds the request from either -json or the positional arguments
// and flags, never both.
func jwtPayload(cmd *cobra.Command, args []string) (map[string]any, error) {
	fromJSON, err := helpers.ResolveJSONInput(jwtJSON)
	if err != nil {
		return nil, err
	}
	if fromJSON != nil {
		if err := helpers.RejectFlagsWithJSON(true, map[string]bool{
			"positional arguments": len(args) > 0,
			"-may-act":             cmd.Flags().Changed("may-act"),
			"-ttl":                 cmd.Flags().Changed("ttl"),
			"-claims":              cmd.Flags().Changed("claims"),
		}); err != nil {
			return nil, err
		}
		// may_act may be given as the claim's own shape, {"sub": "agent-1"}.
		if obj, ok := fromJSON["may_act"].(map[string]any); ok {
			fromJSON["may_act"], _ = obj["sub"].(string)
		}
		return fromJSON, nil
	}

	if len(args) != 2 {
		return nil, fmt.Errorf("give the kind and the subject, e.g. `warden dev jwt agent agent-1`, or -json: %w", helpers.ErrUsage)
	}
	payload := map[string]any{"kind": args[0], "sub": args[1]}
	if jwtMayAct != "" {
		payload["may_act"] = jwtMayAct
	}
	if jwtTTL != 0 {
		payload["ttl"] = jwtTTL.String()
	}
	if jwtClaims != "" {
		var claims map[string]any
		if err := json.Unmarshal([]byte(jwtClaims), &claims); err != nil || claims == nil {
			return nil, fmt.Errorf("-claims must be a JSON object: %w", helpers.ErrInvalidInput)
		}
		payload["claims"] = claims
	}
	return payload, nil
}

// structuredOutputRequested reports whether -o or WARDEN_OUTPUT explicitly asks
// for json or ndjson.
func structuredOutputRequested() bool {
	if *helpers.OutputFlagPtr() == "" && os.Getenv("WARDEN_OUTPUT") == "" {
		return false
	}
	f := helpers.ResolveFormat()
	return f == helpers.FormatJSON || f == helpers.FormatNDJSON
}

// decodeClaims shows a JWT's payload. It does not verify the token: the server
// that minted it just returned it.
func decodeClaims(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]any
	_ = json.Unmarshal(raw, &claims)
	return claims
}
