package oidcissuer

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	cfgIssuerURL         string
	cfgAssertionTTL      string
	cfgKeyRotationPeriod string
	cfgJWKSCacheTTL      string
	cfgRetiredKeyGrace   string

	cfgJSON string

	ConfigureCmd = &cobra.Command{
		Use:           "configure",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Enable and configure the OIDC issuer",
		Long: `
Usage: warden oidc-issuer configure [options]

  Enable the OIDC issuer and set its issuer URL, assertion TTL, and signing-key
  rotation timings. Root namespace only. Use 'warden oidc-issuer set-publisher'
  to push the discovery + JWKS documents to a bucket/CDN.

  A write is a PARTIAL update: only the fields you pass change; everything else
  keeps its current value. So you can tweak one setting without re-supplying the
  rest. Clear or disable a field by setting it explicitly (e.g.
  -key-rotation-period=0). Duration flags accept a Go duration ("5m", "24h") or
  a number of seconds. Use 'warden oidc-issuer disable' to turn the issuer off.

  First-time enable:

      $ warden oidc-issuer configure -issuer-url=https://warden.example.com

  Change just the rotation cadence later (issuer_url and the rest are kept):

      $ warden oidc-issuer configure -key-rotation-period=24h

  Full JSON payload (agent-friendly):

      $ warden oidc-issuer configure -json @issuer.json
      $ cat issuer.json | warden oidc-issuer configure -json -

  -json is mutually exclusive with the typed flags. Combine any mode with
  -dry-run to validate the payload against the server schema without writing.
`,
		RunE: runConfigure,
	}
)

func init() {
	f := ConfigureCmd.Flags()
	f.StringVar(&cfgIssuerURL, "issuer-url", "", "Public HTTPS URL upstreams fetch discovery/JWKS from and the `iss` claim (required on first enable)")
	f.StringVar(&cfgAssertionTTL, "assertion-ttl", "", "Lifetime of a minted identity assertion (default 5m)")
	f.StringVar(&cfgKeyRotationPeriod, "key-rotation-period", "", "Signing-key rotation cadence (0 disables automatic rotation)")
	f.StringVar(&cfgJWKSCacheTTL, "jwks-cache-ttl", "", "Cache-Control max-age of the published JWKS; also the min pre-publication age of a new key (default 1m)")
	f.StringVar(&cfgRetiredKeyGrace, "retired-key-grace", "", "Margin beyond the assertion TTL before a retired key is pruned from the JWKS (default 1h)")

	f.StringVarP(&cfgJSON, "json", "j", "", "Full JSON payload — '<json>', '@file.json', or '-' for stdin (mutually exclusive with the typed flags)")
}

func runConfigure(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	jsonPayload, err := helpers.ResolveJSONInput(cfgJSON)
	if err != nil {
		return err
	}

	var payload map[string]any
	if jsonPayload != nil {
		if err := helpers.RejectFlagsWithJSON(true, map[string]bool{
			"-issuer-url":          cfgIssuerURL != "",
			"-assertion-ttl":       cfgAssertionTTL != "",
			"-key-rotation-period": cfgKeyRotationPeriod != "",
			"-jwks-cache-ttl":      cfgJWKSCacheTTL != "",
			"-retired-key-grace":   cfgRetiredKeyGrace != "",
		}); err != nil {
			return err
		}
		payload = jsonPayload
		if _, ok := payload["enabled"]; !ok {
			payload["enabled"] = true
		}
	} else {
		// configure both enables the issuer and sets the provided fields; the
		// server merges these over the stored config, leaving unset fields intact.
		payload = map[string]any{"enabled": true}
		setIfNonEmpty(payload, "issuer_url", cfgIssuerURL)
		// Durations are sent as integer seconds — the runtime parser accepts "5m",
		// but the dry-run schema validator expects an integer, so normalize here.
		for _, d := range []struct {
			key, val string
		}{
			{"assertion_ttl", cfgAssertionTTL},
			{"key_rotation_period", cfgKeyRotationPeriod},
			{"jwks_cache_ttl", cfgJWKSCacheTTL},
			{"retired_key_grace", cfgRetiredKeyGrace},
		} {
			if d.val == "" {
				continue
			}
			secs, err := durationToSeconds(d.val)
			if err != nil {
				return fmt.Errorf("-%s: %w", strings.ReplaceAll(d.key, "_", "-"), err)
			}
			payload[d.key] = secs
		}
	}

	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "POST", oidcIssuerConfigPath, payload)
	}

	resource, err := c.Operator().Write(oidcIssuerConfigPath, payload)
	if err != nil {
		return fmt.Errorf("error configuring OIDC issuer: %w", err)
	}

	data := map[string]any{}
	var resData map[string]any
	if resource != nil {
		resData = resource.Data
	}
	helpers.MergeServerResponseInto(data, resData, map[string]any{"enabled": true})
	return helpers.RenderMap(data, func() {
		fmt.Println("Success! OIDC issuer configured.")
		helpers.PrintMapAsTable(data)
	})
}

func setIfNonEmpty(m map[string]any, key, value string) {
	if value != "" {
		m[key] = value
	}
}

// durationToSeconds parses a Go duration ("5m", "24h") or a bare number of
// seconds into an integer number of seconds.
func durationToSeconds(s string) (int, error) {
	s = strings.TrimSpace(s)
	if d, err := time.ParseDuration(s); err == nil {
		return int(d.Seconds()), nil
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n, nil
	}
	return 0, fmt.Errorf("invalid duration %q (use e.g. 5m, 24h, or a number of seconds)", s)
}
