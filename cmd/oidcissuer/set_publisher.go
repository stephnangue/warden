package oidcissuer

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	pubType           string
	pubConfig         map[string]string
	pubRotationPeriod string
	pubJSON           string

	SetPublisherCmd = &cobra.Command{
		Use:           "set-publisher",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Configure the OIDC issuer's discovery/JWKS publisher",
		Long: `
Usage: warden oidc-issuer set-publisher -type=<type> [-config=key=value ...]

  Configure the publisher that pushes the discovery + JWKS documents to a
  bucket/CDN. This never changes whether the issuer is enabled; it only sets the
  publisher. Root namespace only.

  The publisher type is selected with -type; every other field is passed as a
  repeatable -config=key=value pair, so new publisher fields need no new flags.
  Config keys are the type's field names, validated server-side per type. A
  value prefixed with '@' is read from a file (handy for secrets):
  -config=client_secret=@/run/secrets/sp.

  A write is a PARTIAL update over the stored publisher: unset keys keep their
  value, switching -type drops the previous type's fields, and secrets are
  preserved when omitted (or sent masked). Set -type=none to remove the
  publisher and serve the documents only from Warden's own endpoint.

  Publisher types and their config keys:

      local_file   dir
      http_put     base_url, auth_header, auth_value
      s3           bucket, region, access_key_id, secret_access_key, prefix, endpoint
      azure_blob   account_name, container, tenant_id, client_id, client_secret,
                   secret_id, prefix, endpoint
      gcs          bucket, credentials_json, prefix, endpoint
      none         (removes the publisher)

  Automatic credential rotation (gcs, s3, azure_blob) is enabled with
  -rotation-period: on that cadence Warden mints a fresh write credential, verifies
  it, swaps it in, and deletes the old one. gcs needs
  iam.serviceAccountKeys.create/delete on its own service account; s3 needs
  iam:CreateAccessKey/DeleteAccessKey/ListAccessKeys on its own IAM user (a permanent
  AKIA… key, not temporary STS credentials); azure_blob authenticates with a service
  principal (Entra ID) that has Storage Blob Data Contributor on the container and
  Graph rights to manage its own app registration, and rotation regenerates that SP's
  client_secret. Set -rotation-period=0 to disable.

  The s3 endpoint key targets an S3-compatible object store (MinIO, Cloudflare R2,
  …). Rotation always uses AWS IAM, so -rotation-period applies to real-AWS keys
  only — leave it unset when publishing to a non-AWS store.

  S3:

      $ warden oidc-issuer set-publisher -type=s3 \
          -config=bucket=my-jwks -config=region=us-east-1 \
          -config=access_key_id=AKIA... \
          -config=secret_access_key=@/run/secrets/s3

  Azure Blob (service-principal auth, with automatic secret rotation every 30 days):

      $ warden oidc-issuer set-publisher -type=azure_blob -rotation-period=720h \
          -config=account_name=wardenoidc -config=container=jwks \
          -config=tenant_id=<tenant> -config=client_id=<app-id> \
          -config=client_secret=@/run/secrets/sp -config=secret_id=<keyId>

  Google Cloud Storage (with automatic key rotation every 30 days):

      $ warden oidc-issuer set-publisher -type=gcs -rotation-period=720h \
          -config=bucket=my-jwks \
          -config=credentials_json=@/run/secrets/sa.json

  Remove the publisher:

      $ warden oidc-issuer set-publisher -type=none

  Full JSON payload (agent-friendly):

      $ warden oidc-issuer set-publisher -json @publisher.json
      $ cat publisher.json | warden oidc-issuer set-publisher -json -

  -json is mutually exclusive with -type/-config. Combine any mode with
  -dry-run to validate the payload against the server schema without writing.
`,
		Args: cobra.NoArgs,
		RunE: runSetPublisher,
	}
)

func init() {
	f := SetPublisherCmd.Flags()
	f.StringVar(&pubType, "type", "", "Publisher type: none, local_file, http_put, s3, azure_blob, or gcs")
	f.StringToStringVar(&pubConfig, "config", nil, "Type-specific config (key=value; repeatable). Use @file to read a value from a file, e.g. -config=client_secret=@/run/secrets/sp")
	f.StringVar(&pubRotationPeriod, "rotation-period", "", "Automatic credential-rotation cadence for the publisher's write key (gcs, s3, azure_blob). A Go duration like 720h; 0 disables. Empty leaves it unchanged.")
	f.StringVarP(&pubJSON, "json", "j", "", "Full publisher JSON block — '<json>', '@file.json', or '-' for stdin (mutually exclusive with -type/-config)")
}

func runSetPublisher(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	jsonPayload, err := helpers.ResolveJSONInput(pubJSON)
	if err != nil {
		return err
	}

	var publisher map[string]any
	if jsonPayload != nil {
		if err := helpers.RejectFlagsWithJSON(true, map[string]bool{
			"-type":            pubType != "",
			"-config":          len(pubConfig) > 0,
			"-rotation-period": pubRotationPeriod != "",
		}); err != nil {
			return err
		}
		// -json here is the publisher block only (e.g. {"type":"s3",...}), not
		// the full issuer config that 'configure -json' takes. Catch a mistakenly
		// reused config document up front — otherwise it would be silently nested
		// under "publisher" and rejected server-side with a cryptic per-field error.
		for _, k := range []string{"enabled", "issuer_url", "assertion_ttl", "key_rotation_period", "jwks_cache_ttl", "retired_key_grace", "publisher"} {
			if _, ok := jsonPayload[k]; ok {
				return fmt.Errorf("-json expects the publisher block only (e.g. {\"type\":\"s3\",...}), but got issuer-level field %q; use 'warden oidc-issuer configure -json' for the full config: %w", k, helpers.ErrUsage)
			}
		}
		publisher = jsonPayload
	} else {
		if pubType == "" {
			return fmt.Errorf("-type is required (or use -json): %w", helpers.ErrUsage)
		}
		resolved, err := helpers.ResolveFileRefs(pubConfig)
		if err != nil {
			return err
		}
		publisher = map[string]any{"type": pubType}
		for k, v := range resolved {
			publisher[k] = v
		}
		// rotation_period is a publisher field surfaced as a typed flag; fold it into
		// the same payload so the server validates and merges it per type.
		if pubRotationPeriod != "" {
			publisher["rotation_period"] = pubRotationPeriod
		}
	}

	// No "enabled" key: this only merges the publisher, leaving the issuer's
	// on/off state untouched. The server field-merges the publisher over the
	// stored config and validates it per type before persisting.
	payload := map[string]any{"publisher": publisher}

	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "POST", oidcIssuerConfigPath, payload)
	}

	resource, err := c.Operator().Write(oidcIssuerConfigPath, payload)
	if err != nil {
		return fmt.Errorf("error configuring OIDC issuer publisher: %w", err)
	}

	// The write response echoes only the issuer state (enabled/issuer_url/ready),
	// not the publisher. Read back so the confirmation reflects the merged,
	// server-masked publisher — the point of this command. Fall back to the write
	// response if the read fails, so success is still reported.
	data := map[string]any{}
	if read, rerr := c.Operator().Read(oidcIssuerConfigPath); rerr == nil && read != nil && read.Data != nil {
		data = read.Data
	} else if resource != nil {
		data = resource.Data
	}
	return helpers.RenderMap(data, func() {
		fmt.Println("Success! OIDC issuer publisher configured.")
		printOIDCIssuerTable(data)
	})
}
