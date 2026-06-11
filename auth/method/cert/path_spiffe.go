package cert

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// spiffeTrustDomainPrefix is the internal storage-key prefix for trust-domain
// entries (namespaced away from role/ and config). It is independent of the
// API route, which is "trust-domain/<name>".
const spiffeTrustDomainPrefix = "spiffe/trust-domain/"

// pathSPIFFETrustDomain manages a SPIFFE trust domain and the X.509 authorities
// that are authoritative for it. These paths are only meaningful in spiffe mode.
func (b *certAuthBackend) pathSPIFFETrustDomain() *framework.Path {
	return &framework.Path{
		Pattern: "trust-domain/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "SPIFFE trust domain name (e.g. prod.example.org)",
				Required:    true,
			},
			"bundle_pem": {
				Type:        framework.TypeString,
				Description: "PEM-encoded X.509 authorities (CA certificates) for the trust domain",
			},
			"bundle_json": {
				Type:        framework.TypeString,
				Description: "SPIFFE trust-bundle (JWKS) document; only its X.509 authorities are used",
			},
			"bundle_endpoint_url": {
				Type:        framework.TypeString,
				Description: "SPIFFE Federation bundle endpoint URL (https://). Setting this makes the trust domain federated.",
			},
			"bundle_endpoint_profile": {
				Type:          framework.TypeString,
				Description:   "Bundle endpoint profile: https_web (Web PKI) or https_spiffe (endpoint authenticated by its SVID).",
				AllowedValues: []interface{}{bundleProfileWeb, bundleProfileSPIFFE},
			},
			"endpoint_spiffe_id": {
				Type:        framework.TypeString,
				Description: "Expected SPIFFE ID of the bundle endpoint (required for https_spiffe; must be in this trust domain).",
			},
			"web_pki_ca_pem": {
				Type:        framework.TypeString,
				Description: "Optional PEM CA roots for validating the https_web endpoint's TLS cert (default: system roots).",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.handleTrustDomainWrite, Summary: "Register a SPIFFE trust domain bundle"},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleTrustDomainWrite, Summary: "Update a SPIFFE trust domain bundle"},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.handleTrustDomainRead, Summary: "Read a SPIFFE trust domain"},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.handleTrustDomainDelete, Summary: "Delete a SPIFFE trust domain"},
		},
		HelpSynopsis:    "Manage SPIFFE trust domains and their X.509 bundles",
		HelpDescription: "Register the X.509 authorities authoritative for a SPIFFE trust domain. Only available when the mount is configured with mode=spiffe.",
	}
}

// pathSPIFFETrustDomainList lists the configured SPIFFE trust domains.
func (b *certAuthBackend) pathSPIFFETrustDomainList() *framework.Path {
	return &framework.Path{
		Pattern: "trust-domain/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.handleTrustDomainList, Summary: "List SPIFFE trust domains"},
		},
		HelpSynopsis:    "List SPIFFE trust domains",
		HelpDescription: "List the configured SPIFFE trust domains. Only available when the mount is configured with mode=spiffe.",
	}
}

// pathSPIFFETrustDomainRefresh triggers an immediate bundle fetch for a federated
// trust domain.
func (b *certAuthBackend) pathSPIFFETrustDomainRefresh() *framework.Path {
	return &framework.Path{
		Pattern: "trust-domain/" + framework.GenericNameRegex("name") + "/refresh",
		Fields: map[string]*framework.FieldSchema{
			"name": {Type: framework.TypeString, Description: "SPIFFE trust domain name", Required: true},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleTrustDomainRefresh, Summary: "Fetch and apply a federated trust domain's bundle now"},
		},
		HelpSynopsis:    "Refresh a federated SPIFFE trust domain's bundle",
		HelpDescription: "Fetches the bundle from the trust domain's configured endpoint and applies it. Only valid in spiffe mode for a federated trust domain.",
	}
}

func (b *certAuthBackend) handleTrustDomainRefresh(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if resp := b.requireSPIFFEMode(); resp != nil {
		return resp, nil
	}
	name := d.Get("name").(string)
	if td, err := spiffeid.TrustDomainFromString(name); err == nil {
		name = td.Name()
	}

	entry, err := b.getTrustDomain(ctx, name)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}
	if entry == nil {
		return logical.ErrorResponse(logical.ErrNotFoundf("trust domain %q not found", name)), nil
	}
	if !entry.IsFederated() {
		return &logical.Response{StatusCode: http.StatusBadRequest, Err: fmt.Errorf("trust domain %q has no bundle endpoint configured", name)}, nil
	}

	changed, err := b.refreshFederatedTrustDomain(ctx, entry)
	if err != nil {
		// 502: the upstream bundle endpoint fetch failed; the last-good bundle is kept.
		return &logical.Response{StatusCode: http.StatusBadGateway, Err: fmt.Errorf("bundle refresh failed: %w", err)}, nil
	}

	return &logical.Response{
		StatusCode: http.StatusOK,
		Data:       map[string]any{"name": name, "changed": changed, "sequence": entry.Sequence},
	}, nil
}

// requireSPIFFEMode returns a 400 response when the mount is not in spiffe mode.
func (b *certAuthBackend) requireSPIFFEMode() *logical.Response {
	if b.mountMode() != modeSPIFFE {
		return &logical.Response{
			StatusCode: http.StatusBadRequest,
			Err:        fmt.Errorf("trust domains are only available when the mount is configured with mode=spiffe"),
		}
	}
	return nil
}

func (b *certAuthBackend) handleTrustDomainWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if resp := b.requireSPIFFEMode(); resp != nil {
		return resp, nil
	}
	name := d.Get("name").(string)
	td, err := spiffeid.TrustDomainFromString(name)
	if err != nil {
		return &logical.Response{StatusCode: http.StatusBadRequest, Err: fmt.Errorf("invalid trust domain %q: %w", name, err)}, nil
	}

	// A config write replaces the entry; any fetched federation state resets so the
	// next refresh fetches against the new config.
	entry := &SPIFFETrustDomain{
		Name:                  td.Name(),
		BundlePEM:             d.Get("bundle_pem").(string),
		BundleJSON:            d.Get("bundle_json").(string),
		BundleEndpointURL:     d.Get("bundle_endpoint_url").(string),
		BundleEndpointProfile: d.Get("bundle_endpoint_profile").(string),
		EndpointSPIFFEID:      d.Get("endpoint_spiffe_id").(string),
		WebPKICAPEM:           d.Get("web_pki_ca_pem").(string),
	}

	if err := validateTrustDomainConfig(entry); err != nil {
		return &logical.Response{StatusCode: http.StatusBadRequest, Err: err}, nil
	}

	if err := b.setTrustDomain(ctx, entry); err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}
	// Refresh the in-memory verification set so the change takes effect at once.
	if err := b.rebuildBundleSet(ctx); err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}

	return &logical.Response{
		StatusCode: http.StatusOK,
		Data:       map[string]any{"name": entry.Name, "federated": entry.IsFederated(), "message": fmt.Sprintf("Successfully configured trust domain %s", entry.Name)},
	}, nil
}

// validateTrustDomainConfig validates a trust-domain entry: a static domain needs
// a bundle; a federated domain needs a valid https endpoint and the profile's
// requirements (https_spiffe: a valid in-domain endpoint_spiffe_id + a bootstrap
// bundle; https_web: no endpoint_spiffe_id, optional custom roots).
func validateTrustDomainConfig(d *SPIFFETrustDomain) error {
	td, err := spiffeid.TrustDomainFromString(d.Name)
	if err != nil {
		return fmt.Errorf("invalid trust domain %q: %w", d.Name, err)
	}
	hasBundle := d.BundlePEM != "" || d.BundleJSON != ""

	switch d.BundleEndpointProfile {
	case "": // static
		if d.BundleEndpointURL != "" || d.EndpointSPIFFEID != "" || d.WebPKICAPEM != "" {
			return fmt.Errorf("bundle_endpoint_url/endpoint_spiffe_id/web_pki_ca_pem require bundle_endpoint_profile")
		}
		if _, err := parseTrustDomainAuthorities(td, d.BundlePEM, d.BundleJSON); err != nil {
			return err
		}

	case bundleProfileWeb:
		if err := validateHTTPSURL(d.BundleEndpointURL); err != nil {
			return err
		}
		if d.EndpointSPIFFEID != "" {
			return fmt.Errorf("endpoint_spiffe_id is not valid for the https_web profile")
		}
		if _, err := rootsFromPEM(d.WebPKICAPEM); err != nil {
			return err
		}
		if hasBundle { // optional bootstrap; if present it must parse
			if _, err := parseTrustDomainAuthorities(td, d.BundlePEM, d.BundleJSON); err != nil {
				return err
			}
		}

	case bundleProfileSPIFFE:
		if err := validateHTTPSURL(d.BundleEndpointURL); err != nil {
			return err
		}
		if d.WebPKICAPEM != "" {
			return fmt.Errorf("web_pki_ca_pem is not valid for the https_spiffe profile")
		}
		endpointID, err := spiffeid.FromString(d.EndpointSPIFFEID)
		if err != nil {
			return fmt.Errorf("https_spiffe requires a valid endpoint_spiffe_id: %w", err)
		}
		if !endpointID.MemberOf(td) {
			return fmt.Errorf("endpoint_spiffe_id %q must be in trust domain %q", d.EndpointSPIFFEID, td.Name())
		}
		if _, err := parseTrustDomainAuthorities(td, d.BundlePEM, d.BundleJSON); err != nil {
			return fmt.Errorf("https_spiffe requires a bootstrap bundle (bundle_pem or bundle_json) to authenticate the endpoint: %w", err)
		}

	default:
		return fmt.Errorf("invalid bundle_endpoint_profile %q; must be %s or %s", d.BundleEndpointProfile, bundleProfileWeb, bundleProfileSPIFFE)
	}
	return nil
}

func validateHTTPSURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("bundle_endpoint_url is required for a federated trust domain")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid bundle_endpoint_url: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("bundle_endpoint_url must be an https:// URL")
	}
	return nil
}

func (b *certAuthBackend) handleTrustDomainRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if resp := b.requireSPIFFEMode(); resp != nil {
		return resp, nil
	}
	name := d.Get("name").(string)
	if td, err := spiffeid.TrustDomainFromString(name); err == nil {
		name = td.Name()
	}

	entry, err := b.getTrustDomain(ctx, name)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}
	if entry == nil {
		return logical.ErrorResponse(logical.ErrNotFoundf("trust domain %q not found", name)), nil
	}

	// Trust bundles are public CA material, but the read returns a summary
	// (count + subjects) rather than the raw bytes, matching the config-read style.
	source := "none"
	switch {
	case entry.BundleJSON != "":
		source = "bundle_json"
	case entry.BundlePEM != "":
		source = "bundle_pem"
	}
	subjects := []string{}
	count := 0
	if td, err := spiffeid.TrustDomainFromString(entry.Name); err == nil {
		if authorities, err := parseTrustDomainAuthorities(td, entry.BundlePEM, entry.BundleJSON); err == nil {
			count = len(authorities)
			for _, a := range authorities {
				subjects = append(subjects, a.Subject.String())
			}
		}
	}

	data := map[string]any{
		"name":                    entry.Name,
		"federated":               entry.IsFederated(),
		"bundle_source":           source,
		"x509_authority_count":    count,
		"x509_authority_subjects": subjects,
	}
	if entry.IsFederated() {
		data["bundle_endpoint_url"] = entry.BundleEndpointURL
		data["bundle_endpoint_profile"] = entry.BundleEndpointProfile
		data["endpoint_spiffe_id"] = entry.EndpointSPIFFEID
		data["sequence"] = entry.Sequence
		data["last_error"] = entry.LastError
		data["last_refresh"] = ""
		if entry.LastRefreshUnix != 0 {
			data["last_refresh"] = time.Unix(entry.LastRefreshUnix, 0).UTC().Format(time.RFC3339)
		}
	}

	return &logical.Response{StatusCode: http.StatusOK, Data: data}, nil
}

func (b *certAuthBackend) handleTrustDomainDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if resp := b.requireSPIFFEMode(); resp != nil {
		return resp, nil
	}
	name := d.Get("name").(string)
	if td, err := spiffeid.TrustDomainFromString(name); err == nil {
		name = td.Name()
	}

	if err := b.deleteTrustDomain(ctx, name); err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}
	if err := b.rebuildBundleSet(ctx); err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}
	return &logical.Response{StatusCode: http.StatusOK, Data: map[string]any{"message": fmt.Sprintf("Successfully deleted trust domain %s", name)}}, nil
}

func (b *certAuthBackend) handleTrustDomainList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if resp := b.requireSPIFFEMode(); resp != nil {
		return resp, nil
	}
	names, err := b.listTrustDomains(ctx)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}
	return &logical.Response{StatusCode: http.StatusOK, Data: map[string]any{"keys": names}}, nil
}

// --- storage + bundle-set helpers ---

func (b *certAuthBackend) getTrustDomain(ctx context.Context, name string) (*SPIFFETrustDomain, error) {
	entry, err := b.storageView.Get(ctx, spiffeTrustDomainPrefix+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var td SPIFFETrustDomain
	if err := entry.DecodeJSON(&td); err != nil {
		return nil, err
	}
	return &td, nil
}

func (b *certAuthBackend) setTrustDomain(ctx context.Context, td *SPIFFETrustDomain) error {
	entry, err := sdklogical.StorageEntryJSON(spiffeTrustDomainPrefix+td.Name, td)
	if err != nil {
		return err
	}
	return b.storageView.Put(ctx, entry)
}

func (b *certAuthBackend) deleteTrustDomain(ctx context.Context, name string) error {
	return b.storageView.Delete(ctx, spiffeTrustDomainPrefix+name)
}

func (b *certAuthBackend) listTrustDomains(ctx context.Context) ([]string, error) {
	return b.storageView.List(ctx, spiffeTrustDomainPrefix)
}

func (b *certAuthBackend) listTrustDomainEntries(ctx context.Context) ([]*SPIFFETrustDomain, error) {
	names, err := b.listTrustDomains(ctx)
	if err != nil {
		return nil, err
	}
	entries := make([]*SPIFFETrustDomain, 0, len(names))
	for _, name := range names {
		td, err := b.getTrustDomain(ctx, name)
		if err != nil {
			return nil, err
		}
		if td != nil {
			entries = append(entries, td)
		}
	}
	return entries, nil
}

// rebuildBundleSet loads every configured trust-domain bundle from storage and
// atomically replaces the in-memory verification set.
func (b *certAuthBackend) rebuildBundleSet(ctx context.Context) error {
	entries, err := b.listTrustDomainEntries(ctx)
	if err != nil {
		return err
	}
	set, err := buildBundleSet(entries)
	if err != nil {
		return err
	}
	b.spiffeMu.Lock()
	b.spiffeBundleSet = set
	b.spiffeMu.Unlock()
	return nil
}

// snapshotBundleSet returns the current verification set under a read lock. It
// may be nil if no trust domains have been loaded yet (callers fail closed).
func (b *certAuthBackend) snapshotBundleSet() *x509bundle.Set {
	b.spiffeMu.RLock()
	defer b.spiffeMu.RUnlock()
	return b.spiffeBundleSet
}
