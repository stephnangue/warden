package cert

import (
	"context"
	"fmt"
	"net/http"

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
	canonical := td.Name()

	bundlePEM, _ := d.Get("bundle_pem").(string)
	bundleJSON, _ := d.Get("bundle_json").(string)

	// Validate the bundle parses into at least one X.509 authority before storing.
	if _, err := parseTrustDomainAuthorities(td, bundlePEM, bundleJSON); err != nil {
		return &logical.Response{StatusCode: http.StatusBadRequest, Err: err}, nil
	}

	if err := b.setTrustDomain(ctx, &SPIFFETrustDomain{Name: canonical, BundlePEM: bundlePEM, BundleJSON: bundleJSON}); err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}

	// Refresh the in-memory verification set so the change takes effect at once.
	if err := b.rebuildBundleSet(ctx); err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}

	return &logical.Response{
		StatusCode: http.StatusOK,
		Data:       map[string]any{"name": canonical, "message": fmt.Sprintf("Successfully configured trust domain %s", canonical)},
	}, nil
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
	source := "bundle_pem"
	if entry.BundleJSON != "" {
		source = "bundle_json"
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

	return &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"name":                    entry.Name,
			"bundle_source":           source,
			"x509_authority_count":    count,
			"x509_authority_subjects": subjects,
		},
	}, nil
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
