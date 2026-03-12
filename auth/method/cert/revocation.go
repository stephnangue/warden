package cert

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

// revocationChecker handles CRL and OCSP certificate revocation checks.
type revocationChecker struct {
	crlCache    sync.Map // URL → *crlEntry
	crlCacheTTL time.Duration
	ocspTimeout time.Duration
	crlTimeout  time.Duration
	httpClient  *http.Client
}

type crlEntry struct {
	crl       *x509.RevocationList
	fetchedAt time.Time
}

func newRevocationChecker(crlCacheTTL, ocspTimeout time.Duration) *revocationChecker {
	// CRL downloads can be large (up to 10MB); use a longer timeout than OCSP.
	crlTimeout := 3 * ocspTimeout
	if crlTimeout < 15*time.Second {
		crlTimeout = 15 * time.Second
	}

	return &revocationChecker{
		crlCacheTTL: crlCacheTTL,
		ocspTimeout: ocspTimeout,
		crlTimeout:  crlTimeout,
		httpClient: &http.Client{
			Timeout: ocspTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Do not follow redirects
			},
		},
	}
}

// checkRevocation verifies the certificate has not been revoked.
// mode: "crl", "ocsp", or "best_effort".
// verifiedChains comes from cert.Verify() — the first chain is used to find the issuer.
func (rc *revocationChecker) checkRevocation(cert *x509.Certificate, verifiedChains [][]*x509.Certificate, mode string) error {
	// Find the issuer certificate from the verified chain
	var issuer *x509.Certificate
	if len(verifiedChains) > 0 && len(verifiedChains[0]) > 1 {
		issuer = verifiedChains[0][1]
	}

	// Try OCSP first (faster, more current), then CRL
	ocspErr := rc.checkOCSP(cert, issuer)
	if ocspErr == nil {
		return nil // OCSP says good
	}
	if isRevoked(ocspErr) {
		return ocspErr // Definitively revoked
	}

	// OCSP inconclusive — try CRL
	crlErr := rc.checkCRL(cert, issuer)
	if crlErr == nil {
		return nil // CRL says not revoked
	}
	if isRevoked(crlErr) {
		return crlErr // Definitively revoked
	}

	// Both checks inconclusive
	if mode == "best_effort" {
		return nil // Allow on best_effort
	}
	// Strict mode — fail if we can't verify
	if ocspErr != nil {
		return fmt.Errorf("revocation check failed: %w", ocspErr)
	}
	return fmt.Errorf("revocation check failed: %w", crlErr)
}

// errRevoked is a sentinel error indicating a certificate has been revoked.
var errRevoked = fmt.Errorf("certificate has been revoked")

func isRevoked(err error) bool {
	return errors.Is(err, errRevoked)
}

// checkOCSP queries the OCSP responder for the certificate's revocation status.
func (rc *revocationChecker) checkOCSP(cert *x509.Certificate, issuer *x509.Certificate) error {
	if len(cert.OCSPServer) == 0 {
		return fmt.Errorf("no OCSP responder URL in certificate")
	}
	if issuer == nil {
		return fmt.Errorf("issuer certificate not available for OCSP")
	}

	ocspReq, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return fmt.Errorf("failed to create OCSP request: %w", err)
	}

	for _, responderURL := range cert.OCSPServer {
		resp, err := rc.httpClient.Post(responderURL, "application/ocsp-request", bytes.NewReader(ocspReq))
		if err != nil {
			continue // Try next responder
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
		resp.Body.Close()
		if err != nil {
			continue
		}

		ocspResp, err := ocsp.ParseResponseForCert(body, cert, issuer)
		if err != nil {
			continue
		}

		switch ocspResp.Status {
		case ocsp.Good:
			return nil
		case ocsp.Revoked:
			return errRevoked
		default:
			continue // Unknown or other status — try next
		}
	}

	return fmt.Errorf("no OCSP responder returned a definitive answer")
}

// checkCRL downloads and checks the CRL distribution points.
// The issuer is required to verify the CRL signature.
func (rc *revocationChecker) checkCRL(cert *x509.Certificate, issuer *x509.Certificate) error {
	if len(cert.CRLDistributionPoints) == 0 {
		return fmt.Errorf("no CRL distribution points in certificate")
	}

	for _, crlURL := range cert.CRLDistributionPoints {
		crl, err := rc.fetchCRL(crlURL, issuer)
		if err != nil {
			continue // Try next distribution point
		}

		for _, revoked := range crl.RevokedCertificateEntries {
			if revoked.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return errRevoked
			}
		}
		// Found a valid CRL that doesn't list this cert — it's good
		return nil
	}

	return fmt.Errorf("no CRL distribution point returned a usable CRL")
}

// fetchCRL retrieves a CRL from the given URL, using cached data when available.
// The issuer is required to verify the CRL signature; unsigned/forged CRLs are rejected.
func (rc *revocationChecker) fetchCRL(crlURL string, issuer *x509.Certificate) (*x509.RevocationList, error) {
	// Check cache
	if cached, ok := rc.crlCache.Load(crlURL); ok {
		entry := cached.(*crlEntry)
		if time.Since(entry.fetchedAt) < rc.crlCacheTTL {
			return entry.crl, nil
		}
	}

	// Issuer is required to verify the CRL signature — fail-closed.
	if issuer == nil {
		return nil, fmt.Errorf("cannot verify CRL signature: issuer certificate not available")
	}

	// Use a separate timeout for CRL downloads (larger payloads than OCSP).
	ctx, cancel := context.WithTimeout(context.Background(), rc.crlTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, crlURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create CRL request: %w", err)
	}

	resp, err := rc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CRL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CRL endpoint returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10MB limit
	if err != nil {
		return nil, fmt.Errorf("failed to read CRL response: %w", err)
	}

	crl, err := x509.ParseRevocationList(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRL: %w", err)
	}

	// Verify the CRL was signed by the issuer to prevent forged CRLs
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return nil, fmt.Errorf("CRL signature verification failed: %w", err)
	}

	rc.crlCache.Store(crlURL, &crlEntry{
		crl:       crl,
		fetchedAt: time.Now(),
	})

	return crl, nil
}
