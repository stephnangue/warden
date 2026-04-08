package drivers

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/stephnangue/warden/credential"
)

// BuildHTTPClient creates an *http.Client with optional TLS configuration.
// It reads "ca_data" and "tls_skip_verify" from the config map.
// If neither is set, returns a plain client with the given timeout.
func BuildHTTPClient(config map[string]string, timeout time.Duration) (*http.Client, error) {
	caData := credential.GetString(config, "ca_data", "")
	skipVerify := credential.GetBool(config, "tls_skip_verify", false)

	if caData == "" && !skipVerify {
		return &http.Client{Timeout: timeout}, nil
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if skipVerify {
		tlsConfig.InsecureSkipVerify = true
	}

	if caData != "" {
		pemBytes, err := base64.StdEncoding.DecodeString(caData)
		if err != nil {
			return nil, fmt.Errorf("ca_data is not valid base64: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("ca_data contains no valid PEM certificates")
		}
		tlsConfig.RootCAs = pool
	}

	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}

// ValidateCAData validates that a ca_data value is valid base64-encoded PEM.
// Intended for use as a credential.StringField().Custom() validator.
func ValidateCAData(v string) error {
	if v == "" {
		return nil
	}
	pemBytes, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return fmt.Errorf("ca_data is not valid base64: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return fmt.Errorf("ca_data contains no valid PEM certificates")
	}
	return nil
}
