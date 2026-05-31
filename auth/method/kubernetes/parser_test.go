package kubernetes

import (
	"testing"
	"time"
)

func TestMapToKubernetesAuthConfig_TokenTTLNormalization(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want time.Duration
	}{
		{"string", "30m", 30 * time.Minute},
		{"int seconds (TypeDurationSecond)", 1800, 1800 * time.Second},
		{"float64 (JSON decode)", float64(900), 900 * time.Second},
		{"time.Duration passthrough", 2 * time.Hour, 2 * time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := mapToKubernetesAuthConfig(map[string]any{
				"kubernetes_host":    "https://kube",
				"kubernetes_ca_cert": "PEM",
				"token_ttl":          tc.in,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.TokenTTL != tc.want {
				t.Fatalf("token_ttl: got %v, want %v", cfg.TokenTTL, tc.want)
			}
		})
	}
}

func TestMapToKubernetesAuthConfig_DefaultTokenTTL(t *testing.T) {
	cfg, err := mapToKubernetesAuthConfig(map[string]any{
		"kubernetes_host": "https://kube",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TokenTTL != time.Hour {
		t.Fatalf("expected default 1h, got %v", cfg.TokenTTL)
	}
}

func TestMapToKubernetesAuthConfig_AllFieldsRoundTrip(t *testing.T) {
	in := map[string]any{
		"kubernetes_host":        "https://kube.example.com",
		"kubernetes_ca_cert":     "-----BEGIN CERTIFICATE-----...",
		"token_reviewer_jwt":     "eyJ.reviewer.jwt",
		"tls_skip_verify":        true,
		"issuer":                 "https://kubernetes.default.svc",
		"disable_iss_validation": false,
		"token_ttl":              "45m",
		"default_role":           "ops-reader",
	}
	cfg, err := mapToKubernetesAuthConfig(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.KubernetesHost != in["kubernetes_host"] {
		t.Errorf("kubernetes_host: %q", cfg.KubernetesHost)
	}
	if cfg.KubernetesCACert != in["kubernetes_ca_cert"] {
		t.Errorf("kubernetes_ca_cert: %q", cfg.KubernetesCACert)
	}
	if cfg.TokenReviewerJWT != in["token_reviewer_jwt"] {
		t.Errorf("token_reviewer_jwt: %q", cfg.TokenReviewerJWT)
	}
	if !cfg.TLSSkipVerify {
		t.Error("tls_skip_verify should be true")
	}
	if cfg.Issuer != in["issuer"] {
		t.Errorf("issuer: %q", cfg.Issuer)
	}
	if cfg.DisableIssValidation {
		t.Error("disable_iss_validation should be false")
	}
	if cfg.TokenTTL != 45*time.Minute {
		t.Errorf("token_ttl: %v", cfg.TokenTTL)
	}
	if cfg.DefaultRole != in["default_role"] {
		t.Errorf("default_role: %q", cfg.DefaultRole)
	}
}
