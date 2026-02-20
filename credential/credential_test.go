package credential

import (
	"testing"
	"time"
)

// TestCredential_IsExpired tests credential expiration logic
func TestCredential_IsExpired(t *testing.T) {
	tests := []struct {
		name     string
		leaseTTL time.Duration
		issuedAt time.Time
		expected bool
	}{
		{
			name:     "static credential (zero TTL)",
			leaseTTL: 0,
			issuedAt: time.Now(),
			expected: false,
		},
		{
			name:     "fresh credential",
			leaseTTL: time.Hour,
			issuedAt: time.Now(),
			expected: false,
		},
		{
			name:     "expired credential",
			leaseTTL: time.Hour,
			issuedAt: time.Now().Add(-2 * time.Hour),
			expected: true,
		},
		{
			name:     "just expired credential",
			leaseTTL: time.Minute,
			issuedAt: time.Now().Add(-61 * time.Second),
			expected: true,
		},
		{
			name:     "about to expire",
			leaseTTL: time.Minute,
			issuedAt: time.Now().Add(-59 * time.Second),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred := &Credential{
				LeaseTTL: tt.leaseTTL,
				IssuedAt: tt.issuedAt,
			}

			result := cred.IsExpired()
			if result != tt.expected {
				t.Errorf("expected IsExpired() = %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestCredential_RemainingTTL tests remaining TTL calculation
func TestCredential_RemainingTTL(t *testing.T) {
	tests := []struct {
		name     string
		leaseTTL time.Duration
		issuedAt time.Time
		minTTL   time.Duration // minimum expected remaining TTL
		maxTTL   time.Duration // maximum expected remaining TTL
	}{
		{
			name:     "static credential",
			leaseTTL: 0,
			issuedAt: time.Now(),
			minTTL:   0,
			maxTTL:   0,
		},
		{
			name:     "fresh credential",
			leaseTTL: time.Hour,
			issuedAt: time.Now(),
			minTTL:   59 * time.Minute,
			maxTTL:   time.Hour,
		},
		{
			name:     "half expired",
			leaseTTL: time.Hour,
			issuedAt: time.Now().Add(-30 * time.Minute),
			minTTL:   29 * time.Minute,
			maxTTL:   31 * time.Minute,
		},
		{
			name:     "expired credential",
			leaseTTL: time.Hour,
			issuedAt: time.Now().Add(-2 * time.Hour),
			minTTL:   0,
			maxTTL:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred := &Credential{
				LeaseTTL: tt.leaseTTL,
				IssuedAt: tt.issuedAt,
			}

			remaining := cred.RemainingTTL()
			if remaining < tt.minTTL || remaining > tt.maxTTL {
				t.Errorf("expected remaining TTL between %v and %v, got %v",
					tt.minTTL, tt.maxTTL, remaining)
			}
		})
	}
}

// TestCredential_ShouldRotate tests rotation threshold logic
func TestCredential_ShouldRotate(t *testing.T) {
	tests := []struct {
		name       string
		leaseTTL   time.Duration
		issuedAt   time.Time
		revocable  bool
		threshold  float64
		shouldRotate bool
	}{
		{
			name:         "static credential",
			leaseTTL:     0,
			issuedAt:     time.Now(),
			revocable:    true,
			threshold:    0.2,
			shouldRotate: false,
		},
		{
			name:         "non-revocable credential",
			leaseTTL:     time.Hour,
			issuedAt:     time.Now().Add(-50 * time.Minute),
			revocable:    false,
			threshold:    0.2,
			shouldRotate: false,
		},
		{
			name:         "above threshold (80% remaining)",
			leaseTTL:     time.Hour,
			issuedAt:     time.Now().Add(-12 * time.Minute),
			revocable:    true,
			threshold:    0.2, // 20% threshold
			shouldRotate: false,
		},
		{
			name:         "below threshold (10% remaining)",
			leaseTTL:     time.Hour,
			issuedAt:     time.Now().Add(-54 * time.Minute),
			revocable:    true,
			threshold:    0.2, // 20% threshold
			shouldRotate: true,
		},
		{
			name:         "at threshold (20% remaining)",
			leaseTTL:     time.Hour,
			issuedAt:     time.Now().Add(-48 * time.Minute),
			revocable:    true,
			threshold:    0.2, // 20% threshold
			shouldRotate: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred := &Credential{
				LeaseTTL:  tt.leaseTTL,
				IssuedAt:  tt.issuedAt,
				Revocable: tt.revocable,
			}

			result := cred.ShouldRotate(tt.threshold)
			if result != tt.shouldRotate {
				t.Errorf("expected ShouldRotate(%v) = %v, got %v (remaining: %v)",
					tt.threshold, tt.shouldRotate, result, cred.RemainingTTL())
			}
		})
	}
}

// TestCredential_Metadata tests credential metadata fields
func TestCredential_Metadata(t *testing.T) {
	now := time.Now()
	cred := &Credential{
		Type:       TypeVaultToken,
		Category:   CategoryDatabase,
		LeaseTTL:   time.Hour,
		LeaseID:    "lease-123",
		TokenID:    "token-456",
		IssuedAt:   now,
		Data: map[string]string{
			"username": "testuser",
			"password": "testpass",
		},
		SourceType: "local",
		Revocable:  true,
		SpecName:   "my-spec",
	}

	// Verify all fields
	if cred.Type != TypeVaultToken {
		t.Errorf("expected type %s, got %s", TypeVaultToken, cred.Type)
	}
	if cred.Category != CategoryDatabase {
		t.Errorf("expected category %s, got %s", CategoryDatabase, cred.Category)
	}
	if cred.LeaseID != "lease-123" {
		t.Errorf("expected lease ID lease-123, got %s", cred.LeaseID)
	}
	if cred.TokenID != "token-456" {
		t.Errorf("expected token ID token-456, got %s", cred.TokenID)
	}
	if cred.IssuedAt != now {
		t.Errorf("expected issued at %v, got %v", now, cred.IssuedAt)
	}
	if cred.Data["username"] != "testuser" {
		t.Errorf("expected username testuser, got %s", cred.Data["username"])
	}
	if cred.SourceType != "local" {
		t.Errorf("expected source type local, got %s", cred.SourceType)
	}
	if !cred.Revocable {
		t.Error("expected credential to be revocable")
	}
	if cred.SpecName != "my-spec" {
		t.Errorf("expected spec name my-spec, got %s", cred.SpecName)
	}
}

// TestCredential_Categories tests category constants
func TestCredential_Categories(t *testing.T) {
	categories := []string{
		CategoryDatabase,
		CategoryCloudIAM,
		CategoryOAuth,
		CategoryPKI,
		CategoryK8s,
		CategoryAPI,
	}

	// Just verify they're defined and unique
	seen := make(map[string]bool)
	for _, cat := range categories {
		if cat == "" {
			t.Error("found empty category constant")
		}
		if seen[cat] {
			t.Errorf("duplicate category: %s", cat)
		}
		seen[cat] = true
	}

	if len(seen) != 6 {
		t.Errorf("expected 6 unique categories, got %d", len(seen))
	}
}

// TestCredential_Types tests type constants
func TestCredential_Types(t *testing.T) {
	types := []string{
		TypeVaultToken,
		TypeAWSAccessKeys,
	}

	// Verify they're defined and unique
	seen := make(map[string]bool)
	for _, typ := range types {
		if typ == "" {
			t.Error("found empty type constant")
		}
		if seen[typ] {
			t.Errorf("duplicate type: %s", typ)
		}
		seen[typ] = true
	}

	if len(seen) != 2 {
		t.Errorf("expected 2 unique types, got %d", len(seen))
	}
}
