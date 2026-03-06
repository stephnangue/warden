package helper

import "testing"

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		pattern string
		want    bool
	}{
		// --- Exact match ---
		{"exact spiffe", "spiffe://example.com/web", "spiffe://example.com/web", true},
		{"exact mismatch path", "spiffe://example.com/web", "spiffe://example.com/api", false},
		{"exact mismatch domain", "spiffe://example.com/web", "spiffe://other.com/web", false},

		// --- Single-segment wildcard (+) ---
		{"plus trust domain", "spiffe://example.com/dept/svc", "spiffe://+/dept/svc", true},
		{"plus middle", "spiffe://example.com/dept/svc", "spiffe://example.com/+/svc", true},
		{"plus last", "spiffe://example.com/dept/svc", "spiffe://example.com/dept/+", true},
		{"plus multiple", "spiffe://example.com/path/to/dept/subject", "spiffe://+/path/+/+/subject", true},
		{"plus all", "spiffe://a/b/c", "spiffe://+/+/+", true},
		{"plus mismatch fixed", "spiffe://example.com/other/svc", "spiffe://+/dept/svc", false},
		{"plus too few segments", "spiffe://example.com/svc", "spiffe://+/dept/svc", false},
		{"plus too many segments", "spiffe://example.com/dept/team/svc", "spiffe://+/dept/svc", false},

		// --- Trailing * (prefix match) ---
		{"star matches rest", "spiffe://domain/dept/team/svc", "spiffe://domain/dept/*", true},
		{"star matches one", "spiffe://domain/dept/svc", "spiffe://domain/dept/*", true},
		{"star matches many", "spiffe://domain/dept/a/b/c/d", "spiffe://domain/dept/*", true},
		{"star mismatch prefix", "spiffe://domain/other/svc", "spiffe://domain/dept/*", false},
		{"star mismatch domain", "spiffe://other/dept/svc", "spiffe://domain/dept/*", false},
		{"star needs at least one after", "spiffe://domain/dept", "spiffe://domain/dept/*", false},

		// --- scheme://* (catch-all for scheme) ---
		{"scheme star", "spiffe://anything/any/path", "spiffe://*", true},
		{"scheme star single segment", "spiffe://domain", "spiffe://*", true},
		{"scheme star mismatch scheme", "https://example.com/path", "spiffe://*", false},

		// --- Combined + and * ---
		{"plus and star", "spiffe://example.com/dept/team/svc", "spiffe://+/dept/*", true},
		{"plus and star mismatch", "spiffe://example.com/other/team/svc", "spiffe://+/dept/*", false},

		// --- Scheme mismatch ---
		{"different schemes", "https://example.com/path", "spiffe://example.com/path", false},

		// --- Non-SPIFFE URIs ---
		{"https exact", "https://example.com/callback", "https://example.com/callback", true},
		{"https plus", "https://example.com/callback", "https://+/callback", true},
		{"https star", "https://example.com/api/v1/users", "https://example.com/api/*", true},

		// --- No scheme (bare segments) ---
		{"bare exact", "example.com/dept/svc", "example.com/dept/svc", true},
		{"bare plus", "example.com/dept/svc", "+/dept/svc", true},
		{"bare star", "example.com/dept/team/svc", "example.com/dept/*", true},
		{"bare mismatch", "example.com/other/svc", "+/dept/svc", false},
		{"bare catch-all", "anything/here", "*", true},

		// --- Scheme presence mismatch ---
		{"scheme vs bare", "spiffe://example.com/path", "example.com/path", false},
		{"bare vs scheme", "example.com/path", "spiffe://example.com/path", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchPattern(tc.value, tc.pattern)
			if got != tc.want {
				t.Errorf("MatchPattern(%q, %q) = %v, want %v", tc.value, tc.pattern, got, tc.want)
			}
		})
	}
}

func TestMatchAny(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		patterns []string
		want     bool
	}{
		{"matches first", "spiffe://example.com/web", []string{"spiffe://example.com/web", "spiffe://other.com/web"}, true},
		{"matches second", "spiffe://other.com/web", []string{"spiffe://example.com/web", "spiffe://other.com/web"}, true},
		{"matches none", "spiffe://third.com/web", []string{"spiffe://example.com/web", "spiffe://other.com/web"}, false},
		{"empty patterns", "spiffe://example.com/web", []string{}, false},
		{"wildcard in list", "spiffe://any.com/svc", []string{"spiffe://example.com/web", "spiffe://*"}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchAny(tc.value, tc.patterns)
			if got != tc.want {
				t.Errorf("MatchAny(%q, %v) = %v, want %v", tc.value, tc.patterns, got, tc.want)
			}
		})
	}
}

func TestValidatePattern(t *testing.T) {
	valid := []string{
		"spiffe://example.com/web",
		"spiffe://+/dept/svc",
		"spiffe://+/path/+/+/subject",
		"spiffe://domain/dept/*",
		"spiffe://*",
		"https://+/callback",
		"https://example.com/api/*",
		"+/dept/svc",
		"example.com/dept/*",
		"*",
	}
	for _, p := range valid {
		t.Run("valid/"+p, func(t *testing.T) {
			if err := ValidatePattern(p); err != nil {
				t.Errorf("ValidatePattern(%q) unexpected error: %v", p, err)
			}
		})
	}

	invalid := []struct {
		pattern string
		desc    string
	}{
		{"spiffe://", "empty body after scheme"},
		{"spiffe://domain/+*/svc", "+* forbidden"},
		{"spiffe://domain/*/svc", "* not last segment"},
		{"spiffe://domain//svc", "empty segment"},
	}
	for _, tc := range invalid {
		t.Run("invalid/"+tc.desc, func(t *testing.T) {
			if err := ValidatePattern(tc.pattern); err == nil {
				t.Errorf("ValidatePattern(%q) expected error for %s, got nil", tc.pattern, tc.desc)
			}
		})
	}
}
