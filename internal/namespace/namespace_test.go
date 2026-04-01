package namespace

import (
	"context"
	"testing"
)

func TestNamespace_Validate(t *testing.T) {
	tests := []struct {
		name    string
		ns      *Namespace
		wantErr bool
	}{
		{"root namespace", &Namespace{Path: ""}, false},
		{"valid path", &Namespace{Path: "org1/"}, false},
		{"valid nested path", &Namespace{Path: "org1/team1/"}, false},
		{"missing trailing slash", &Namespace{Path: "org1"}, true},
		{"contains dotdot", &Namespace{Path: "org1/../evil/"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ns.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNamespace_HasParent(t *testing.T) {
	root := RootNamespace
	org := &Namespace{Path: "org1/"}
	team := &Namespace{Path: "org1/team1/"}
	other := &Namespace{Path: "org2/"}

	tests := []struct {
		name   string
		ns     *Namespace
		parent *Namespace
		want   bool
	}{
		{"root is parent of org", org, root, true},
		{"root is parent of team", team, root, true},
		{"org is parent of team", team, org, true},
		{"team is not parent of org", org, team, false},
		{"other is not parent of team", team, other, false},
		{"same namespace", org, org, true},
		{"root is parent of itself", root, root, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ns.HasParent(tt.parent); got != tt.want {
				t.Fatalf("HasParent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNamespace_ParentPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		want     string
		wantBool bool
	}{
		{"root", "", "", false},
		{"top-level", "org1/", "", true},
		{"nested", "org1/team1/", "org1/", true},
		{"deeply nested", "a/b/c/", "a/b/", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := &Namespace{Path: tt.path}
			got, ok := ns.ParentPath()
			if got != tt.want || ok != tt.wantBool {
				t.Fatalf("ParentPath() = (%q, %v), want (%q, %v)", got, ok, tt.want, tt.wantBool)
			}
		})
	}
}

func TestNamespace_Clone(t *testing.T) {
	original := &Namespace{
		ID:        "test-id",
		UUID:      "test-uuid",
		Path:      "org1/",
		Tainted:   true,
		Locked:    true,
		UnlockKey: "secret-key",
		CustomMetadata: map[string]string{
			"env": "prod",
		},
	}

	t.Run("clone with unlock key", func(t *testing.T) {
		clone := original.Clone(true)
		if clone.UnlockKey != original.UnlockKey {
			t.Fatal("expected UnlockKey to be preserved")
		}
		if clone.ID != original.ID || clone.Path != original.Path {
			t.Fatal("clone fields don't match original")
		}
		// Mutate clone metadata, verify original unaffected
		clone.CustomMetadata["env"] = "staging"
		if original.CustomMetadata["env"] != "prod" {
			t.Fatal("mutating clone affected original")
		}
	})

	t.Run("clone without unlock key", func(t *testing.T) {
		clone := original.Clone(false)
		if clone.UnlockKey != "" {
			t.Fatal("expected UnlockKey to be omitted")
		}
	})
}

func TestNamespace_TrimmedPath(t *testing.T) {
	tests := []struct {
		name   string
		nsPath string
		input  string
		want   string
	}{
		{"strips prefix", "org1/", "org1/secret/foo", "secret/foo"},
		{"no match", "org1/", "other/path", "other/path"},
		{"root strips nothing", "", "secret/foo", "secret/foo"},
		{"exact match", "org1/", "org1/", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := &Namespace{Path: tt.nsPath}
			if got := ns.TrimmedPath(tt.input); got != tt.want {
				t.Fatalf("TrimmedPath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestCanonicalize(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"/", ""},
		{"org1", "org1/"},
		{"org1/", "org1/"},
		{"/org1", "org1/"},
		{"/org1/", "org1/"},
		{"/org1/team1", "org1/team1/"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := Canonicalize(tt.input); got != tt.want {
				t.Fatalf("Canonicalize(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestContextWithNamespace_RoundTrip(t *testing.T) {
	ns := &Namespace{ID: "test", Path: "org1/"}
	ctx := ContextWithNamespace(context.Background(), ns)

	got, err := FromContext(ctx)
	if err != nil {
		t.Fatalf("FromContext() error = %v", err)
	}
	if got != ns {
		t.Fatalf("got %v, want %v", got, ns)
	}
}

func TestFromContext_Empty(t *testing.T) {
	_, err := FromContext(context.Background())
	if err != ErrNoNamespace {
		t.Fatalf("expected ErrNoNamespace, got %v", err)
	}
}

func TestFromContext_Nil(t *testing.T) {
	_, err := FromContext(nil)
	if err != ErrNoNamespace {
		t.Fatalf("expected ErrNoNamespace, got %v", err)
	}
}

func TestRootContext(t *testing.T) {
	ctx := RootContext(nil)
	ns, err := FromContext(ctx)
	if err != nil {
		t.Fatalf("FromContext() error = %v", err)
	}
	if ns != RootNamespace {
		t.Fatalf("expected RootNamespace, got %v", ns)
	}
}

func TestNamespace_String(t *testing.T) {
	ns := &Namespace{ID: "abc", UUID: "def", Path: "org1/"}
	s := ns.String()
	if s != "ID: abc. UUID: def. Path: org1/" {
		t.Fatalf("unexpected String(): %s", s)
	}
}
