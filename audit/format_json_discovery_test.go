package audit

import (
	"context"
	"strings"
	"testing"
)

func discoveryEntry() *LogEntry {
	return &LogEntry{Auth: &Auth{
		PrincipalID: "agent-1",
		Discovery: &DiscoveryAuth{
			AdmittedBy:   []AdmittedMount{{Mount: "jwt/", PrincipalID: "agent-1"}, {Mount: "k8s/", PrincipalID: "agent-1"}},
			RolesGranted: 1,
		},
	}}
}

// Salting principal_id salts the principals a discovery request was admitted
// as too: they are the same identity, and left in clear they would undo it.
func TestJSONFormat_PrincipalSaltCoversDiscovery(t *testing.T) {
	f := NewJSONFormat(
		WithSaltFunc(func(_ context.Context, v string) (string, error) { return "hmac-sha256:" + strings.ToUpper(v), nil }),
		WithSaltFields([]string{"auth.principal_id"}),
	)
	out, err := f.FormatRequest(context.Background(), discoveryEntry())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), `"agent-1"`) {
		t.Errorf("a principal left in clear: %s", out)
	}
	if strings.Count(string(out), "hmac-sha256:AGENT-1") != 3 {
		t.Errorf("want the principal and both admitted principals salted: %s", out)
	}
}

// Salting alias_name salts the aliases a discovery request was admitted as
// too, as for principal_id; the principals are left alone.
func TestJSONFormat_AliasSaltCoversDiscovery(t *testing.T) {
	entry := discoveryEntry()
	entry.Auth.AliasName = "repo:acme/x"
	for i := range entry.Auth.Discovery.AdmittedBy {
		entry.Auth.Discovery.AdmittedBy[i].AliasName = "repo:acme/x"
	}
	f := NewJSONFormat(
		WithSaltFunc(func(_ context.Context, v string) (string, error) { return "hmac-sha256:" + strings.ToUpper(v), nil }),
		WithSaltFields([]string{"auth.alias_name"}),
	)
	out, err := f.FormatRequest(context.Background(), entry)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), `"repo:acme/x"`) {
		t.Errorf("an alias left in clear: %s", out)
	}
	if strings.Count(string(out), "hmac-sha256:REPO:ACME/X") != 3 {
		t.Errorf("want the alias and both admitted aliases salted: %s", out)
	}
	if !strings.Contains(string(out), `"agent-1"`) {
		t.Errorf("the principals are not salted by alias_name: %s", out)
	}

	f = NewJSONFormat(WithOmitFields([]string{"auth.alias_name"}))
	entry.Auth.AliasName = "repo:acme/x"
	for i := range entry.Auth.Discovery.AdmittedBy {
		entry.Auth.Discovery.AdmittedBy[i].AliasName = "repo:acme/x"
	}
	out, err = f.FormatRequest(context.Background(), entry)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "repo:acme/x") {
		t.Errorf("an alias left in after omit: %s", out)
	}
}

// Omitting principal_id omits the admitted principals too; the mounts stay.
func TestJSONFormat_PrincipalOmitCoversDiscovery(t *testing.T) {
	f := NewJSONFormat(WithOmitFields([]string{"auth.principal_id"}))
	out, err := f.FormatRequest(context.Background(), discoveryEntry())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "agent-1") {
		t.Errorf("a principal left in: %s", out)
	}
	if !strings.Contains(string(out), `"mount":"jwt/"`) {
		t.Errorf("the admitting mounts are kept: %s", out)
	}
}
