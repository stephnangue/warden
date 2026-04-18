package ibmcloud

import (
	"strings"
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSpec(t *testing.T) {
	assert.Equal(t, "ibmcloud", Spec.Name)
	assert.Equal(t, credential.TypeIBMCloudKeys, Spec.CredentialType)
	assert.Equal(t, DefaultIBMCloudURL, Spec.DefaultURL)
	assert.Equal(t, "ibmcloud_url", Spec.URLConfigKey)
	assert.Equal(t, DefaultIBMCloudTimeout, Spec.DefaultTimeout)
	assert.Equal(t, "warden-ibmcloud-proxy", Spec.UserAgent)
}

func TestSpec_APIAuth(t *testing.T) {
	assert.Equal(t, "Authorization", Spec.APIAuth.HeaderName)
	assert.Equal(t, "Bearer %s", Spec.APIAuth.HeaderValueFormat)
	assert.Equal(t, "access_token", Spec.APIAuth.CredentialField)
	assert.True(t, Spec.APIAuth.StripAuthorization)
}

func TestSpec_S3Endpoint(t *testing.T) {
	require.NotNil(t, Spec.S3Endpoint)

	tests := []struct {
		name     string
		state    map[string]any
		region   string
		expected string
	}{
		{"public default (nil state)", nil, "us-south", "s3.us-south.cloud-object-storage.appdomain.cloud"},
		{"public default (empty state)", map[string]any{}, "eu-de", "s3.eu-de.cloud-object-storage.appdomain.cloud"},
		{"public explicit", map[string]any{"cos_endpoint_type": "public"}, "au-syd", "s3.au-syd.cloud-object-storage.appdomain.cloud"},
		{"private", map[string]any{"cos_endpoint_type": "private"}, "us-south", "s3.private.us-south.cloud-object-storage.appdomain.cloud"},
		{"direct", map[string]any{"cos_endpoint_type": "direct"}, "eu-de", "s3.direct.eu-de.cloud-object-storage.appdomain.cloud"},
		{"unknown falls back to public", map[string]any{"cos_endpoint_type": "bogus"}, "jp-tok", "s3.jp-tok.cloud-object-storage.appdomain.cloud"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Spec.S3Endpoint(tt.state, tt.region)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestSpec_OnConfigParsed(t *testing.T) {
	require.NotNil(t, Spec.OnConfigParsed)

	t.Run("endpoint type and suffixes", func(t *testing.T) {
		state := Spec.OnConfigParsed(map[string]any{
			"cos_endpoint_type":     "private",
			"allowed_host_suffixes": []string{".example.internal"},
		})
		assert.Equal(t, "private", state["cos_endpoint_type"])
		assert.Equal(t, []string{".example.internal"}, state["allowed_host_suffixes"])
	})

	t.Run("missing keys get defaults", func(t *testing.T) {
		state := Spec.OnConfigParsed(map[string]any{})
		assert.Equal(t, "", state["cos_endpoint_type"])
		assert.Equal(t, defaultIBMAllowedHostSuffixes, state["allowed_host_suffixes"])
	})
}

func TestSpec_ExtraConfigKeys(t *testing.T) {
	assert.Contains(t, Spec.ExtraConfigKeys, "cos_endpoint_type")
	assert.Contains(t, Spec.ExtraConfigKeys, "allowed_host_suffixes")
	require.Contains(t, Spec.ExtraConfigFields, "cos_endpoint_type")
	require.Contains(t, Spec.ExtraConfigFields, "allowed_host_suffixes")
}

func TestSpec_ExtractS3Credentials(t *testing.T) {
	require.NotNil(t, Spec.ExtractS3Credentials)
}

func TestSpec_RewriteAPITarget_Present(t *testing.T) {
	require.NotNil(t, Spec.RewriteAPITarget)
}

func TestFactory(t *testing.T) {
	assert.NotNil(t, Factory)
}

// --- RewriteAPITarget routing ---

func defaultState() map[string]any {
	return map[string]any{"allowed_host_suffixes": defaultIBMAllowedHostSuffixes}
}

func TestRewriteAPITarget_HappyPaths(t *testing.T) {
	tests := []struct {
		name     string
		apiPath  string
		expected string
	}{
		{
			"resource controller",
			"/resource-controller.cloud.ibm.com/v2/resource_instances",
			"https://resource-controller.cloud.ibm.com/v2/resource_instances",
		},
		{
			"resource groups",
			"/resource-controller.cloud.ibm.com/v2/resource_groups",
			"https://resource-controller.cloud.ibm.com/v2/resource_groups",
		},
		{
			"regional VPC",
			"/us-south.iaas.cloud.ibm.com/v1/vpcs",
			"https://us-south.iaas.cloud.ibm.com/v1/vpcs",
		},
		{
			"IKS with /global/ prefix preserved",
			"/containers.cloud.ibm.com/global/v2/vpc/getClusters",
			"https://containers.cloud.ibm.com/global/v2/vpc/getClusters",
		},
		{
			"Code Engine regional",
			"/api.eu-de.codeengine.cloud.ibm.com/v2/projects",
			"https://api.eu-de.codeengine.cloud.ibm.com/v2/projects",
		},
		{
			"appdomain.cloud host (COS-adjacent)",
			"/s3.us-south.cloud-object-storage.appdomain.cloud/buckets",
			"https://s3.us-south.cloud-object-storage.appdomain.cloud/buckets",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Spec.RewriteAPITarget("unused", tt.apiPath, defaultState())
			require.NoError(t, err)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestRewriteAPITarget_HostOnlyPathGetsRoot(t *testing.T) {
	got, err := Spec.RewriteAPITarget("unused", "/containers.cloud.ibm.com", defaultState())
	require.NoError(t, err)
	assert.Equal(t, "https://containers.cloud.ibm.com/", got)
}

func TestRewriteAPITarget_RejectsEmptyPath(t *testing.T) {
	_, err := Spec.RewriteAPITarget("unused", "/", defaultState())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing target host")
}

func TestRewriteAPITarget_RejectsCompletelyEmpty(t *testing.T) {
	_, err := Spec.RewriteAPITarget("unused", "", defaultState())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing target host")
}

func TestRewriteAPITarget_DisallowedSuffix(t *testing.T) {
	_, err := Spec.RewriteAPITarget("unused", "/evil.example.com/x", defaultState())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not in allowed_host_suffixes")
}

func TestRewriteAPITarget_BlocksEvilSubdomainTrick(t *testing.T) {
	// Without the leading-dot enforcement, "evilcloud.ibm.com" could match a
	// suffix like "cloud.ibm.com". Our normalization drops non-dot suffixes
	// so the default allowlist entries all start with a dot.
	_, err := Spec.RewriteAPITarget("unused", "/evilcloud.ibm.com/x", defaultState())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not in allowed_host_suffixes")
}

func TestRewriteAPITarget_RejectsHostWithPort(t *testing.T) {
	_, err := Spec.RewriteAPITarget("unused", "/containers.cloud.ibm.com:8080/x", defaultState())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid target host")
}

func TestRewriteAPITarget_RejectsHostWithUserinfo(t *testing.T) {
	_, err := Spec.RewriteAPITarget("unused", "/user@containers.cloud.ibm.com/x", defaultState())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid target host")
}

func TestRewriteAPITarget_RejectsIPv4Literal(t *testing.T) {
	_, err := Spec.RewriteAPITarget("unused", "/169.254.169.254/x", defaultState())
	require.Error(t, err)
	// Either IP rejection or regex rejection is acceptable; both are safe.
	assert.True(t,
		strings.Contains(err.Error(), "IP literal") ||
			strings.Contains(err.Error(), "not a valid hostname"),
		"unexpected error: %v", err)
}

func TestRewriteAPITarget_RejectsUppercaseHost(t *testing.T) {
	_, err := Spec.RewriteAPITarget("unused", "/Containers.Cloud.IBM.com/x", defaultState())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "lowercase")
}

func TestRewriteAPITarget_CustomSuffixesOverrideDefault(t *testing.T) {
	state := map[string]any{"allowed_host_suffixes": []string{".example.internal"}}

	// Default-allowed host now disallowed
	_, err := Spec.RewriteAPITarget("unused", "/resource-controller.cloud.ibm.com/x", state)
	require.Error(t, err)

	// Custom-allowed host now allowed
	got, err := Spec.RewriteAPITarget("unused", "/svc.example.internal/x", state)
	require.NoError(t, err)
	assert.Equal(t, "https://svc.example.internal/x", got)
}

func TestRewriteAPITarget_Wildcard(t *testing.T) {
	state := map[string]any{"allowed_host_suffixes": []string{"*"}}
	got, err := Spec.RewriteAPITarget("unused", "/any.host.example/x", state)
	require.NoError(t, err)
	assert.Equal(t, "https://any.host.example/x", got)
}

func TestRewriteAPITarget_EmptySuffixesFallsBackToDefault(t *testing.T) {
	// If state somehow arrives without allowed_host_suffixes populated,
	// the hook falls back to the default closed allowlist.
	got, err := Spec.RewriteAPITarget("unused", "/resource-controller.cloud.ibm.com/x", map[string]any{})
	require.NoError(t, err)
	assert.Equal(t, "https://resource-controller.cloud.ibm.com/x", got)

	_, err = Spec.RewriteAPITarget("unused", "/evil.example.com/x", map[string]any{})
	require.Error(t, err)
}

// --- parseHostSuffixes ---

func TestParseHostSuffixes(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected []string
	}{
		{"nil", nil, nil},
		{"empty string", "", nil},
		{"single dotted string", ".cloud.ibm.com", []string{".cloud.ibm.com"}},
		{"comma-separated string", ".cloud.ibm.com,.appdomain.cloud", []string{".cloud.ibm.com", ".appdomain.cloud"}},
		{"whitespace trimmed and lowercased", " .Cloud.IBM.com , .APPDOMAIN.cloud ", []string{".cloud.ibm.com", ".appdomain.cloud"}},
		{"[]string", []string{".a.b", ".c.d"}, []string{".a.b", ".c.d"}},
		{"[]any", []any{".a.b", ".c.d"}, []string{".a.b", ".c.d"}},
		{"wildcard alone", "*", []string{"*"}},
		{"wildcard with others short-circuits", ".a.b,*,.c.d", []string{"*"}},
		{"non-dot entries dropped", "cloud.ibm.com,.appdomain.cloud,ibm", []string{".appdomain.cloud"}},
		{"unknown type", 42, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseHostSuffixes(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// --- hostAllowed ---

func TestHostAllowed(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		suffixes []string
		allowed  bool
	}{
		{"exact-suffix match", "foo.cloud.ibm.com", []string{".cloud.ibm.com"}, true},
		{"deep subdomain match", "a.b.c.cloud.ibm.com", []string{".cloud.ibm.com"}, true},
		{"disallowed host", "evil.example.com", []string{".cloud.ibm.com"}, false},
		{"wildcard allows any", "anything.example", []string{"*"}, true},
		{"empty suffixes denies all", "foo.cloud.ibm.com", nil, false},
		{"empty string in list is ignored", "foo.cloud.ibm.com", []string{"", ".cloud.ibm.com"}, true},
		{"multiple suffixes — match second", "foo.appdomain.cloud", []string{".cloud.ibm.com", ".appdomain.cloud"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.allowed, hostAllowed(tt.host, tt.suffixes))
		})
	}
}
