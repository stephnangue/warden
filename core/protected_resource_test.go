package core

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// prmTestCore builds a core with two provider mounts — one opted into the user
// leg, one not — and the metadata feature configured.
func prmTestCore(t *testing.T, cfg *protectedResourceConfig) *Core {
	t.Helper()
	core := createTestCore(t)

	mount := func(path, uuid, desc, userAuthPath string) {
		backend := &mockUnauthPathBackend{userAuthPath: userAuthPath}
		entry := &MountEntry{
			Path:        path,
			Type:        "mcp",
			Class:       mountClassProvider,
			UUID:        uuid,
			Accessor:    uuid + "_acc",
			Description: desc,
			NamespaceID: namespace.RootNamespaceID,
			namespace:   namespace.RootNamespace,
		}
		require.NoError(t, core.router.Mount(path, backend, entry, &mockBarrierView{prefix: "provider/" + uuid + "/"}))
	}
	mount("github/", "prm-gh", "GitHub for the platform team", "auth/user-jwt/")
	mount("plain/", "prm-plain", "", "")

	if cfg != nil {
		view := NewBarrierView(core.barrier, protectedResourceStorePrefix)
		require.NoError(t, saveProtectedResourceConfig(context.Background(), view, cfg))
	}
	return core
}

func TestProtectedResourceMetadata(t *testing.T) {
	ctx := context.Background()

	t.Run("disabled when no resource_url is configured", func(t *testing.T) {
		core := prmTestCore(t, nil)
		_, _, err := core.ProtectedResourceMetadata(ctx, "/v1/github")
		assert.ErrorIs(t, err, ErrNotProtectedResource)
	})

	cfg := &protectedResourceConfig{
		ResourceURL:           "https://warden.example.com",
		AuthorizationServers:  []string{"https://idp.example.com"},
		ResourceDocumentation: "https://docs.example.com",
	}

	t.Run("serves an opted-in mount", func(t *testing.T) {
		core := prmTestCore(t, cfg)
		body, _, err := core.ProtectedResourceMetadata(ctx, "/v1/github")
		require.NoError(t, err)

		var doc ProtectedResourceMetadata
		require.NoError(t, json.Unmarshal(body, &doc))
		assert.Equal(t, "https://warden.example.com/v1/github", doc.Resource)
		assert.Equal(t, []string{"https://idp.example.com"}, doc.AuthorizationServers)
		assert.Equal(t, []string{"header"}, doc.BearerMethodsSupported)
		assert.Equal(t, "GitHub for the platform team", doc.ResourceName,
			"the operator's mount description names the resource on a consent screen")
		assert.Equal(t, "https://docs.example.com", doc.ResourceDocumentation)
	})

	t.Run("a mount without user_auth_path is not a protected resource", func(t *testing.T) {
		core := prmTestCore(t, cfg)
		_, _, err := core.ProtectedResourceMetadata(ctx, "/v1/plain")
		assert.ErrorIs(t, err, ErrNotProtectedResource,
			"a mount that cannot validate a user must not advertise that it wants one")
	})

	t.Run("unknown mount, base path and non-v1 paths yield nothing", func(t *testing.T) {
		core := prmTestCore(t, cfg)
		for _, suffix := range []string{"", "/", "/v1/nope", "/github", "/v1/", "/sys/mcp"} {
			_, _, err := core.ProtectedResourceMetadata(ctx, suffix)
			assert.ErrorIs(t, err, ErrNotProtectedResource, "suffix %q", suffix)
		}
	})

	t.Run("resource identifier is stable across base-URL spellings", func(t *testing.T) {
		// Clients compare `resource` literally, so a trailing slash on the
		// configured base must not change the identifier.
		withSlash := *cfg
		withSlash.ResourceURL = "https://warden.example.com/"
		core := prmTestCore(t, &withSlash)

		body, _, err := core.ProtectedResourceMetadata(ctx, "/v1/github")
		require.NoError(t, err)
		var doc ProtectedResourceMetadata
		require.NoError(t, json.Unmarshal(body, &doc))
		assert.Equal(t, "https://warden.example.com/v1/github", doc.Resource)
	})

	t.Run("falls back to the mount path when no description is set", func(t *testing.T) {
		core := prmTestCore(t, cfg)
		entry := &MountEntry{
			Path: "nodesc/", Type: "mcp", Class: mountClassProvider,
			UUID: "prm-nodesc", Accessor: "prm-nodesc_acc",
			NamespaceID: namespace.RootNamespaceID, namespace: namespace.RootNamespace,
		}
		require.NoError(t, core.router.Mount("nodesc/",
			&mockUnauthPathBackend{userAuthPath: "auth/user-jwt/"}, entry,
			&mockBarrierView{prefix: "provider/prm-nodesc/"}))

		body, _, err := core.ProtectedResourceMetadata(ctx, "/v1/nodesc")
		require.NoError(t, err)
		var doc ProtectedResourceMetadata
		require.NoError(t, json.Unmarshal(body, &doc))
		assert.Equal(t, "nodesc", doc.ResourceName)
	})

	t.Run("non-canonical paths are refused", func(t *testing.T) {
		// Go's ServeMux redirects a literal "/../" before the handler runs, but a
		// percent-encoded one arrives decoded and intact. Left unchecked,
		// "/v1/github/../plain" longest-prefix matches the github mount while the
		// document echoes a `resource` that normalizes to /v1/plain — binding one
		// mount's identifier to another mount's authorization server, which is a
		// token-confusion primitive for any client that normalizes before
		// comparing.
		core := prmTestCore(t, cfg)
		for _, suffix := range []string{
			"/v1/github/../plain",
			"/v1/github/..",
			"/v1/./github",
			"/v1//github",
			"/v1/github/",
		} {
			_, _, err := core.ProtectedResourceMetadata(ctx, suffix)
			assert.ErrorIs(t, err, ErrNotProtectedResource,
				"non-canonical suffix %q must not yield a document", suffix)
		}
	})

	t.Run("no derivable authorization server yields nothing", func(t *testing.T) {
		// No global override, and the user auth mount does not exist — so
		// nothing can name an issuer. Guessing would send the user's browser to
		// the wrong authorization server.
		noOverride := *cfg
		noOverride.AuthorizationServers = nil
		core := prmTestCore(t, &noOverride)

		_, _, err := core.ProtectedResourceMetadata(ctx, "/v1/github")
		assert.ErrorIs(t, err, ErrNotProtectedResource)
	})
}
