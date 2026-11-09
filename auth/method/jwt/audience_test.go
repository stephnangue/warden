package jwt

import (
	"context"
	"crypto/ecdsa"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// A config write that would leave an agent mount without bound_audiences is
// refused and changes nothing; a human mount may leave them empty.
func TestConfigWrite_AgentMountRequiresBoundAudiences(t *testing.T) {
	_, pemStr := genTestPubKeyPEM(t, "ECDSA")

	t.Run("agent without audiences refused", func(t *testing.T) {
		b, ctx := createTestBackendWithStorage(t)
		resp := writeConfig(b, map[string]any{"jwt_validation_pubkeys": []string{pemStr}})
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.ErrorIs(t, resp.Err, helper.ErrAgentAudiencesRequired)
		assert.Contains(t, resp.Err.Error(), "entity_kind")
		assert.Nil(t, b.config, "a refused write is not installed")
		entry, err := b.storageView.Get(ctx, "config")
		require.NoError(t, err)
		assert.Nil(t, entry, "a refused write is not stored")
	})

	t.Run("explicit agent kind refused alike", func(t *testing.T) {
		b, _ := createTestBackendWithStorage(t)
		resp := writeConfig(b, map[string]any{"jwt_validation_pubkeys": []string{pemStr}, "entity_kind": "agent"})
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.ErrorIs(t, resp.Err, helper.ErrAgentAudiencesRequired)
	})

	t.Run("human without audiences accepted", func(t *testing.T) {
		b, _ := createTestBackendWithStorage(t)
		resp := writeConfig(b, map[string]any{"jwt_validation_pubkeys": []string{pemStr}, "entity_kind": "human"})
		require.Equal(t, http.StatusOK, resp.StatusCode, "write: %v", resp.Err)
	})

	t.Run("clearing the audiences of an agent mount refused", func(t *testing.T) {
		b, _ := factsBackend(t, nil)
		before := b.config
		resp := writeConfig(b, map[string]any{"bound_audiences": ""})
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.ErrorIs(t, resp.Err, helper.ErrAgentAudiencesRequired)
		assert.Same(t, before, b.config)
	})
}

// storedWithoutAudiences returns a backend whose stored config (written before
// audience binding was required) has no bound_audiences, as an unseal loads
// it: the load does not fail, and the config is installed.
func storedWithoutAudiences(t *testing.T, kind string) (*jwtAuthBackend, *ecdsa.PrivateKey) {
	t.Helper()
	privAny, pemStr := genTestPubKeyPEM(t, "ECDSA")
	b, ctx := createTestBackendWithStorage(t)
	require.NoError(t, b.setupJWTConfig(ctx, map[string]any{
		"jwt_validation_pubkeys": []string{pemStr},
		"bound_issuer":           factsTestIssuer,
		"entity_kind":            kind,
	}))
	require.NotNil(t, b.config)
	return b, privAny.(*ecdsa.PrivateKey)
}

// A stored agent config without bound_audiences refuses admission inside the
// admission check itself, at login and at introspect/admit alike: any token
// the issuer signs, for any relying party, would otherwise be admitted.
func TestAdmission_StoredAgentConfigWithoutAudiencesRefuses(t *testing.T) {
	b, key := storedWithoutAudiences(t, "")
	token := signES256(t, key, baseClaims(map[string]any{"aud": "another-relying-party"}))

	resp := login(t, b, token)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	require.ErrorIs(t, resp.Err, helper.ErrAgentAudiencesRequired)
	assert.Nil(t, resp.Auth)

	_, err := routeAdmit(b, token, true)
	require.ErrorIs(t, err, helper.ErrAgentAudiencesRequired, "introspect/admit reports the mount condition")

	// A human mount may leave the audience to the request's resource.
	h, hkey := storedWithoutAudiences(t, "human")
	resp = login(t, h, signES256(t, hkey, baseClaims(nil)))
	require.Equal(t, http.StatusOK, resp.StatusCode, "login: %v", resp.Err)
	require.NotNil(t, resp.Auth.Admission)
}

// A token minted for another relying party of the same issuer is not
// admitted by a mount bound to Warden's audience.
func TestLogin_AnotherRelyingPartysTokenRefused(t *testing.T) {
	b, key := factsBackend(t, nil)
	for _, aud := range []any{"another-relying-party", []any{"api", "web"}} {
		resp := login(t, b, signES256(t, key, baseClaims(map[string]any{"aud": aud})))
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "aud %v", aud)
		assert.Nil(t, resp.Auth)
		adm, err := b.admit(context.Background(), &logical.Request{ClientToken: signES256(t, key, baseClaims(map[string]any{"aud": aud}))}, time.Now())
		require.NoError(t, err)
		assert.Nil(t, adm, "introspect/admit agrees with login")
	}
	resp := login(t, b, signES256(t, key, baseClaims(map[string]any{"aud": []any{"api", "warden"}})))
	require.Equal(t, http.StatusOK, resp.StatusCode, "any one bound audience admits: %v", resp.Err)
}

// The login reads no claim after handing the claims map to newAdmission,
// which adopts it: the admission is shared by every request of the
// credential, so a later write or read of the map would race them.
func TestLogin_NoClaimsReadAfterNewAdmission(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "path_login.go", nil, 0)
	require.NoError(t, err)

	var login *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "handleLogin" {
			login = fd
		}
	}
	require.NotNil(t, login, "handleLogin not found")

	var adopt *ast.CallExpr
	ast.Inspect(login.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "newAdmission" {
				require.Nil(t, adopt, "newAdmission is called once")
				adopt = call
			}
		}
		return true
	})
	require.NotNil(t, adopt, "handleLogin builds its admission with newAdmission")

	ast.Inspect(login.Body, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == "claims" && id.Pos() > adopt.End() {
			t.Errorf("claims read at %s, after newAdmission adopted them", fset.Position(id.Pos()))
		}
		return true
	})
}

// The login's fields are its credential: there is no role to send.
func TestLogin_SchemaHasNoRole(t *testing.T) {
	b, _ := createTestBackendWithStorage(t)
	assert.Equal(t, []string{"jwt"}, fieldNames(b.pathLogin().Fields))
}

func fieldNames(fields map[string]*framework.FieldSchema) []string {
	out := make([]string, 0, len(fields))
	for k := range fields {
		out = append(out, k)
	}
	return out
}
