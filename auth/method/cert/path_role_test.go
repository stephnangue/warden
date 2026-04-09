// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"time"
)

// createTestBackend creates a cert backend for testing.
func createTestBackend(t *testing.T) (*certAuthBackend, context.Context) {
	t.Helper()
	ctx := context.Background()
	storage := newInmemStorage()
	conf := &logical.BackendConfig{
		Logger:      testLogger(),
		StorageView: storage,
	}
	backend, err := Factory(ctx, conf)
	require.NoError(t, err)
	return backend.(*certAuthBackend), ctx
}

// roleFieldData builds a FieldData for role creation with the given raw values.
// Includes a default allowed_common_names constraint to satisfy role validation.
func roleFieldData(raw map[string]any) *framework.FieldData {
	if _, ok := raw["allowed_common_names"]; !ok {
		raw["allowed_common_names"] = []string{"test-*"}
	}
	return &framework.FieldData{
		Raw: raw,
		Schema: map[string]*framework.FieldSchema{
			"name":                 {Type: framework.TypeString},
			"token_ttl":            {Type: framework.TypeDurationSecond, Default: 3600},
			"allowed_common_names": {Type: framework.TypeCommaStringSlice},
		},
	}
}

func TestPathRole_TokenTypeAlwaysCertRole(t *testing.T) {
	b, ctx := createTestBackend(t)
	b.config = &CertAuthConfig{PrincipalClaim: "cn"}

	fd := roleFieldData(map[string]any{
		"name":      "cert-default",
		"token_ttl": 3600,
	})

	resp, err := b.handleRoleCreate(ctx, &logical.Request{}, fd)
	require.NoError(t, err)
	assert.Nil(t, resp.Err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	role, err := b.getRole(ctx, "cert-default")
	require.NoError(t, err)
	assert.Equal(t, "cert_role", role.TokenType)
}

func TestCertRole_ParseTokenTTL(t *testing.T) {
	t.Run("empty returns 1h", func(t *testing.T) {
		r := &CertRole{}
		d, err := r.ParseTokenTTL()
		require.NoError(t, err)
		assert.Equal(t, time.Hour, d)
	})

	t.Run("valid string", func(t *testing.T) {
		r := &CertRole{TokenTTL: "30m"}
		d, err := r.ParseTokenTTL()
		require.NoError(t, err)
		assert.Equal(t, 30*time.Minute, d)
	})

	t.Run("invalid string", func(t *testing.T) {
		r := &CertRole{TokenTTL: "not-a-duration"}
		_, err := r.ParseTokenTTL()
		assert.Error(t, err)
	})
}

// =============================================================================
// handleConfigRead Tests
// =============================================================================

func TestHandleRoleRead(t *testing.T) {
	b, ctx := createTestBackend(t)

	// Create a role first
	role := &CertRole{
		Name:               "test-role",
		AllowedCommonNames: []string{"test-*"},
		TokenTTL:           time.Hour.String(),
		TokenType:          "cert_role",
		TokenPolicies:      []string{"default"},
	}
	err := b.setRole(ctx, role)
	require.NoError(t, err)

	fd := &framework.FieldData{
		Raw:    map[string]any{"name": "test-role"},
		Schema: map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}},
	}
	resp, err := b.handleRoleRead(ctx, &logical.Request{}, fd)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "test-role", resp.Data["name"])
}

func TestHandleRoleRead_NotFound(t *testing.T) {
	b, ctx := createTestBackend(t)

	fd := &framework.FieldData{
		Raw:    map[string]any{"name": "nonexistent"},
		Schema: map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}},
	}
	resp, err := b.handleRoleRead(ctx, &logical.Request{}, fd)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestHandleRoleDelete(t *testing.T) {
	b, ctx := createTestBackend(t)

	role := &CertRole{
		Name:               "del-role",
		AllowedCommonNames: []string{"*"},
		TokenTTL:           time.Hour.String(),
	}
	err := b.setRole(ctx, role)
	require.NoError(t, err)

	fd := &framework.FieldData{
		Raw:    map[string]any{"name": "del-role"},
		Schema: map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}},
	}
	resp, err := b.handleRoleDelete(ctx, &logical.Request{}, fd)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify deleted
	got, _ := b.getRole(ctx, "del-role")
	assert.Nil(t, got)
}

func TestHandleRoleList(t *testing.T) {
	b, ctx := createTestBackend(t)

	for _, name := range []string{"role-a", "role-b"} {
		err := b.setRole(ctx, &CertRole{Name: name, AllowedCommonNames: []string{"*"}, TokenTTL: "1h"})
		require.NoError(t, err)
	}

	fd := &framework.FieldData{Raw: map[string]any{}, Schema: map[string]*framework.FieldSchema{}}
	resp, err := b.handleRoleList(ctx, &logical.Request{}, fd)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	keys := resp.Data["keys"].([]string)
	assert.Len(t, keys, 2)
}

func TestHandleRoleUpdate_Upsert(t *testing.T) {
	b, ctx := createTestBackend(t)

	fd := roleFieldData(map[string]any{
		"name":      "new-role",
		"token_ttl": 3600,
	})

	resp, err := b.handleRoleUpdate(ctx, &logical.Request{}, fd)
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Contains(t, resp.Data["message"], "created")
}

func TestHandleRoleUpdate_ExistingRole(t *testing.T) {
	b, ctx := createTestBackend(t)

	// Create initial
	role := &CertRole{
		Name:               "upd-role",
		AllowedCommonNames: []string{"old-*"},
		TokenTTL:           time.Hour.String(),
		TokenType:          "cert_role",
	}
	err := b.setRole(ctx, role)
	require.NoError(t, err)

	// Update with new fields
	fd := &framework.FieldData{
		Raw: map[string]any{
			"name":                 "upd-role",
			"allowed_common_names": []string{"new-*"},
			"token_ttl":            7200,
		},
		Schema: map[string]*framework.FieldSchema{
			"name":                 {Type: framework.TypeString},
			"allowed_common_names": {Type: framework.TypeCommaStringSlice},
			"token_ttl":            {Type: framework.TypeDurationSecond},
		},
	}
	resp, err := b.handleRoleUpdate(ctx, &logical.Request{}, fd)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	updated, _ := b.getRole(ctx, "upd-role")
	assert.Equal(t, []string{"new-*"}, updated.AllowedCommonNames)
}

func TestHandleRoleCreate_Duplicate(t *testing.T) {
	b, ctx := createTestBackend(t)

	fd := roleFieldData(map[string]any{
		"name":      "dup-role",
		"token_ttl": 3600,
	})

	_, err := b.handleRoleCreate(ctx, &logical.Request{}, fd)
	require.NoError(t, err)

	// Second create should fail
	resp, err := b.handleRoleCreate(ctx, &logical.Request{}, fd)
	require.NoError(t, err)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

// =============================================================================
// validateRole Tests
// =============================================================================

func TestValidateRole_NoConstraints(t *testing.T) {
	b, _ := createTestBackend(t)
	role := &CertRole{Name: "no-constraints"}
	err := b.validateRole(role)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one certificate constraint")
}

func TestValidateRole_InvalidTTL(t *testing.T) {
	b, _ := createTestBackend(t)
	role := &CertRole{
		Name:               "bad-ttl",
		AllowedCommonNames: []string{"*"},
		TokenTTL:           "not-a-duration",
	}
	err := b.validateRole(role)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token_ttl")
}

func TestValidateRole_InvalidGlobPattern(t *testing.T) {
	b, _ := createTestBackend(t)
	role := &CertRole{
		Name:               "bad-glob",
		AllowedCommonNames: []string{"[invalid"},
		TokenTTL:           "1h",
	}
	err := b.validateRole(role)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid allowed_common_names pattern")
}

func TestValidateRole_InvalidDNSSANGlob(t *testing.T) {
	b, _ := createTestBackend(t)
	role := &CertRole{
		Name:               "bad-dns-glob",
		AllowedCommonNames: []string{"*"},
		AllowedDNSSANs:     []string{"[invalid"},
		TokenTTL:           "1h",
	}
	err := b.validateRole(role)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid allowed_dns_sans")
}

func TestValidateRole_InvalidEmailSANGlob(t *testing.T) {
	b, _ := createTestBackend(t)
	role := &CertRole{
		Name:               "bad-email-glob",
		AllowedCommonNames: []string{"*"},
		AllowedEmailSANs:   []string{"[invalid"},
		TokenTTL:           "1h",
	}
	err := b.validateRole(role)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid allowed_email_sans")
}

func TestValidateRole_InvalidPrincipalClaim(t *testing.T) {
	b, _ := createTestBackend(t)
	role := &CertRole{
		Name:               "bad-claim",
		AllowedCommonNames: []string{"*"},
		PrincipalClaim:     "invalid",
	}
	err := b.validateRole(role)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid principal_claim")
}

func TestValidateRole_InvalidCertPEM(t *testing.T) {
	b, _ := createTestBackend(t)
	role := &CertRole{
		Name:               "bad-cert",
		AllowedCommonNames: []string{"*"},
		Certificate:        "not-a-pem",
	}
	err := b.validateRole(role)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid certificate PEM")
}

// =============================================================================
// calculateTTL Tests
// =============================================================================

func TestBuildRoleFromFieldData_AllFields(t *testing.T) {
	b, _ := createTestBackend(t)

	fd := &framework.FieldData{
		Raw: map[string]any{
			"name":                         "full-role",
			"allowed_common_names":         []string{"cn-*"},
			"allowed_dns_sans":             []string{"*.example.com"},
			"allowed_email_sans":           []string{"*@example.com"},
			"allowed_uri_sans":             []string{"spiffe://*"},
			"allowed_organizational_units": []string{"Engineering"},
			"allowed_organizations":        []string{"Acme"},
			"certificate":                  "pem-data",
			"token_policies":               []string{"default"},
			"token_ttl":                    7200,
			"cred_spec_name":               "aws-dev",
			"principal_claim":              "serial",
		},
		Schema: map[string]*framework.FieldSchema{
			"name":                         {Type: framework.TypeString},
			"allowed_common_names":         {Type: framework.TypeCommaStringSlice},
			"allowed_dns_sans":             {Type: framework.TypeCommaStringSlice},
			"allowed_email_sans":           {Type: framework.TypeCommaStringSlice},
			"allowed_uri_sans":             {Type: framework.TypeCommaStringSlice},
			"allowed_organizational_units": {Type: framework.TypeCommaStringSlice},
			"allowed_organizations":        {Type: framework.TypeCommaStringSlice},
			"certificate":                  {Type: framework.TypeString},
			"token_policies":               {Type: framework.TypeCommaStringSlice},
			"token_ttl":                    {Type: framework.TypeDurationSecond},
			"cred_spec_name":               {Type: framework.TypeString},
			"principal_claim":              {Type: framework.TypeString},
		},
	}

	role := b.buildRoleFromFieldData("full-role", fd)
	assert.Equal(t, "full-role", role.Name)
	assert.Equal(t, []string{"cn-*"}, role.AllowedCommonNames)
	assert.Equal(t, []string{"*.example.com"}, role.AllowedDNSSANs)
	assert.Equal(t, []string{"*@example.com"}, role.AllowedEmailSANs)
	assert.Equal(t, []string{"spiffe://*"}, role.AllowedURISANs)
	assert.Equal(t, []string{"Engineering"}, role.AllowedOrganizationalUnits)
	assert.Equal(t, []string{"Acme"}, role.AllowedOrganizations)
	assert.Equal(t, "pem-data", role.Certificate)
	assert.Equal(t, []string{"default"}, role.TokenPolicies)
	assert.Equal(t, "aws-dev", role.CredSpecName)
	assert.Equal(t, "serial", role.PrincipalClaim)
}

// =============================================================================
// handleRoleUpdate with all field types
// =============================================================================

func TestHandleRoleUpdate_AllFieldsOnExistingRole(t *testing.T) {
	b, ctx := createTestBackend(t)

	// Create initial role
	role := &CertRole{
		Name:               "full-upd",
		AllowedCommonNames: []string{"old-*"},
		TokenTTL:           time.Hour.String(),
		TokenType:          "cert_role",
	}
	err := b.setRole(ctx, role)
	require.NoError(t, err)

	fd := &framework.FieldData{
		Raw: map[string]any{
			"name":                         "full-upd",
			"allowed_common_names":         []string{"new-*"},
			"allowed_dns_sans":             []string{"*.new.com"},
			"allowed_email_sans":           []string{"*@new.com"},
			"allowed_uri_sans":             []string{"spiffe://new/*"},
			"allowed_organizational_units": []string{"NewEng"},
			"allowed_organizations":        []string{"NewOrg"},
			"token_policies":               []string{"new-policy"},
			"token_ttl":                    3600,
			"cred_spec_name":               "new-spec",
			"principal_claim":              "dns_san",
		},
		Schema: map[string]*framework.FieldSchema{
			"name":                         {Type: framework.TypeString},
			"allowed_common_names":         {Type: framework.TypeCommaStringSlice},
			"allowed_dns_sans":             {Type: framework.TypeCommaStringSlice},
			"allowed_email_sans":           {Type: framework.TypeCommaStringSlice},
			"allowed_uri_sans":             {Type: framework.TypeCommaStringSlice},
			"allowed_organizational_units": {Type: framework.TypeCommaStringSlice},
			"allowed_organizations":        {Type: framework.TypeCommaStringSlice},
			"token_policies":               {Type: framework.TypeCommaStringSlice},
			"token_ttl":                    {Type: framework.TypeDurationSecond},
			"cred_spec_name":               {Type: framework.TypeString},
			"principal_claim":              {Type: framework.TypeString},
		},
	}

	resp, err := b.handleRoleUpdate(ctx, &logical.Request{}, fd)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	updated, _ := b.getRole(ctx, "full-upd")
	assert.Equal(t, []string{"new-*"}, updated.AllowedCommonNames)
	assert.Equal(t, []string{"*.new.com"}, updated.AllowedDNSSANs)
	assert.Equal(t, []string{"*@new.com"}, updated.AllowedEmailSANs)
	assert.Equal(t, []string{"spiffe://new/*"}, updated.AllowedURISANs)
	assert.Equal(t, []string{"NewEng"}, updated.AllowedOrganizationalUnits)
	assert.Equal(t, []string{"NewOrg"}, updated.AllowedOrganizations)
	assert.Equal(t, "dns_san", updated.PrincipalClaim)
	assert.Equal(t, "new-spec", updated.CredSpecName)
}

// =============================================================================
// handleConfigWrite persists to storage
// =============================================================================
