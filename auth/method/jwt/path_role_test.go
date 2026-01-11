// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// =============================================================================
// Role Management Tests
// =============================================================================

func TestPathRole_Create(t *testing.T) {
	b, ctx := createTestBackendWithStorage(t)

	fieldData := &framework.FieldData{
		Raw: map[string]any{
			"name":                "test-role",
			"bound_audiences":     []string{"aud1", "aud2"},
			"bound_subject":       "test-subject",
			"token_policies":      []string{"policy1", "policy2"},
			"token_ttl":           3600,
			"token_auth_deadline": 1800,
			"token_type":          "service",
			"user_claim":          "email",
			"cred_spec_name":      "aws-dev",
		},
		Schema: map[string]*framework.FieldSchema{
			"name":                {Type: framework.TypeString},
			"bound_audiences":     {Type: framework.TypeCommaStringSlice},
			"bound_subject":       {Type: framework.TypeString},
			"token_policies":      {Type: framework.TypeCommaStringSlice},
			"token_ttl":           {Type: framework.TypeDurationSecond, Default: 3600},
			"token_auth_deadline": {Type: framework.TypeDurationSecond, Default: 3600},
			"token_type":          {Type: framework.TypeString, Default: "service"},
			"user_claim":          {Type: framework.TypeString, Default: "sub"},
			"cred_spec_name":      {Type: framework.TypeString},
		},
	}

	resp, err := b.handleRoleCreate(ctx, &logical.Request{}, fieldData)
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	// Verify role was stored
	role, err := b.getRole(ctx, "test-role")
	require.NoError(t, err)
	require.NotNil(t, role)
	assert.Equal(t, "test-role", role.Name)
	assert.Equal(t, []string{"aud1", "aud2"}, role.BoundAudiences)
	assert.Equal(t, "test-subject", role.BoundSubject)
	assert.Equal(t, []string{"policy1", "policy2"}, role.TokenPolicies)
	assert.Equal(t, time.Hour, role.TokenTTL)
	assert.Equal(t, 30*time.Minute, role.TokenAuthDeadline)
	assert.Equal(t, "service", role.TokenType)
	assert.Equal(t, "email", role.UserClaim)
	assert.Equal(t, "aws-dev", role.CredSpecName)
}

func TestPathRole_CreateDuplicate(t *testing.T) {
	b, ctx := createTestBackendWithStorage(t)

	// Create first role
	role := &JWTRole{
		Name:          "existing-role",
		TokenPolicies: []string{"policy1"},
		TokenTTL:      time.Hour,
	}
	err := b.setRole(ctx, role)
	require.NoError(t, err)

	// Try to create duplicate
	fieldData := &framework.FieldData{
		Raw: map[string]any{
			"name": "existing-role",
		},
		Schema: map[string]*framework.FieldSchema{
			"name":                {Type: framework.TypeString},
			"bound_audiences":     {Type: framework.TypeCommaStringSlice},
			"bound_subject":       {Type: framework.TypeString},
			"token_policies":      {Type: framework.TypeCommaStringSlice},
			"token_ttl":           {Type: framework.TypeDurationSecond, Default: 3600},
			"token_auth_deadline": {Type: framework.TypeDurationSecond, Default: 3600},
			"token_type":          {Type: framework.TypeString, Default: "service"},
			"user_claim":          {Type: framework.TypeString, Default: "sub"},
			"cred_spec_name":      {Type: framework.TypeString},
		},
	}

	resp, err := b.handleRoleCreate(ctx, &logical.Request{}, fieldData)
	require.NoError(t, err)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

func TestPathRole_Read(t *testing.T) {
	b, ctx := createTestBackendWithStorage(t)

	// Create role
	role := &JWTRole{
		Name:              "read-test-role",
		BoundAudiences:    []string{"aud1"},
		BoundSubject:      "sub1",
		TokenPolicies:     []string{"policy1"},
		TokenTTL:          2 * time.Hour,
		TokenAuthDeadline: time.Hour,
		TokenType:         "batch",
		UserClaim:         "preferred_username",
		CredSpecName:      "aws-prod",
	}
	err := b.setRole(ctx, role)
	require.NoError(t, err)

	fieldData := &framework.FieldData{
		Raw: map[string]any{
			"name": "read-test-role",
		},
		Schema: map[string]*framework.FieldSchema{
			"name": {Type: framework.TypeString},
		},
	}

	resp, err := b.handleRoleRead(ctx, &logical.Request{}, fieldData)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "read-test-role", resp.Data["name"])
	assert.Equal(t, "sub1", resp.Data["bound_subject"])
	assert.Equal(t, "batch", resp.Data["token_type"])
	assert.Equal(t, "preferred_username", resp.Data["user_claim"])
	assert.Equal(t, "aws-prod", resp.Data["cred_spec_name"])
}

func TestPathRole_ReadNotFound(t *testing.T) {
	b, ctx := createTestBackendWithStorage(t)

	fieldData := &framework.FieldData{
		Raw: map[string]any{
			"name": "nonexistent-role",
		},
		Schema: map[string]*framework.FieldSchema{
			"name": {Type: framework.TypeString},
		},
	}

	resp, err := b.handleRoleRead(ctx, &logical.Request{}, fieldData)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestPathRole_Update(t *testing.T) {
	b, ctx := createTestBackendWithStorage(t)

	// Create initial role
	role := &JWTRole{
		Name:              "update-test-role",
		BoundAudiences:    []string{"aud1"},
		TokenPolicies:     []string{"policy1"},
		TokenTTL:          time.Hour,
		TokenAuthDeadline: 30 * time.Minute,
		TokenType:         "service",
		UserClaim:         "sub",
	}
	err := b.setRole(ctx, role)
	require.NoError(t, err)

	// Update role
	fieldData := &framework.FieldData{
		Raw: map[string]any{
			"name":           "update-test-role",
			"token_policies": []string{"policy1", "policy2", "policy3"},
			"token_ttl":      7200,
			"cred_spec_name": "new-aws-spec",
		},
		Schema: map[string]*framework.FieldSchema{
			"name":                {Type: framework.TypeString},
			"bound_audiences":     {Type: framework.TypeCommaStringSlice},
			"bound_subject":       {Type: framework.TypeString},
			"token_policies":      {Type: framework.TypeCommaStringSlice},
			"token_ttl":           {Type: framework.TypeDurationSecond},
			"token_auth_deadline": {Type: framework.TypeDurationSecond},
			"token_type":          {Type: framework.TypeString},
			"user_claim":          {Type: framework.TypeString},
			"cred_spec_name":      {Type: framework.TypeString},
		},
	}

	resp, err := b.handleRoleUpdate(ctx, &logical.Request{}, fieldData)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify updates
	updatedRole, err := b.getRole(ctx, "update-test-role")
	require.NoError(t, err)
	assert.Len(t, updatedRole.TokenPolicies, 3)
	assert.Equal(t, 2*time.Hour, updatedRole.TokenTTL)
	assert.Equal(t, "new-aws-spec", updatedRole.CredSpecName)
	// Verify unchanged fields
	assert.Len(t, updatedRole.BoundAudiences, 1)
	assert.Equal(t, "service", updatedRole.TokenType)
}

// TestPathRole_UpdateCreatesIfNotExists verifies the upsert pattern -
// UpdateOperation creates the role if it doesn't exist.
func TestPathRole_UpdateCreatesIfNotExists(t *testing.T) {
	b, ctx := createTestBackendWithStorage(t)

	fieldData := &framework.FieldData{
		Raw: map[string]any{
			"name":       "new-role-via-update",
			"token_ttl":  3600,
			"token_type": "service",
		},
		Schema: map[string]*framework.FieldSchema{
			"name":       {Type: framework.TypeString},
			"token_ttl":  {Type: framework.TypeDurationSecond},
			"token_type": {Type: framework.TypeString},
		},
	}

	resp, err := b.handleRoleUpdate(ctx, &logical.Request{}, fieldData)
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Contains(t, resp.Data["message"], "created")

	// Verify the role was created
	createdRole, err := b.getRole(ctx, "new-role-via-update")
	require.NoError(t, err)
	require.NotNil(t, createdRole)
	assert.Equal(t, "new-role-via-update", createdRole.Name)
	assert.Equal(t, time.Hour, createdRole.TokenTTL)
	assert.Equal(t, "service", createdRole.TokenType)
	// Verify defaults were applied
	assert.Equal(t, "sub", createdRole.UserClaim)
}

func TestPathRole_Delete(t *testing.T) {
	b, ctx := createTestBackendWithStorage(t)

	// Create role
	role := &JWTRole{
		Name:          "delete-test-role",
		TokenPolicies: []string{"policy1"},
		TokenTTL:      time.Hour,
	}
	err := b.setRole(ctx, role)
	require.NoError(t, err)

	// Verify exists
	existingRole, _ := b.getRole(ctx, "delete-test-role")
	require.NotNil(t, existingRole)

	fieldData := &framework.FieldData{
		Raw: map[string]any{
			"name": "delete-test-role",
		},
		Schema: map[string]*framework.FieldSchema{
			"name": {Type: framework.TypeString},
		},
	}

	resp, err := b.handleRoleDelete(ctx, &logical.Request{}, fieldData)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify deleted
	deletedRole, _ := b.getRole(ctx, "delete-test-role")
	assert.Nil(t, deletedRole)
}

func TestPathRole_List(t *testing.T) {
	b, ctx := createTestBackendWithStorage(t)

	// Create multiple roles
	roles := []string{"role-a", "role-b", "role-c"}
	for _, name := range roles {
		role := &JWTRole{
			Name:          name,
			TokenPolicies: []string{"policy1"},
			TokenTTL:      time.Hour,
		}
		err := b.setRole(ctx, role)
		require.NoError(t, err)
	}

	fieldData := &framework.FieldData{
		Raw:    map[string]any{},
		Schema: map[string]*framework.FieldSchema{},
	}

	resp, err := b.handleRoleList(ctx, &logical.Request{}, fieldData)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	keys, ok := resp.Data["keys"].([]string)
	require.True(t, ok)
	assert.Len(t, keys, 3)
}

func TestPathRole_ListEmpty(t *testing.T) {
	b, ctx := createTestBackendWithStorage(t)

	fieldData := &framework.FieldData{
		Raw:    map[string]any{},
		Schema: map[string]*framework.FieldSchema{},
	}

	resp, err := b.handleRoleList(ctx, &logical.Request{}, fieldData)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	keys, ok := resp.Data["keys"].([]string)
	require.True(t, ok)
	assert.Len(t, keys, 0)
}

func TestRole_StorageRoundTrip(t *testing.T) {
	b, ctx := createTestBackendWithStorage(t)

	original := &JWTRole{
		Name:              "roundtrip-role",
		BoundAudiences:    []string{"aud1", "aud2"},
		BoundSubject:      "test-subject",
		TokenPolicies:     []string{"policy1", "policy2"},
		TokenTTL:          2*time.Hour + 30*time.Minute,
		TokenAuthDeadline: time.Hour + 15*time.Minute,
		TokenType:         "batch",
		UserClaim:         "preferred_username",
		CredSpecName:      "aws-test-spec",
	}

	// Store
	err := b.setRole(ctx, original)
	require.NoError(t, err)

	// Retrieve
	retrieved, err := b.getRole(ctx, "roundtrip-role")
	require.NoError(t, err)

	// Compare
	assert.Equal(t, original.Name, retrieved.Name)
	assert.Equal(t, original.BoundAudiences, retrieved.BoundAudiences)
	assert.Equal(t, original.BoundSubject, retrieved.BoundSubject)
	assert.Equal(t, original.TokenPolicies, retrieved.TokenPolicies)
	assert.Equal(t, original.TokenTTL, retrieved.TokenTTL)
	assert.Equal(t, original.TokenAuthDeadline, retrieved.TokenAuthDeadline)
	assert.Equal(t, original.TokenType, retrieved.TokenType)
	assert.Equal(t, original.UserClaim, retrieved.UserClaim)
	assert.Equal(t, original.CredSpecName, retrieved.CredSpecName)
}

func TestRole_Defaults(t *testing.T) {
	b, ctx := createTestBackendWithStorage(t)

	fieldData := &framework.FieldData{
		Raw: map[string]any{
			"name": "defaults-role",
		},
		Schema: map[string]*framework.FieldSchema{
			"name":                {Type: framework.TypeString},
			"bound_audiences":     {Type: framework.TypeCommaStringSlice},
			"bound_subject":       {Type: framework.TypeString},
			"token_policies":      {Type: framework.TypeCommaStringSlice},
			"token_ttl":           {Type: framework.TypeDurationSecond, Default: 3600},
			"token_auth_deadline": {Type: framework.TypeDurationSecond, Default: 3600},
			"token_type":          {Type: framework.TypeString, Default: "service"},
			"user_claim":          {Type: framework.TypeString, Default: "sub"},
			"cred_spec_name":      {Type: framework.TypeString},
		},
	}

	_, err := b.handleRoleCreate(ctx, &logical.Request{}, fieldData)
	require.NoError(t, err)

	role, err := b.getRole(ctx, "defaults-role")
	require.NoError(t, err)

	// Verify defaults were applied
	assert.Equal(t, "sub", role.UserClaim)
	assert.Equal(t, time.Hour, role.TokenTTL)
	assert.Equal(t, time.Hour, role.TokenAuthDeadline)
}

// =============================================================================
// Path Structure Tests
// =============================================================================

func TestPathRole_Pattern(t *testing.T) {
	b, _ := createTestBackendWithStorage(t)
	path := b.pathRole()

	assert.Equal(t, "role/"+framework.GenericNameRegex("name"), path.Pattern)
}

func TestPathRole_Fields(t *testing.T) {
	b, _ := createTestBackendWithStorage(t)
	path := b.pathRole()

	// Check all expected fields exist
	expectedFields := []string{
		"name", "bound_audiences", "bound_subject", "token_policies",
		"token_ttl", "token_auth_deadline", "token_type", "user_claim", "cred_spec_name",
	}

	for _, field := range expectedFields {
		_, exists := path.Fields[field]
		assert.True(t, exists, "Field %s should exist", field)
	}
}

func TestPathRole_Operations(t *testing.T) {
	b, _ := createTestBackendWithStorage(t)
	path := b.pathRole()

	// Check operations exist
	_, hasCreate := path.Operations[logical.CreateOperation]
	_, hasRead := path.Operations[logical.ReadOperation]
	_, hasUpdate := path.Operations[logical.UpdateOperation]
	_, hasDelete := path.Operations[logical.DeleteOperation]

	assert.True(t, hasCreate, "Should have create operation")
	assert.True(t, hasRead, "Should have read operation")
	assert.True(t, hasUpdate, "Should have update operation")
	assert.True(t, hasDelete, "Should have delete operation")
}

func TestPathRoleList_Pattern(t *testing.T) {
	b, _ := createTestBackendWithStorage(t)
	path := b.pathRoleList()

	assert.Equal(t, "role/?$", path.Pattern)
}

func TestPathRoleList_Operations(t *testing.T) {
	b, _ := createTestBackendWithStorage(t)
	path := b.pathRoleList()

	_, hasList := path.Operations[logical.ListOperation]
	assert.True(t, hasList, "Should have list operation")
}
