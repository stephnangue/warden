// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// stepDownRequest sends PUT /v1/sys/step-down through the request path with
// token and the extra headers, on an HTTP request bound to reqCtx.
func stepDownRequest(t *testing.T, c *Core, reqCtx context.Context, token string, headers map[string]string) (*logical.Response, error) {
	t.Helper()
	return stepDownRequestAt(t, c, reqCtx, "/v1/sys/step-down", token, headers)
}

// stepDownRequestAt is stepDownRequest at urlPath, which may name a namespace.
func stepDownRequestAt(t *testing.T, c *Core, reqCtx context.Context, urlPath, token string, headers map[string]string) (*logical.Response, error) {
	t.Helper()
	httpReq := httptest.NewRequest(http.MethodPut, urlPath, nil).WithContext(reqCtx)
	if token != "" {
		httpReq.Header.Set("X-Warden-Token", token)
	}
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}
	return c.HandleRequest(rootCtx(), &logical.Request{
		Path:        strings.TrimPrefix(urlPath, "/v1/"),
		Operation:   logical.UpdateOperation,
		HTTPRequest: httpReq,
	})
}

// serviceTokenWith returns a service token whose one policy is body.
func serviceTokenWith(t *testing.T, c *Core, name, body string) string {
	t.Helper()
	p := testParsePolicy(t, body)
	p.Name, p.Type = name, PolicyTypeCBP
	require.NoError(t, c.policyStore.SetPolicy(rootCtx(), p, nil))
	te, err := c.tokenStore.GenerateToken(rootCtx(), TypeServiceToken, &AuthData{
		PrincipalID: "operator",
		ExpireAt:    time.Now().Add(time.Hour),
		Policies:    []string{name},
	})
	require.NoError(t, err)
	require.NotEmpty(t, te.Data["token"])
	return te.Data["token"]
}

// A node without HA answers 400 once the caller is authorized.
func TestStepDown_NoHA(t *testing.T) {
	c := createTestCore(t)
	root, err := c.tokenStore.GenerateRootToken()
	require.NoError(t, err)

	resp, _ := stepDownRequest(t, c, context.Background(), root, nil)
	require.NotNil(t, resp)
	require.Error(t, resp.Err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "HA not enabled")
}

// Step-down is a root path: no token and a token without sudo are refused
// before the handler runs; a sudo grant reaches it.
func TestStepDown_RequiresSudo(t *testing.T) {
	c := createTestCore(t)

	t.Run("no token", func(t *testing.T) {
		resp, err := stepDownRequest(t, c, context.Background(), "", nil)
		refused := err != nil || (resp != nil && resp.StatusCode == http.StatusForbidden)
		assert.True(t, refused, "status %v, err %v", resp, err)
	})

	t.Run("update without sudo", func(t *testing.T) {
		token := serviceTokenWith(t, c, "stepdown-nosudo", `path "sys/step-down" { capabilities = ["update", "create"] }`)
		resp, err := stepDownRequest(t, c, context.Background(), token, nil)
		refused := err != nil || (resp != nil && resp.StatusCode == http.StatusForbidden)
		assert.True(t, refused, "status %v, err %v", resp, err)
	})

	t.Run("sudo", func(t *testing.T) {
		token := serviceTokenWith(t, c, "stepdown-sudo", `path "sys/step-down" { capabilities = ["update", "create", "sudo"] }`)
		resp, _ := stepDownRequest(t, c, context.Background(), token, nil)
		require.NotNil(t, resp)
		require.Error(t, resp.Err)
		assert.Contains(t, resp.Err.Error(), "HA not enabled", "the handler ran")
	})
}

// A step-down that names a namespace is refused, by header as by path: the
// operation is cluster-wide.
func TestStepDown_RefusedInNamespace(t *testing.T) {
	c := createTestCore(t)
	root, err := c.tokenStore.GenerateRootToken()
	require.NoError(t, err)
	require.NoError(t, c.namespaceStore.SetNamespace(rootCtx(), &namespace.Namespace{Path: "ns1/"}))

	for name, send := range map[string]func() (*logical.Response, error){
		"header": func() (*logical.Response, error) {
			return stepDownRequest(t, c, context.Background(), root, map[string]string{"X-Warden-Namespace": "ns1"})
		},
		"path": func() (*logical.Response, error) {
			return stepDownRequestAt(t, c, context.Background(), "/v1/ns1/sys/step-down", root, nil)
		},
	} {
		t.Run(name, func(t *testing.T) {
			resp, _ := send()
			require.NotNil(t, resp)
			require.Error(t, resp.Err)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.Contains(t, resp.Err.Error(), "operation unavailable in namespaces")
		})
	}
}

// The step-down starts only once the HTTP request is done, so the request and
// its response are audited before teardown; then the standby takes over.
func TestStepDown_AfterRequestCompletes(t *testing.T) {
	origSleep := manualStepDownSleepPeriod
	manualStepDownSleepPeriod = 100 * time.Millisecond
	defer func() { manualStepDownSleepPeriod = origSleep }()

	physBackend, haBackend := newInmemHABackends(t)
	core1 := createHACore(t, physBackend, haBackend, "http://node1:8400")
	core2 := createHACore(t, physBackend, haBackend, "http://node2:8400")
	defer core1.Shutdown()
	defer core2.Shutdown()

	root, unsealKey := initAndUnsealCore(t, core1)
	unsealCore(t, core2, unsealKey)
	active := waitForActiveNode(t, []*Core{core1, core2}, 5*time.Second)
	standby := waitForStandbyNode(t, []*Core{core1, core2}, 5*time.Second)
	require.True(t, active != standby)

	reqCtx, finish := context.WithCancel(context.Background())
	defer finish()
	resp, err := stepDownRequest(t, active, reqCtx, root, nil)
	require.NoError(t, err)
	if resp != nil {
		require.NoError(t, resp.Err)
	}

	// The request is accepted but not finished: the node keeps leadership.
	time.Sleep(300 * time.Millisecond)
	assert.False(t, active.Standby(), "stepped down before the request finished")

	finish()
	newActive := waitForActiveNode(t, []*Core{standby}, 10*time.Second)
	assert.True(t, newActive == standby, "standby should have promoted")
}
