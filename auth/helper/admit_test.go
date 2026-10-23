package helper

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

func TestAdmitPath(t *testing.T) {
	var calls int
	var adm *logical.Admission
	var admitErr error
	p := AdmitPath(func(_ context.Context, _ *logical.Request, now time.Time) (*logical.Admission, error) {
		calls++
		assert.False(t, now.IsZero())
		return adm, admitErr
	})
	require.Equal(t, AdmitPattern, p.Pattern)
	cb := p.Operations[logical.ReadOperation].(*framework.PathOperation).Callback
	ctx := context.Background()

	t.Run("refused unless internal, before admitting", func(t *testing.T) {
		resp, err := cb(ctx, &logical.Request{}, nil)
		require.NoError(t, err)
		require.Error(t, resp.Err)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.Nil(t, resp.Data)
		assert.Zero(t, calls)
	})
	t.Run("not admitted", func(t *testing.T) {
		resp, err := cb(ctx, &logical.Request{Internal: true}, nil)
		require.NoError(t, err)
		assert.Equal(t, map[string]any{AdmittedKey: false}, resp.Data)
	})
	t.Run("could not decide", func(t *testing.T) {
		admitErr = errors.New("no trusted CA certificates configured")
		defer func() { admitErr = nil }()
		resp, err := cb(ctx, &logical.Request{Internal: true}, nil)
		assert.Equal(t, admitErr, err)
		assert.Nil(t, resp)
	})
	t.Run("admitted", func(t *testing.T) {
		adm = &logical.Admission{}
		resp, err := cb(ctx, &logical.Request{Internal: true}, nil)
		require.NoError(t, err)
		assert.Equal(t, true, resp.Data[AdmittedKey])
		assert.Same(t, adm, resp.Data[AdmissionKey])

		// In process only: the response data does not encode.
		_, err = json.Marshal(resp.Data)
		assert.ErrorIs(t, err, logical.ErrAdmissionNotSerializable)
	})
}
