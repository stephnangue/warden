package login

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// Only the redirect carrying the login's state completes it; anything else is
// a 404 and the listener keeps waiting.
func TestCallbackListener(t *testing.T) {
	l, err := newCallbackListener()
	require.NoError(t, err)
	defer l.Close()
	assert.Regexp(t, `^http://127\.0\.0\.1:\d+/oidc/callback$`, l.RedirectURI())
	l.Serve("st-1")

	for _, q := range []string{"", "?state=wrong&code=evil", "?code=evil"} {
		status, _ := get(t, l.RedirectURI()+q)
		assert.Equal(t, http.StatusNotFound, status, q)
	}
	status, _ := get(t, l.RedirectURI()[:len(l.RedirectURI())-len(callbackPath)]+"/other?state=st-1&code=c")
	assert.Equal(t, http.StatusNotFound, status, "another path")

	status, body := get(t, l.RedirectURI()+"?state=st-1&code=code-1")
	assert.Equal(t, http.StatusOK, status)
	assert.Contains(t, body, "Signed in")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := l.Wait(ctx)
	require.NoError(t, err)
	assert.Equal(t, "code-1", r.Code)

	// A second matching redirect is answered but changes nothing.
	status, _ = get(t, l.RedirectURI()+"?state=st-1&code=code-2")
	assert.Equal(t, http.StatusOK, status)
	short, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	_, err = l.Wait(short)
	assert.Error(t, err, "the first code stands; nothing more is delivered")
}

func TestCallbackListener_ErrorAndTimeout(t *testing.T) {
	l, err := newCallbackListener()
	require.NoError(t, err)
	defer l.Close()
	l.Serve("st-1")
	_, body := get(t, l.RedirectURI()+"?state=st-1&error=access_denied&error_description=no")
	assert.Contains(t, body, "Sign-in failed")
	r, err := l.Wait(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "access_denied", r.Error)
	assert.Equal(t, "no", r.ErrorDescription)

	l2, err := newCallbackListener()
	require.NoError(t, err)
	defer l2.Close()
	l2.Serve("st-2")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = l2.Wait(ctx)
	assert.ErrorContains(t, err, "timed out")
}
