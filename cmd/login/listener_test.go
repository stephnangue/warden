package login

import (
	"context"
	"fmt"
	"io"
	"net"
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
	l, err := newCallbackListener(0)
	require.NoError(t, err)
	defer l.Close()
	assert.Regexp(t, `^http://localhost:\d+/oidc/callback$`, l.RedirectURI())
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
	l, err := newCallbackListener(0)
	require.NoError(t, err)
	defer l.Close()
	l.Serve("st-1")
	_, body := get(t, l.RedirectURI()+"?state=st-1&error=access_denied&error_description=no")
	assert.Contains(t, body, "Sign-in failed")
	r, err := l.Wait(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "access_denied", r.Error)
	assert.Equal(t, "no", r.ErrorDescription)

	l2, err := newCallbackListener(0)
	require.NoError(t, err)
	defer l2.Close()
	l2.Serve("st-2")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = l2.Wait(ctx)
	assert.ErrorContains(t, err, "timed out")
}

// freePort returns a port nothing listens on, on 127.0.0.1 and, where the
// host has it, ::1.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := newCallbackListener(0)
	require.NoError(t, err)
	l.Close()
	return l.port
}

func hasIPv6Loopback() bool {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

func TestCallbackListener_DefaultPort(t *testing.T) {
	assert.Equal(t, "8251", LoginCmd.Flags().Lookup("callback-port").DefValue)
}

// A fixed port gives a redirect URI an identity provider can match exactly.
func TestCallbackListener_FixedPort(t *testing.T) {
	port := freePort(t)
	l, err := newCallbackListener(port)
	require.NoError(t, err)
	defer l.Close()
	assert.Equal(t, fmt.Sprintf("http://localhost:%d/oidc/callback", port), l.RedirectURI())
}

// The redirect is answered on every address localhost may resolve to.
func TestCallbackListener_BothLoopbacks(t *testing.T) {
	l, err := newCallbackListener(0)
	require.NoError(t, err)
	defer l.Close()
	l.Serve("st-1")
	status, _ := get(t, fmt.Sprintf("http://127.0.0.1:%d/oidc/callback?state=other", l.port))
	assert.Equal(t, http.StatusNotFound, status)
	if !hasIPv6Loopback() {
		t.Skip("no IPv6 loopback on this host")
	}
	require.Len(t, l.lns, 2)
	status, _ = get(t, fmt.Sprintf("http://[::1]:%d/oidc/callback?state=other", l.port))
	assert.Equal(t, http.StatusNotFound, status, "::1 is served too")
}

// A port in use on either loopback is refused with a hint: whoever holds ::1
// would otherwise receive a browser's redirect.
func TestCallbackListener_PortInUse(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer held.Close()
	_, err = newCallbackListener(held.Addr().(*net.TCPAddr).Port)
	assert.ErrorContains(t, err, "-callback-port")
	assert.ErrorContains(t, err, "is in use")

	if !hasIPv6Loopback() {
		t.Skip("no IPv6 loopback on this host")
	}
	held6, err := net.Listen("tcp", "[::1]:0")
	require.NoError(t, err)
	defer held6.Close()
	port := held6.Addr().(*net.TCPAddr).Port
	_, err = newCallbackListener(port)
	assert.ErrorContains(t, err, "is in use", "::1 taken refuses the port")
	free, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	require.NoError(t, err, "and 127.0.0.1 was released again")
	free.Close()
}
