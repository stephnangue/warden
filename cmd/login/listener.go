package login

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// callbackPath is the path the identity provider redirects the browser to.
const callbackPath = "/oidc/callback"

// defaultCallbackPort is the port the sign-in redirect lands on by default:
// fixed, so it can be registered at an identity provider that matches
// redirect URIs exactly (http://localhost:8251/oidc/callback). It is neither
// OpenBao's 8250 nor Warden's dev listener's 8400.
const defaultCallbackPort = 8251

// callbackResult is what the identity provider sent back: a code, or an
// error.
type callbackResult struct {
	Code             string
	Error            string
	ErrorDescription string
}

// callbackListener is the loopback HTTP server the browser lands on after
// sign-in. It accepts only the redirect whose state is the login's: any other
// request is answered 404 and ignored without ending the login, so a local
// process that finds the port cannot end it early or feed it a code.
type callbackListener struct {
	lns    []net.Listener
	port   int
	srv    *http.Server
	result chan callbackResult

	mu    sync.Mutex
	state string
	once  sync.Once
}

// newCallbackListener listens on port on the loopback addresses localhost
// may resolve to: 127.0.0.1, and ::1 where the host has IPv6. Port 0 picks a
// free port. A port already in use on either address is an error, naming
// -callback-port: whoever holds ::1 would otherwise receive the redirect of a
// browser that resolves localhost there.
func newCallbackListener(port int) (*callbackListener, error) {
	v4, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, listenError(port, err)
	}
	port = v4.Addr().(*net.TCPAddr).Port
	lns := []net.Listener{v4}
	v6, err := net.Listen("tcp", net.JoinHostPort("::1", strconv.Itoa(port)))
	switch {
	case err == nil:
		lns = append(lns, v6)
	case errors.Is(err, syscall.EADDRINUSE):
		_ = v4.Close()
		return nil, listenError(port, err)
	default:
		// No IPv6 loopback on this host: localhost resolves to 127.0.0.1.
	}
	l := &callbackListener{lns: lns, port: port, result: make(chan callbackResult, 1)}
	l.srv = &http.Server{Handler: http.HandlerFunc(l.handle), ReadHeaderTimeout: 10 * time.Second}
	return l, nil
}

func listenError(port int, err error) error {
	if errors.Is(err, syscall.EADDRINUSE) {
		return fmt.Errorf("port %d is in use: choose another with -callback-port, and register http://localhost:<port>%s "+
			"at the identity provider (or use -callback-port=0 if it accepts any loopback port)", port, callbackPath)
	}
	return fmt.Errorf("cannot listen for the sign-in redirect on port %d: %w", port, err)
}

// RedirectURI is the redirect URI the login passes to auth_url.
func (l *callbackListener) RedirectURI() string {
	return fmt.Sprintf("http://localhost:%d%s", l.port, callbackPath)
}

// Serve starts answering redirects carrying state.
func (l *callbackListener) Serve(state string) {
	l.mu.Lock()
	l.state = state
	l.mu.Unlock()
	for _, ln := range l.lns {
		go func() { _ = l.srv.Serve(ln) }()
	}
}

func (l *callbackListener) handle(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	want := l.state
	l.mu.Unlock()
	q := r.URL.Query()
	if r.Method != http.MethodGet || r.URL.Path != callbackPath || want == "" || q.Get("state") != want {
		http.NotFound(w, r)
		return
	}
	res := callbackResult{Code: q.Get("code"), Error: q.Get("error"), ErrorDescription: q.Get("error_description")}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if res.Error != "" {
		_, _ = fmt.Fprint(w, page("Sign-in failed", "Return to the terminal for details."))
	} else {
		_, _ = fmt.Fprint(w, page("Signed in", "You can close this window and return to the terminal."))
	}
	l.once.Do(func() { l.result <- res })
}

// Wait returns the first redirect carrying the login's state, or ctx's error.
func (l *callbackListener) Wait(ctx context.Context) (callbackResult, error) {
	select {
	case r := <-l.result:
		return r, nil
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return callbackResult{}, errors.New("timed out waiting for the sign-in to finish in the browser")
		}
		return callbackResult{}, ctx.Err()
	}
}

// Close stops the listener.
func (l *callbackListener) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = l.srv.Shutdown(ctx)
	for _, ln := range l.lns {
		_ = ln.Close()
	}
}

func page(title, body string) string {
	return "<!doctype html><html><head><meta charset=\"utf-8\"><title>Warden: " + title +
		"</title></head><body style=\"font-family:sans-serif;margin:3em\"><h1>" + title +
		"</h1><p>" + body + "</p></body></html>"
}
