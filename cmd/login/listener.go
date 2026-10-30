package login

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// callbackPath is the path the identity provider redirects the browser to.
// The mount's allowed_redirect_uris lists http://127.0.0.1/oidc/callback,
// which matches any port.
const callbackPath = "/oidc/callback"

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
	ln     net.Listener
	srv    *http.Server
	result chan callbackResult

	mu    sync.Mutex
	state string
	once  sync.Once
}

// newCallbackListener listens on a port the system picks on 127.0.0.1.
func newCallbackListener() (*callbackListener, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("cannot listen for the sign-in redirect: %w", err)
	}
	l := &callbackListener{ln: ln, result: make(chan callbackResult, 1)}
	l.srv = &http.Server{Handler: http.HandlerFunc(l.handle), ReadHeaderTimeout: 10 * time.Second}
	return l, nil
}

// RedirectURI is the redirect URI the login passes to auth_url.
func (l *callbackListener) RedirectURI() string {
	return fmt.Sprintf("http://127.0.0.1:%d%s", l.ln.Addr().(*net.TCPAddr).Port, callbackPath)
}

// Serve starts answering redirects carrying state.
func (l *callbackListener) Serve(state string) {
	l.mu.Lock()
	l.state = state
	l.mu.Unlock()
	go func() { _ = l.srv.Serve(l.ln) }()
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
	_ = l.ln.Close()
}

func page(title, body string) string {
	return "<!doctype html><html><head><meta charset=\"utf-8\"><title>Warden: " + title +
		"</title></head><body style=\"font-family:sans-serif;margin:3em\"><h1>" + title +
		"</h1><p>" + body + "</p></body></html>"
}
