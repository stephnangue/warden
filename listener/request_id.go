package listener

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"sync/atomic"

	"github.com/go-chi/chi/middleware"
)

// ForwardedRequestIDHeader carries a request's id from the node that received
// it to the active node it is forwarded to. It is internal to the cluster: the
// forwarding proxy sets it and the cluster listener consumes it, so a caller's
// own X-Request-Id reaches the upstream untouched.
const ForwardedRequestIDHeader = "X-Warden-Request-Id"

var (
	requestIDPrefix = newRequestIDPrefix()
	requestIDSeq    atomic.Uint64
)

// newRequestIDPrefix is this process's request-id prefix: the hostname and ten
// random characters, the shape chi's RequestID middleware uses, so ids from
// different nodes and restarts do not collide.
func newRequestIDPrefix() string {
	hostname, err := os.Hostname()
	if hostname == "" || err != nil {
		hostname = "localhost"
	}
	var buf [12]byte
	var b64 string
	for len(b64) < 10 {
		_, _ = rand.Read(buf[:])
		b64 = strings.NewReplacer("+", "", "/", "").Replace(base64.StdEncoding.EncodeToString(buf[:]))
	}
	return hostname + "/" + b64[:10]
}

// NewRequestID returns a request id no other request in the cluster has.
func NewRequestID() string {
	return fmt.Sprintf("%s-%06d", requestIDPrefix, requestIDSeq.Add(1))
}

// WithRequestID stores id as the request's id, where middleware.GetReqID
// reads it.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, middleware.RequestIDKey, id)
}
