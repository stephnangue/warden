// Package namespace provides namespace types and context helpers for Warden.
// This replaces the internal github.com/openbao/openbao/helper/namespace package.
package namespace

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

type contextKeyType struct{}

var contextKey contextKeyType

const (
	// RootNamespaceID is the ID of the root namespace.
	RootNamespaceID = "root"

	// RootNamespaceUUID is the UUID of the root namespace.
	RootNamespaceUUID = "00000000-0000-0000-0000-000000000000"
)

// ErrNoNamespace is returned when a namespace is not found in a context.
var ErrNoNamespace = errors.New("no namespace")

// Namespace represents a Warden namespace.
type Namespace struct {
	ID             string            `json:"id"`
	UUID           string            `json:"uuid"`
	Path           string            `json:"path"`
	Tainted        bool              `json:"tainted"`
	Locked         bool              `json:"locked"`
	UnlockKey      string            `json:"unlock_key,omitempty"`
	CustomMetadata map[string]string `json:"custom_metadata,omitempty"`
}

// RootNamespace is the root namespace singleton.
var RootNamespace = &Namespace{
	ID:   RootNamespaceID,
	UUID: RootNamespaceUUID,
	Path: "",
}

// MountPathDetails contains the namespace and mount path for a given mount.
type MountPathDetails struct {
	Namespace *Namespace
	MountPath string
}

// String returns a human-readable representation of the namespace.
func (n *Namespace) String() string {
	return fmt.Sprintf("ID: %s. UUID: %s. Path: %s", n.ID, n.UUID, n.Path)
}

// Clone returns a deep copy of the namespace.
// If withUnlock is true, the UnlockKey is included in the clone.
func (n *Namespace) Clone(withUnlock bool) *Namespace {
	clone := &Namespace{
		ID:      n.ID,
		UUID:    n.UUID,
		Path:    n.Path,
		Tainted: n.Tainted,
		Locked:  n.Locked,
	}

	if withUnlock {
		clone.UnlockKey = n.UnlockKey
	}

	if n.CustomMetadata != nil {
		clone.CustomMetadata = make(map[string]string, len(n.CustomMetadata))
		for k, v := range n.CustomMetadata {
			clone.CustomMetadata[k] = v
		}
	}

	return clone
}

// TrimmedPath strips the namespace's path prefix from the given path.
func (n *Namespace) TrimmedPath(path string) string {
	return strings.TrimPrefix(path, n.Path)
}

// HasParent returns true if the namespace has the given parent namespace
// as an ancestor (or is the same namespace).
func (n *Namespace) HasParent(parent *Namespace) bool {
	switch {
	case n.Path == parent.Path:
		return true
	case parent.Path == "":
		return true
	default:
		return strings.HasPrefix(n.Path, parent.Path)
	}
}

// ParentPath returns the path of the parent namespace and whether a parent exists.
func (n *Namespace) ParentPath() (string, bool) {
	return ParentOf(n.Path)
}

// Validate checks that the namespace path is valid.
func (n *Namespace) Validate() error {
	if n.Path == "" {
		return nil // root namespace
	}
	if !strings.HasSuffix(n.Path, "/") {
		return fmt.Errorf("namespace path %q must end with /", n.Path)
	}
	if strings.Contains(n.Path, "..") {
		return fmt.Errorf("namespace path %q must not contain '..'", n.Path)
	}
	return nil
}

// Canonicalize normalizes a namespace path: removes leading slash, ensures trailing slash.
// Returns empty string for root-level paths.
func Canonicalize(nsPath string) string {
	if nsPath == "" || nsPath == "/" {
		return ""
	}
	nsPath = strings.TrimPrefix(nsPath, "/")
	if !strings.HasSuffix(nsPath, "/") {
		nsPath += "/"
	}
	return nsPath
}

// ParentOf returns the parent namespace path and whether a parent exists.
// path must be a canonicalized path.
func ParentOf(path string) (string, bool) {
	if path == "" {
		return "", false
	}
	segments := strings.SplitAfter(path, "/")
	if len(segments) <= 2 {
		return "", true
	}
	return strings.Join(segments[:len(segments)-2], ""), true
}

// ContextWithNamespace returns a new context with the given namespace stored.
func ContextWithNamespace(ctx context.Context, ns *Namespace) context.Context {
	return context.WithValue(ctx, contextKey, ns)
}

// FromContext retrieves the namespace from the context.
// Returns ErrNoNamespace if no namespace is set.
func FromContext(ctx context.Context) (*Namespace, error) {
	if ctx == nil {
		return nil, ErrNoNamespace
	}
	ns, ok := ctx.Value(contextKey).(*Namespace)
	if !ok {
		return nil, ErrNoNamespace
	}
	return ns, nil
}

// RootContext returns a context with the root namespace.
func RootContext(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return ContextWithNamespace(ctx, RootNamespace)
}
